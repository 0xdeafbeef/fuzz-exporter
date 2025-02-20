use tokio::io::AsyncBufReadExt;
use winnow::Result;
use winnow::ascii::{dec_uint, space1};
use winnow::combinator::{preceded, terminated};
use winnow::error::{ContextError, ParseError};
use winnow::token::{rest, take_until};

use winnow::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    metrics_exporter_prometheus::PrometheusBuilder::new().install()?;
    println!("Starting server...");

    let journalctl = tokio::process::Command::new("journalctl")
        .arg("--user")
        .arg("-f")
        .arg("-u")
        .arg("fuzz")
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let mut stream = tokio::io::BufReader::new(journalctl.stdout.unwrap()).lines();
    while let Some(line) = stream.next_line().await? {
        if let Ok(parsed) = Parsed::from_log(&line) {
            metrics::gauge!("fuzz_cov").set(parsed.cov as f64);
            metrics::gauge!("fuzz_feat").set(parsed.ft as f64);
            metrics::gauge!("fuzz_corp").set(parsed.corp as f64);
            metrics::gauge!("fuzz_exec_s").set(parsed.exec_s as f64);
            metrics::gauge!("fuzz_oom").set(parsed.oom as f64);
            metrics::gauge!("fuzz_timeout").set(parsed.timeout as f64);
            metrics::gauge!("fuzz_crash").set(parsed.crash as f64);
            metrics::gauge!("fuzz_time").set(parsed.time as f64);
        }
    }

    Ok(())
}

// Feb 20 08:24:30 test-server-1 cargo[117394]: #2903021619: cov: 2163 ft: 20854 corp: 2853 exec/s: 1464 oom/timeout/crash: 0/0/0 time: 56383s job: 6125 dft_time: 0
#[derive(Debug, PartialEq, Eq)]
struct Parsed {
    cov: u32,
    ft: u32,
    corp: u32,
    exec_s: u32,
    oom: u32,
    timeout: u32,
    crash: u32,
    time: u32,
}

impl Parsed {
    fn from_log(log: &str) -> Result<Parsed, ParseError<&str, ContextError>> {
        parse_log.parse(log)
    }
}

fn parse_log(input: &mut &str) -> Result<Parsed> {
    // 1. Skip everything until "cov:"
    take_until(0.., "cov:").void().parse_next(input)?;

    let cov = preceded(("cov:", space1), dec_uint).parse_next(input)?;
    let ft = preceded((space1, ("ft:", space1)), dec_uint).parse_next(input)?;
    let corp = preceded((space1, ("corp:", space1)), dec_uint).parse_next(input)?;
    let exec_s = preceded((space1, ("exec/s:", space1)), dec_uint).parse_next(input)?;

    // 3. Parse OOM/Timeout/Crash
    let oom_crash = preceded(
        (space1, "oom/timeout/crash:", space1),
        (dec_uint, '/', dec_uint, '/', dec_uint).map(|(o, _, t, _, c)| (o, t, c)),
    )
    .parse_next(input)?;

    // 4. Parse time with 's' suffix
    let time =
        preceded((space1, ("time:", space1)), terminated(dec_uint, 's')).parse_next(input)?;
    rest.void().parse_next(input)?;

    Ok(Parsed {
        cov,
        ft,
        corp,
        exec_s,
        oom: oom_crash.0,
        timeout: oom_crash.1,
        crash: oom_crash.2,
        time,
    })
}

#[cfg(test)]
mod test {
    use crate::{Parsed, parse_log};
    use winnow::Parser;

    #[test]
    fn test_parse() {
        let log = "Feb 20 08:24:30 test-server-1 cargo[117394]: #2903021619: cov: 2163 ft: 20854 corp: 2853 exec/s: 1464 oom/timeout/crash: 0/0/0 time: 56383s job: 6125 dft_time: 0";
        let parsed = parse_log.parse(log).unwrap();
        assert_eq!(
            parsed,
            Parsed {
                cov: 2163,
                ft: 20854,
                corp: 2853,
                exec_s: 1464,
                oom: 0,
                timeout: 0,
                crash: 0,
                time: 56383
            }
        );
    }
}
