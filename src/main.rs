use anyhow::Context;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tokio::io::AsyncBufReadExt;
use tokio::process::ChildStdout;
use winnow::Result;
use winnow::ascii::{dec_uint, space1};
use winnow::combinator::{alt, opt, preceded, terminated};
use winnow::error::{ContextError, ParseError};
use winnow::token::{rest, take_until};

use winnow::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    metrics_exporter_prometheus::PrometheusBuilder::new().install()?;
    println!("Starting server...");

    let Some(dir_path) = std::env::args().nth(1) else {
        return journalctl_parser().await;
    };
    jobs_parser(Path::new(&dir_path)).await?;

    Ok(())
}
#[derive(Default)]
struct JobStatus {
    cov: AtomicU32,
    ft: AtomicU32,
    corp: AtomicU32,
    exec_s: AtomicU32,
    corp_size: AtomicU64,
}

impl JobStatus {
    fn update(&self, parsed: &Parsed) {
        self.cov.store(parsed.cov, Ordering::Relaxed);
        self.ft.store(parsed.ft, Ordering::Relaxed);
        self.corp.store(parsed.corp, Ordering::Relaxed);
        self.exec_s.store(parsed.exec_s, Ordering::Relaxed);
        self.corp_size.store(parsed.corp_size, Ordering::Relaxed);
    }
}

async fn jobs_parser(dir_path: &Path) -> anyhow::Result<()> {
    let logs = std::fs::read_dir(dir_path)?;
    let logs: Vec<_> = logs
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "log"))
        .map(|entry| entry.path())
        .collect();

    let jobs = std::iter::repeat_with(JobStatus::default)
        .take(logs.len())
        .collect::<Vec<_>>();
    let jobs = Arc::new(jobs);

    for (idx, log) in logs.iter().enumerate() {
        let jobs = jobs.clone();
        let stream = stream_lines(log)?;

        tokio::spawn(async move {
            let mut stream = tokio::io::BufReader::new(stream).lines();

            while let Ok(Some(line)) = stream.next_line().await {
                let Ok(parsed) = Parsed::from_log_job(&line) else {
                    continue;
                };
                jobs[idx].update(&parsed);
            }
        });
    }

    macro_rules! update_metric {
        ($field:ident, max, $metric:expr) => {{
            let value = jobs
                .iter()
                .map(|job| job.$field.load(Ordering::Acquire))
                .max()
                .unwrap_or(0);
            metrics::gauge!($metric).set(value as f64);
        }};
        ($field:ident, sum, $metric:expr) => {{
            let value: u32 = jobs
                .iter()
                .map(|job| job.$field.load(Ordering::Acquire))
                .sum();
            metrics::gauge!($metric).set(value as f64);
        }};
    }

    loop {
        update_metric!(cov, max, "fuzz_cov");
        update_metric!(ft, max, "fuzz_feat");
        update_metric!(corp, max, "fuzz_corp");
        update_metric!(exec_s, sum, "fuzz_exec_s");
        update_metric!(corp_size, max, "fuzz_corp_size");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
fn stream_lines(path: &Path) -> anyhow::Result<ChildStdout> {
    let command = tokio::process::Command::new("tail")
        .arg("-f")
        .arg(path)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tail");
    command.stdout.context("failed to get stdout")
}

async fn journalctl_parser() -> Result<(), anyhow::Error> {
    println!("Starting journalctl parser");

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
    corp_size: u64,
    exec_s: u32,
    oom: u32,
    timeout: u32,
    crash: u32,
    time: u32,
}

impl Parsed {
    fn from_log(log: &str) -> Result<Parsed, ParseError<&str, ContextError>> {
        parse_fork_mode.parse(log)
    }

    fn from_log_job(log: &str) -> Result<Parsed, ParseError<&str, ContextError>> {
        parse_job_mode.parse(log)
    }
}

fn parse_fork_mode(input: &mut &str) -> Result<Parsed> {
    // 1. Skip everything until "cov:"
    take_until(0.., "cov:").void().parse_next(input)?;

    let cov = preceded(("cov:", space1), dec_uint).parse_next(input)?;
    let ft = preceded((space1, ("ft:", space1)), dec_uint).parse_next(input)?;
    let corp = preceded((space1, ("corp:", space1)), dec_uint).parse_next(input)?;

    // somehow it can both variants of exec/s
    let exec_s = alt((("exec/s", space1), ("exec/s:", space1)));
    let exec_s = preceded((space1, exec_s), dec_uint).parse_next(input)?;

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
        corp_size: 0,
        exec_s,
        oom: oom_crash.0,
        timeout: oom_crash.1,
        crash: oom_crash.2,
        time,
    })
}

//  RELOAD cov: 641 ft: 9191 corp: 1640/591Kb lim: 2411 exec/s: 529 rss: 36Mb
fn parse_job_mode(input: &mut &str) -> Result<Parsed> {
    // 1. Skip everything until "cov:"
    take_until(0.., "cov:").void().parse_next(input)?;

    let cov = preceded(("cov:", space1), dec_uint).parse_next(input)?;
    let ft = preceded((space1, "ft:", space1), dec_uint).parse_next(input)?;

    // Parse corp: <units>[/<size><unit>]
    let (corp_units, corp_size) = preceded(
        (space1, "corp:", space1),
        (
            dec_uint,
            opt(preceded(
                '/',
                (
                    dec_uint,
                    alt((
                        "Kb".value(1024u64),
                        "Mb".value(1024u64 * 1024),
                        "b".value(1u64),
                    )),
                )
                    .map(|(n, unit): (u64, u64)| n * unit),
            )),
        ),
    )
    .map(|(units, size)| (units, size.unwrap_or(0)))
    .parse_next(input)?;

    // Skip remaining fields until exec/s using proper delimiters
    let _ = terminated(take_until(0.., "exec/s:"), "exec/s:").parse_next(input)?;

    let exec_s = preceded(space1, dec_uint).parse_next(input)?;

    // Skip the rest (rss: XXMb)
    rest.void().parse_next(input)?;

    Ok(Parsed {
        cov,
        ft,
        corp: corp_units,
        corp_size,
        exec_s,
        oom: 0,
        timeout: 0,
        crash: 0,
        time: 0,
    })
}

#[cfg(test)]
mod test {
    use crate::{Parsed, parse_fork_mode, parse_job_mode};
    use winnow::Parser;

    #[test]
    fn test_parse() {
        let log = "Feb 20 08:24:30 test-server-1 cargo[117394]: #2903021619: cov: 2163 ft: 20854 corp: 2853 exec/s: 1464 oom/timeout/crash: 0/0/0 time: 56383s job: 6125 dft_time: 0";
        let parsed = parse_fork_mode.parse(log).unwrap();
        assert_eq!(
            parsed,
            Parsed {
                cov: 2163,
                ft: 20854,
                corp: 2853,
                corp_size: 0,
                exec_s: 1464,
                oom: 0,
                timeout: 0,
                crash: 0,
                time: 56383
            }
        );

        let log = "Feb 24 16:30:28 test-server-1 cargo[478967]: #190817895: cov: 400 ft: 7911 corp: 1901 exec/s 24015 oom/timeout/crash: 0/0/0 time: 252s job: 110 dft_time: 0";
        let parsed = parse_fork_mode.parse(log).unwrap();
        assert_eq!(
            parsed,
            Parsed {
                cov: 400,
                ft: 7911,
                corp: 1901,
                corp_size: 0,
                exec_s: 24015,
                oom: 0,
                timeout: 0,
                crash: 0,
                time: 252
            }
        );
    }

    #[test]
    fn test_parse_job_mode() {
        let log = "RELOAD cov: 641 ft: 9191 corp: 1640/591Kb lim: 2411 exec/s: 529 rss: 36Mb";
        let parsed = parse_job_mode.parse(log).unwrap();
        assert_eq!(
            parsed,
            Parsed {
                cov: 641,
                ft: 9191,
                corp: 1640,
                corp_size: 591 * 1024,
                exec_s: 529,
                oom: 0,
                timeout: 0,
                crash: 0,
                time: 0
            }
        );
    }
}
