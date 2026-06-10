#[cfg(all(feature = "metrics", target_os = "linux"))]
use std::fs;
#[cfg(all(feature = "metrics", target_os = "macos"))]
use std::fs;
#[cfg(all(feature = "metrics", any(target_os = "linux", target_os = "macos")))]
use std::io;
#[cfg(all(feature = "metrics", target_os = "macos"))]
use std::mem::{size_of, zeroed};
use std::net::SocketAddr;
#[cfg(all(feature = "metrics", target_os = "macos"))]
use std::os::raw::{c_int, c_void};
use std::time::{Duration, SystemTime};

/// Computes an average per-second rate for a monotonically increasing counter.
fn rate_per_sec(count: u64, interval_secs: f64) -> f64 {
    if interval_secs > 0.0 {
        count as f64 / interval_secs
    } else {
        0.0
    }
}

#[cfg(feature = "metrics")]
fn duration_since_epoch_secs(time: SystemTime) -> f64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs_f64()
}

/// A point-in-time snapshot of cumulative subscription metrics.
///
/// Counter fields in this snapshot are cumulative from the lifetime of the
/// subscription and can be compared against an earlier snapshot to compute
/// deltas and rates.
#[cfg(feature = "metrics")]
#[derive(Debug, Clone)]
pub struct SubscriptionMetricsSnapshot {
    pub packets_received: u64,
    pub bytes_received: u64,
    pub would_block_count: u64,
    pub receive_errors: u64,
    pub join_count: u64,
    pub leave_count: u64,
    pub last_payload_len: Option<usize>,
    pub last_source: Option<SocketAddr>,
    pub last_receive_at: Option<SystemTime>,
    pub captured_at: SystemTime,
}

/// The difference between two cumulative subscription metrics snapshots.
///
/// This contains only counter-based deltas over the sampled interval.
/// Last-seen values such as source address or payload length are intentionally
/// not included here; callers should inspect those directly from the latest
/// snapshot instead.
#[cfg(feature = "metrics")]
#[derive(Debug, Clone)]
pub struct SubscriptionMetricsDelta {
    pub interval_secs: f64,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub would_block_count: u64,
    pub receive_errors: u64,
    pub join_count: u64,
    pub leave_count: u64,
}

#[cfg(feature = "metrics")]
impl SubscriptionMetricsSnapshot {
    /// Computes the counter deltas between this snapshot and an earlier one.
    ///
    /// Returns `None` if:
    /// - `earlier` was captured after `self`
    /// - any cumulative counter appears to have moved backwards
    pub fn delta_since(&self, earlier: &Self) -> Option<SubscriptionMetricsDelta> {
        let duration = self.captured_at.duration_since(earlier.captured_at).ok()?;
        let interval_secs = duration.as_secs_f64();

        Some(SubscriptionMetricsDelta {
            interval_secs,
            packets_received: self
                .packets_received
                .checked_sub(earlier.packets_received)?,
            bytes_received: self.bytes_received.checked_sub(earlier.bytes_received)?,
            would_block_count: self
                .would_block_count
                .checked_sub(earlier.would_block_count)?,
            receive_errors: self.receive_errors.checked_sub(earlier.receive_errors)?,
            join_count: self.join_count.checked_sub(earlier.join_count)?,
            leave_count: self.leave_count.checked_sub(earlier.leave_count)?,
        })
    }
}

#[cfg(feature = "metrics")]
impl SubscriptionMetricsDelta {
    /// Returns the average packets received per second over the sampled interval.
    pub fn packets_per_sec(&self) -> f64 {
        rate_per_sec(self.packets_received, self.interval_secs)
    }

    /// Returns the average bytes received per second over the sampled interval.
    pub fn bytes_per_sec(&self) -> f64 {
        rate_per_sec(self.bytes_received, self.interval_secs)
    }

    /// Returns the average would-block count per second over the sampled interval.
    pub fn would_block_per_sec(&self) -> f64 {
        rate_per_sec(self.would_block_count, self.interval_secs)
    }

    /// Returns the average receive error count per second over the sampled interval.
    pub fn receive_errors_per_sec(&self) -> f64 {
        rate_per_sec(self.receive_errors, self.interval_secs)
    }
}

/// Tracks successive subscription metrics snapshots and computes deltas between them.
///
/// The first call to `sample()` stores the provided snapshot and returns `None`,
/// because there is no earlier sample to compare against yet.
///
/// Each subsequent call compares the new snapshot against the previous one,
/// updates the stored baseline, and returns the computed delta.
#[cfg(feature = "metrics")]
#[derive(Debug, Default, Clone)]
pub struct SubscriptionMetricsSampler {
    previous: Option<SubscriptionMetricsSnapshot>,
}

#[cfg(feature = "metrics")]
impl SubscriptionMetricsSampler {
    /// Creates a new sampler with no previous snapshot.
    pub fn new() -> Self {
        Self { previous: None }
    }

    /// Samples a new cumulative subscription metrics snapshot and returns the
    /// delta since the previous sample, if any.
    ///
    /// On the first call, this stores `current` and returns `None`.
    ///
    /// On later calls, this returns the delta between `current` and the previous
    /// snapshot, then stores `current` as the new baseline.
    pub fn sample(
        &mut self,
        current: SubscriptionMetricsSnapshot,
    ) -> Option<SubscriptionMetricsDelta> {
        let delta = match &self.previous {
            Some(previous) => current.delta_since(previous),
            None => None,
        };

        self.previous = Some(current);
        delta
    }

    /// Clears the stored baseline snapshot.
    ///
    /// After calling this, the next call to `sample()` will return `None` again.
    pub fn reset(&mut self) {
        self.previous = None;
    }

    /// Returns the currently stored baseline snapshot, if any.
    pub fn previous(&self) -> Option<&SubscriptionMetricsSnapshot> {
        self.previous.as_ref()
    }
}

/// A point-in-time snapshot of process hardware/resource metrics.
///
/// Counter fields in this snapshot are cumulative from the lifetime of the
/// process and can be compared against an earlier snapshot to compute deltas
/// and rates.
///
/// Gauge-like fields such as memory usage, thread count, and open file
/// descriptors represent the current state at the moment the snapshot was
/// taken and should not be interpreted as cumulative counters.
#[cfg(feature = "metrics")]
#[derive(Debug, Clone)]
pub struct HardwareMetricsSnapshot {
    pub cpu_user_secs_total: f64,
    pub cpu_system_secs_total: f64,
    pub rss_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub thread_count: u64,
    pub open_fds: u64,
    pub page_faults_minor_total: u64,
    pub page_faults_major_total: u64,
    pub ctx_switches_voluntary_total: u64,
    pub ctx_switches_involuntary_total: u64,
    pub captured_at: SystemTime,
}

/// The difference between two cumulative hardware metrics snapshots.
///
/// This contains counter-based deltas over the sampled interval and the latest
/// gauge-like values sampled at the end of the interval.
#[cfg(feature = "metrics")]
#[derive(Debug, Clone)]
pub struct HardwareMetricsDelta {
    pub ts: f64,
    pub interval_secs: f64,
    pub cpu_user_secs: f64,
    pub cpu_system_secs: f64,
    pub cpu_total_secs: f64,
    pub cpu_util_percent: f64,
    pub rss_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub thread_count: u64,
    pub open_fds: u64,
    pub page_faults_minor: u64,
    pub page_faults_major: u64,
    pub ctx_switches_voluntary: u64,
    pub ctx_switches_involuntary: u64,
}

#[cfg(feature = "metrics")]
impl HardwareMetricsSnapshot {
    /// Computes the counter deltas between this snapshot and an earlier one.
    ///
    /// Returns `None` if:
    /// - `earlier` was captured after `self`
    /// - any cumulative counter appears to have moved backwards
    pub fn delta_since(&self, earlier: &Self) -> Option<HardwareMetricsDelta> {
        let duration = self.captured_at.duration_since(earlier.captured_at).ok()?;
        let interval_secs = duration.as_secs_f64();

        if self.cpu_user_secs_total < earlier.cpu_user_secs_total
            || self.cpu_system_secs_total < earlier.cpu_system_secs_total
        {
            return None;
        }

        let cpu_user_secs = self.cpu_user_secs_total - earlier.cpu_user_secs_total;
        let cpu_system_secs = self.cpu_system_secs_total - earlier.cpu_system_secs_total;
        let cpu_total_secs = cpu_user_secs + cpu_system_secs;
        let cpu_util_percent = if interval_secs > 0.0 {
            (cpu_total_secs / interval_secs) * 100.0
        } else {
            0.0
        };

        Some(HardwareMetricsDelta {
            ts: duration_since_epoch_secs(self.captured_at),
            interval_secs,
            cpu_user_secs,
            cpu_system_secs,
            cpu_total_secs,
            cpu_util_percent,
            rss_bytes: self.rss_bytes,
            virtual_memory_bytes: self.virtual_memory_bytes,
            thread_count: self.thread_count,
            open_fds: self.open_fds,
            page_faults_minor: self
                .page_faults_minor_total
                .checked_sub(earlier.page_faults_minor_total)?,
            page_faults_major: self
                .page_faults_major_total
                .checked_sub(earlier.page_faults_major_total)?,
            ctx_switches_voluntary: self
                .ctx_switches_voluntary_total
                .checked_sub(earlier.ctx_switches_voluntary_total)?,
            ctx_switches_involuntary: self
                .ctx_switches_involuntary_total
                .checked_sub(earlier.ctx_switches_involuntary_total)?,
        })
    }

    /// Collects a hardware/resource snapshot for the current process on Linux.
    #[cfg(target_os = "linux")]
    pub fn capture_current_process() -> io::Result<Self> {
        let page_size = linux_page_size();
        let clk_tck = linux_clk_tck();
        let proc = read_proc_snapshot(page_size)?;

        Ok(Self {
            cpu_user_secs_total: proc.utime_ticks as f64 / clk_tck as f64,
            cpu_system_secs_total: proc.stime_ticks as f64 / clk_tck as f64,
            rss_bytes: proc.rss_bytes,
            virtual_memory_bytes: proc.vsize_bytes,
            thread_count: proc.num_threads,
            open_fds: proc.open_fds,
            page_faults_minor_total: proc.minflt,
            page_faults_major_total: proc.majflt,
            ctx_switches_voluntary_total: proc.voluntary_ctxt_switches,
            ctx_switches_involuntary_total: proc.nonvoluntary_ctxt_switches,
            captured_at: SystemTime::now(),
        })
    }

    /// Collects a hardware/resource snapshot for the current process on macOS.
    #[cfg(target_os = "macos")]
    pub fn capture_current_process() -> io::Result<Self> {
        let task_info = read_macos_task_info()?;
        let rusage = read_macos_rusage()?;
        let open_fds = fs::read_dir("/dev/fd")?.count() as u64;

        Ok(Self {
            cpu_user_secs_total: timeval_to_secs(rusage.ru_utime),
            cpu_system_secs_total: timeval_to_secs(rusage.ru_stime),
            rss_bytes: task_info.pti_resident_size,
            virtual_memory_bytes: task_info.pti_virtual_size,
            thread_count: task_info.pti_threadnum as u64,
            open_fds,
            page_faults_minor_total: nonnegative_i64_to_u64(rusage.ru_minflt),
            page_faults_major_total: nonnegative_i64_to_u64(rusage.ru_majflt),
            ctx_switches_voluntary_total: nonnegative_i64_to_u64(rusage.ru_nvcsw),
            ctx_switches_involuntary_total: nonnegative_i64_to_u64(rusage.ru_nivcsw),
            captured_at: SystemTime::now(),
        })
    }
}

/// Tracks successive hardware metrics snapshots and computes deltas between them.
///
/// The first call to `sample()` stores the provided snapshot and returns `None`,
/// because there is no earlier sample to compare against yet.
#[cfg(feature = "metrics")]
#[derive(Debug, Default, Clone)]
pub struct HardwareMetricsSampler {
    previous: Option<HardwareMetricsSnapshot>,
}

#[cfg(feature = "metrics")]
impl HardwareMetricsSampler {
    /// Creates a new sampler with no previous snapshot.
    pub fn new() -> Self {
        Self { previous: None }
    }

    /// Samples a new cumulative hardware metrics snapshot and returns the delta
    /// since the previous sample, if any.
    pub fn sample(&mut self, current: HardwareMetricsSnapshot) -> Option<HardwareMetricsDelta> {
        let delta = match &self.previous {
            Some(previous) => current.delta_since(previous),
            None => None,
        };

        self.previous = Some(current);
        delta
    }

    /// Clears the stored baseline snapshot.
    pub fn reset(&mut self) {
        self.previous = None;
    }

    /// Returns the currently stored baseline snapshot, if any.
    pub fn previous(&self) -> Option<&HardwareMetricsSnapshot> {
        self.previous.as_ref()
    }
}

#[cfg(all(feature = "metrics", target_os = "linux"))]
#[derive(Debug, Clone)]
struct ProcSnapshot {
    utime_ticks: u64,
    stime_ticks: u64,
    minflt: u64,
    majflt: u64,
    num_threads: u64,
    vsize_bytes: u64,
    rss_bytes: u64,
    voluntary_ctxt_switches: u64,
    nonvoluntary_ctxt_switches: u64,
    open_fds: u64,
}

#[cfg(all(feature = "metrics", target_os = "linux"))]
fn linux_page_size() -> u64 {
    linux_sysconf(libc::_SC_PAGESIZE, 4096)
}

#[cfg(all(feature = "metrics", target_os = "linux"))]
fn linux_clk_tck() -> u64 {
    linux_sysconf(libc::_SC_CLK_TCK, 100)
}

#[cfg(all(feature = "metrics", target_os = "linux"))]
fn linux_sysconf(name: libc::c_int, fallback: u64) -> u64 {
    let value = unsafe { libc::sysconf(name) };
    if value > 0 { value as u64 } else { fallback }
}

#[cfg(all(feature = "metrics", target_os = "linux"))]
fn read_proc_snapshot(page_size: u64) -> io::Result<ProcSnapshot> {
    let stat_content = fs::read_to_string("/proc/self/stat")?;
    stat_content.find('(').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing '(' in /proc/self/stat")
    })?;
    let close_paren = stat_content.rfind(')').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing ')' in /proc/self/stat")
    })?;

    let after = stat_content
        .get(close_paren + 1..)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid /proc/self/stat suffix")
        })?
        .trim();
    let fields: Vec<&str> = after.split_whitespace().collect();

    if fields.len() < 22 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too few fields in /proc/self/stat",
        ));
    }

    let parse_u64 = |index: usize, name: &str| -> io::Result<u64> {
        fields[index].parse::<u64>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse {name} from /proc/self/stat: {error}"),
            )
        })
    };

    let parse_i64 = |index: usize, name: &str| -> io::Result<i64> {
        fields[index].parse::<i64>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse {name} from /proc/self/stat: {error}"),
            )
        })
    };

    let minflt = parse_u64(7, "minflt")?;
    let majflt = parse_u64(9, "majflt")?;
    let utime_ticks = parse_u64(11, "utime")?;
    let stime_ticks = parse_u64(12, "stime")?;
    let num_threads = parse_u64(17, "num_threads")?;
    let vsize_bytes = parse_u64(20, "vsize")?;
    let rss_pages = parse_i64(21, "rss")?;
    let rss_bytes = if rss_pages <= 0 {
        0
    } else {
        (rss_pages as u64).saturating_mul(page_size)
    };

    let status_content = fs::read_to_string("/proc/self/status")?;
    let mut voluntary_ctxt_switches = 0;
    let mut nonvoluntary_ctxt_switches = 0;
    for line in status_content.lines() {
        if let Some(value) = line.strip_prefix("voluntary_ctxt_switches:") {
            voluntary_ctxt_switches = value.trim().parse::<u64>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse voluntary_ctxt_switches: {error}"),
                )
            })?;
        } else if let Some(value) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
            nonvoluntary_ctxt_switches = value.trim().parse::<u64>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse nonvoluntary_ctxt_switches: {error}"),
                )
            })?;
        }
    }

    let open_fds = fs::read_dir("/proc/self/fd")?.count() as u64;

    Ok(ProcSnapshot {
        utime_ticks,
        stime_ticks,
        minflt,
        majflt,
        num_threads,
        vsize_bytes,
        rss_bytes,
        voluntary_ctxt_switches,
        nonvoluntary_ctxt_switches,
        open_fds,
    })
}

#[cfg(all(feature = "metrics", target_os = "macos"))]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct TimeVal {
    tv_sec: i64,
    tv_usec: i32,
    #[cfg(target_pointer_width = "64")]
    _pad: i32,
}

#[cfg(all(feature = "metrics", target_os = "macos"))]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct RUsage {
    ru_utime: TimeVal,
    ru_stime: TimeVal,
    ru_maxrss: i64,
    ru_ixrss: i64,
    ru_idrss: i64,
    ru_isrss: i64,
    ru_minflt: i64,
    ru_majflt: i64,
    ru_nswap: i64,
    ru_inblock: i64,
    ru_oublock: i64,
    ru_msgsnd: i64,
    ru_msgrcv: i64,
    ru_nsignals: i64,
    ru_nvcsw: i64,
    ru_nivcsw: i64,
}

#[cfg(all(feature = "metrics", target_os = "macos"))]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct ProcTaskInfo {
    pti_virtual_size: u64,
    pti_resident_size: u64,
    pti_total_user: u64,
    pti_total_system: u64,
    pti_threads_user: u64,
    pti_threads_system: u64,
    pti_policy: i32,
    pti_faults: i32,
    pti_pageins: i32,
    pti_cow_faults: i32,
    pti_messages_sent: i32,
    pti_messages_received: i32,
    pti_syscalls_mach: i32,
    pti_syscalls_unix: i32,
    pti_csw: i32,
    pti_threadnum: i32,
    pti_numrunning: i32,
    pti_priority: i32,
}

#[cfg(all(feature = "metrics", target_os = "macos"))]
const RUSAGE_SELF: c_int = 0;
#[cfg(all(feature = "metrics", target_os = "macos"))]
const PROC_PIDTASKINFO: c_int = 4;

#[cfg(all(feature = "metrics", target_os = "macos"))]
unsafe extern "C" {
    fn getpid() -> c_int;
    fn getrusage(who: c_int, usage: *mut RUsage) -> c_int;
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
}

#[cfg(all(feature = "metrics", target_os = "macos"))]
fn timeval_to_secs(value: TimeVal) -> f64 {
    value.tv_sec as f64 + (value.tv_usec as f64 / 1_000_000.0)
}

#[cfg(all(feature = "metrics", target_os = "macos"))]
fn nonnegative_i64_to_u64(value: i64) -> u64 {
    if value <= 0 { 0 } else { value as u64 }
}

#[cfg(all(feature = "metrics", target_os = "macos"))]
fn read_macos_rusage() -> io::Result<RUsage> {
    let mut usage: RUsage = unsafe { zeroed() };
    let result = unsafe { getrusage(RUSAGE_SELF, &mut usage) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usage)
}

#[cfg(all(feature = "metrics", target_os = "macos"))]
fn read_macos_task_info() -> io::Result<ProcTaskInfo> {
    let mut info: ProcTaskInfo = unsafe { zeroed() };
    let pid = unsafe { getpid() };
    let size = size_of::<ProcTaskInfo>() as c_int;
    let written = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTASKINFO,
            0,
            &mut info as *mut ProcTaskInfo as *mut c_void,
            size,
        )
    };

    if written != size {
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("proc_pidinfo(PROC_PIDTASKINFO) returned {written} bytes, expected {size}"),
        ));
    }

    Ok(info)
}

/// A point-in-time snapshot of cumulative context metrics.
///
/// Counter fields in this snapshot are cumulative from the lifetime of the
/// context, including packets received by subscriptions that have since been
/// removed, and can be compared against an earlier snapshot to compute deltas
/// and rates.
///
/// Gauge-like fields such as `active_subscriptions` and `joined_subscriptions`
/// represent the current state at the moment the snapshot was taken and should
/// not be interpreted as cumulative counters.
#[cfg(feature = "metrics")]
#[derive(Debug, Clone)]
pub struct ContextMetricsSnapshot {
    pub subscriptions_added: u64,
    pub subscriptions_removed: u64,
    pub active_subscriptions: usize,
    pub joined_subscriptions: usize,
    pub total_packets_received: u64,
    pub total_bytes_received: u64,
    pub total_would_block_count: u64,
    pub total_receive_errors: u64,
    pub total_join_count: u64,
    pub total_leave_count: u64,
    pub batch_calls: u64,
    pub batch_packets_received: u64,
    pub captured_at: SystemTime,
}

/// The difference between two cumulative context metrics snapshots.
///
/// This contains only counter-based deltas over the sampled interval.
/// Gauge-like values such as active subscription counts are intentionally not
/// included here; callers should inspect those directly from the latest
/// snapshot instead.
#[cfg(feature = "metrics")]
#[derive(Debug, Clone)]
pub struct ContextMetricsDelta {
    pub interval_secs: f64,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub would_block_count: u64,
    pub receive_errors: u64,
    pub join_count: u64,
    pub leave_count: u64,
    pub batch_calls: u64,
    pub batch_packets_received: u64,
}

#[cfg(feature = "metrics")]
impl ContextMetricsSnapshot {
    /// Computes the counter deltas between this snapshot and an earlier one.
    ///
    /// Returns `None` if:
    /// - `earlier` was captured after `self`
    /// - any cumulative counter appears to have moved backwards
    ///
    /// The resulting delta contains only counter-based values and the elapsed
    /// interval in seconds. Gauge-like values such as active subscription counts
    /// should be read directly from the latest snapshot instead.
    pub fn delta_since(&self, earlier: &Self) -> Option<ContextMetricsDelta> {
        let duration = self.captured_at.duration_since(earlier.captured_at).ok()?;
        let interval_secs = duration.as_secs_f64();

        Some(ContextMetricsDelta {
            interval_secs,
            packets_received: self
                .total_packets_received
                .checked_sub(earlier.total_packets_received)?,
            bytes_received: self
                .total_bytes_received
                .checked_sub(earlier.total_bytes_received)?,
            would_block_count: self
                .total_would_block_count
                .checked_sub(earlier.total_would_block_count)?,
            receive_errors: self
                .total_receive_errors
                .checked_sub(earlier.total_receive_errors)?,
            join_count: self
                .total_join_count
                .checked_sub(earlier.total_join_count)?,
            leave_count: self
                .total_leave_count
                .checked_sub(earlier.total_leave_count)?,
            batch_calls: self.batch_calls.checked_sub(earlier.batch_calls)?,
            batch_packets_received: self
                .batch_packets_received
                .checked_sub(earlier.batch_packets_received)?,
        })
    }
}

#[cfg(feature = "metrics")]
impl ContextMetricsDelta {
    /// Returns the average packets received per second over the sampled interval.
    pub fn packets_per_sec(&self) -> f64 {
        rate_per_sec(self.packets_received, self.interval_secs)
    }

    /// Returns the average bytes received per second over the sampled interval.
    pub fn bytes_per_sec(&self) -> f64 {
        rate_per_sec(self.bytes_received, self.interval_secs)
    }

    /// Returns the average would-block count per second over the sampled interval.
    pub fn would_block_per_sec(&self) -> f64 {
        rate_per_sec(self.would_block_count, self.interval_secs)
    }

    /// Returns the average receive error count per second over the sampled interval.
    pub fn receive_errors_per_sec(&self) -> f64 {
        rate_per_sec(self.receive_errors, self.interval_secs)
    }
}

/// Tracks successive context metrics snapshots and computes deltas between them.
///
/// The first call to `sample()` stores the provided snapshot and returns `None`,
/// because there is no earlier sample to compare against yet.
///
/// Each subsequent call compares the new snapshot against the previous one,
/// updates the stored baseline, and returns the computed delta.
#[cfg(feature = "metrics")]
#[derive(Debug, Default, Clone)]
pub struct ContextMetricsSampler {
    previous: Option<ContextMetricsSnapshot>,
}

#[cfg(feature = "metrics")]
impl ContextMetricsSampler {
    /// Creates a new sampler with no previous snapshot.
    pub fn new() -> Self {
        Self { previous: None }
    }

    /// Samples a new cumulative context metrics snapshot and returns the delta
    /// since the previous sample, if any.
    ///
    /// On the first call, this stores `current` and returns `None`.
    ///
    /// On later calls, this returns the delta between `current` and the previous
    /// snapshot, then stores `current` as the new baseline.
    pub fn sample(&mut self, current: ContextMetricsSnapshot) -> Option<ContextMetricsDelta> {
        let delta = match &self.previous {
            Some(previous) => current.delta_since(previous),
            None => None,
        };

        self.previous = Some(current);
        delta
    }

    /// Clears the stored baseline snapshot.
    ///
    /// After calling this, the next call to `sample()` will return `None` again.
    pub fn reset(&mut self) {
        self.previous = None;
    }

    /// Returns the currently stored baseline snapshot, if any.
    pub fn previous(&self) -> Option<&ContextMetricsSnapshot> {
        self.previous.as_ref()
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    use crate::Context;
    use crate::Subscription;
    use crate::SubscriptionConfig;
    use crate::test_support::{
        make_multicast_sender, recv_next_packet, sample_config_on_unused_port,
    };

    use std::net::SocketAddrV4;
    use std::thread;
    use std::time::{Duration, Instant};

    fn ipv4_group(config: &SubscriptionConfig) -> std::net::Ipv4Addr {
        config.ipv4_membership().unwrap().group
    }

    // Test helper: uses fixed non-zero values for unrelated fields.
    fn make_context_snapshot(
        total_packets_received: u64,
        total_bytes_received: u64,
        total_would_block_count: u64,
        total_receive_errors: u64,
        batch_calls: u64,
        batch_packets_received: u64,
    ) -> ContextMetricsSnapshot {
        ContextMetricsSnapshot {
            subscriptions_added: 1,
            subscriptions_removed: 0,
            active_subscriptions: 1,
            joined_subscriptions: 1,
            total_packets_received,
            total_bytes_received,
            total_would_block_count,
            total_receive_errors,
            total_join_count: 1,
            total_leave_count: 0,
            batch_calls,
            batch_packets_received,
            captured_at: SystemTime::now(),
        }
    }

    fn assert_sync<T: Sync>() {}

    // Test helper: uses fixed non-zero values for unrelated fields.
    fn make_subscription_snapshot(
        packets_received: u64,
        bytes_received: u64,
        would_block_count: u64,
        receive_errors: u64,
        last_payload_len: Option<usize>,
    ) -> SubscriptionMetricsSnapshot {
        SubscriptionMetricsSnapshot {
            packets_received,
            bytes_received,
            would_block_count,
            receive_errors,
            join_count: 1,
            leave_count: 0,
            last_payload_len,
            last_source: None,
            last_receive_at: None,
            captured_at: SystemTime::now(),
        }
    }

    struct HardwareSnapshotArgs {
        cpu_user_secs_total: f64,
        cpu_system_secs_total: f64,
        rss_bytes: u64,
        virtual_memory_bytes: u64,
        thread_count: u64,
        open_fds: u64,
        page_faults_minor_total: u64,
        page_faults_major_total: u64,
        ctx_switches_voluntary_total: u64,
        ctx_switches_involuntary_total: u64,
    }

    fn make_hardware_snapshot(args: HardwareSnapshotArgs) -> HardwareMetricsSnapshot {
        HardwareMetricsSnapshot {
            cpu_user_secs_total: args.cpu_user_secs_total,
            cpu_system_secs_total: args.cpu_system_secs_total,
            rss_bytes: args.rss_bytes,
            virtual_memory_bytes: args.virtual_memory_bytes,
            thread_count: args.thread_count,
            open_fds: args.open_fds,
            page_faults_minor_total: args.page_faults_minor_total,
            page_faults_major_total: args.page_faults_major_total,
            ctx_switches_voluntary_total: args.ctx_switches_voluntary_total,
            ctx_switches_involuntary_total: args.ctx_switches_involuntary_total,
            captured_at: SystemTime::now(),
        }
    }

    #[test]
    fn context_metrics_sampler_returns_none_on_first_sample() {
        let snapshot = make_context_snapshot(10, 1000, 2, 0, 3, 10);

        let mut sampler = ContextMetricsSampler::new();
        let delta = sampler.sample(snapshot);

        assert!(delta.is_none());
    }

    #[test]
    fn context_metrics_sampler_returns_delta_on_second_sample() {
        let earlier = make_context_snapshot(10, 1000, 2, 0, 3, 10);

        thread::sleep(Duration::from_millis(10));

        let later = make_context_snapshot(15, 1600, 3, 1, 5, 15);

        let mut sampler = ContextMetricsSampler::new();
        assert!(sampler.sample(earlier).is_none());

        let delta = sampler.sample(later).unwrap();

        assert_eq!(delta.packets_received, 5);
        assert_eq!(delta.bytes_received, 600);
        assert_eq!(delta.would_block_count, 1);
        assert_eq!(delta.receive_errors, 1);
        assert_eq!(delta.join_count, 0);
        assert_eq!(delta.leave_count, 0);
        assert_eq!(delta.batch_calls, 2);
        assert_eq!(delta.batch_packets_received, 5);
        assert!(delta.interval_secs > 0.0);
    }

    #[test]
    fn subscription_metrics_sampler_returns_none_on_first_sample() {
        let snapshot = make_subscription_snapshot(10, 1000, 2, 0, Some(100));

        let mut sampler = SubscriptionMetricsSampler::new();
        let delta = sampler.sample(snapshot);

        assert!(delta.is_none());
    }

    #[test]
    fn subscription_metrics_sampler_returns_delta_on_second_sample() {
        let earlier = make_subscription_snapshot(10, 1000, 2, 0, Some(100));

        thread::sleep(Duration::from_millis(10));

        let later = make_subscription_snapshot(12, 1300, 3, 1, Some(150));

        let mut sampler = SubscriptionMetricsSampler::new();
        assert!(sampler.sample(earlier).is_none());

        let delta = sampler.sample(later).unwrap();

        assert_eq!(delta.packets_received, 2);
        assert_eq!(delta.bytes_received, 300);
        assert_eq!(delta.would_block_count, 1);
        assert_eq!(delta.receive_errors, 1);
        assert_eq!(delta.join_count, 0);
        assert_eq!(delta.leave_count, 0);
        assert!(delta.interval_secs > 0.0);
    }

    #[test]
    fn hardware_metrics_sampler_returns_none_on_first_sample() {
        let snapshot = make_hardware_snapshot(HardwareSnapshotArgs {
            cpu_user_secs_total: 1.0,
            cpu_system_secs_total: 0.5,
            rss_bytes: 4096,
            virtual_memory_bytes: 16384,
            thread_count: 2,
            open_fds: 5,
            page_faults_minor_total: 10,
            page_faults_major_total: 1,
            ctx_switches_voluntary_total: 7,
            ctx_switches_involuntary_total: 2,
        });

        let mut sampler = HardwareMetricsSampler::new();
        let delta = sampler.sample(snapshot);

        assert!(delta.is_none());
    }

    #[test]
    fn hardware_metrics_sampler_returns_delta_on_second_sample() {
        let earlier = make_hardware_snapshot(HardwareSnapshotArgs {
            cpu_user_secs_total: 1.0,
            cpu_system_secs_total: 0.5,
            rss_bytes: 4096,
            virtual_memory_bytes: 16384,
            thread_count: 2,
            open_fds: 5,
            page_faults_minor_total: 10,
            page_faults_major_total: 1,
            ctx_switches_voluntary_total: 7,
            ctx_switches_involuntary_total: 2,
        });

        thread::sleep(Duration::from_millis(10));

        let later = make_hardware_snapshot(HardwareSnapshotArgs {
            cpu_user_secs_total: 1.4,
            cpu_system_secs_total: 0.7,
            rss_bytes: 8192,
            virtual_memory_bytes: 32768,
            thread_count: 3,
            open_fds: 6,
            page_faults_minor_total: 15,
            page_faults_major_total: 2,
            ctx_switches_voluntary_total: 11,
            ctx_switches_involuntary_total: 4,
        });

        let mut sampler = HardwareMetricsSampler::new();
        assert!(sampler.sample(earlier).is_none());

        let delta = sampler.sample(later).unwrap();

        assert!((delta.cpu_user_secs - 0.4).abs() < 1e-9);
        assert!((delta.cpu_system_secs - 0.2).abs() < 1e-9);
        assert!((delta.cpu_total_secs - 0.6).abs() < 1e-9);
        assert!(delta.cpu_util_percent > 0.0);
        assert_eq!(delta.rss_bytes, 8192);
        assert_eq!(delta.virtual_memory_bytes, 32768);
        assert_eq!(delta.thread_count, 3);
        assert_eq!(delta.open_fds, 6);
        assert_eq!(delta.page_faults_minor, 5);
        assert_eq!(delta.page_faults_major, 1);
        assert_eq!(delta.ctx_switches_voluntary, 4);
        assert_eq!(delta.ctx_switches_involuntary, 2);
        assert!(delta.interval_secs > 0.0);
        assert!(delta.ts > 0.0);
    }

    #[test]
    fn metrics_snapshot_tracks_join_and_leave_counts() {
        let mut context = Context::new();
        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        context.join_subscription(id).unwrap();
        context.leave_subscription(id).unwrap();

        let metrics = context.metrics_snapshot();
        let subscription_metrics = context.get_subscription(id).unwrap().metrics_snapshot();

        assert_eq!(metrics.subscriptions_added, 1);
        assert_eq!(metrics.subscriptions_removed, 0);
        assert_eq!(metrics.active_subscriptions, 1);
        assert_eq!(metrics.joined_subscriptions, 0);
        assert_eq!(metrics.total_join_count, 1);
        assert_eq!(metrics.total_leave_count, 1);

        assert_eq!(subscription_metrics.join_count, 1);
        assert_eq!(subscription_metrics.leave_count, 1);
    }

    #[test]
    fn metrics_snapshot_tracks_received_packets_and_bytes() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let sender = make_multicast_sender();

        let payload = b"metrics-packet";
        sender
            .send_to(
                payload,
                SocketAddrV4::new(ipv4_group(&config), config.dst_port),
            )
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = recv_next_packet(&mut context, deadline);
        assert_eq!(&packet.payload[..], payload);

        let metrics = context.metrics_snapshot();
        let subscription_metrics = context.get_subscription(id).unwrap().metrics_snapshot();

        assert_eq!(metrics.total_packets_received, 1);
        assert_eq!(metrics.total_bytes_received, payload.len() as u64);
        assert_eq!(subscription_metrics.packets_received, 1);
        assert_eq!(subscription_metrics.bytes_received, payload.len() as u64);
        assert_eq!(subscription_metrics.last_payload_len, Some(payload.len()));
        assert!(subscription_metrics.last_source.is_some());
        assert!(subscription_metrics.last_receive_at.is_some());
    }

    #[test]
    fn context_metrics_totals_survive_subscription_removal() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let sender = make_multicast_sender();

        let payload = b"lifetime-metrics";
        sender
            .send_to(
                payload,
                SocketAddrV4::new(ipv4_group(&config), config.dst_port),
            )
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = recv_next_packet(&mut context, deadline);
        assert_eq!(&packet.payload[..], payload);

        let before_removal = context.metrics_snapshot();
        assert!(context.remove_subscription(id));

        let after_removal = context.metrics_snapshot();

        assert_eq!(before_removal.total_packets_received, 1);
        assert_eq!(before_removal.total_bytes_received, payload.len() as u64);
        assert_eq!(after_removal.total_packets_received, 1);
        assert_eq!(after_removal.total_bytes_received, payload.len() as u64);
        assert_eq!(after_removal.active_subscriptions, 0);
        assert_eq!(after_removal.joined_subscriptions, 0);
        assert_eq!(after_removal.subscriptions_removed, 1);
    }

    #[test]
    fn metrics_snapshot_delta_tracks_counter_changes() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let earlier = context.metrics_snapshot();

        let sender = make_multicast_sender();

        let payload = b"delta-metrics";
        sender
            .send_to(
                payload,
                SocketAddrV4::new(ipv4_group(&config), config.dst_port),
            )
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = recv_next_packet(&mut context, deadline);
        assert_eq!(&packet.payload[..], payload);

        let later = context.metrics_snapshot();
        let delta = later.delta_since(&earlier).unwrap();

        assert_eq!(delta.packets_received, 1);
        assert_eq!(delta.bytes_received, payload.len() as u64);
        assert_eq!(delta.join_count, 0);
        assert_eq!(delta.leave_count, 0);
    }

    #[test]
    fn try_recv_all_counts_one_batch_call_per_public_invocation() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let sender = make_multicast_sender();
        let destination = SocketAddrV4::new(ipv4_group(&config), config.dst_port);
        sender.send_to(b"batch-one", destination).unwrap();
        sender.send_to(b"batch-two", destination).unwrap();

        thread::sleep(Duration::from_millis(50));

        let mut packets = Vec::new();
        let received = context.try_recv_all_into(&mut packets).unwrap();
        let metrics = context.metrics_snapshot();

        assert_eq!(received, 2);
        assert_eq!(packets.len(), 2);
        assert_eq!(metrics.batch_calls, 1);
        assert_eq!(metrics.batch_packets_received, 2);
    }

    #[test]
    fn metrics_feature_preserves_sync_for_core_types() {
        assert_sync::<Context>();
        assert_sync::<Subscription>();
    }
}
