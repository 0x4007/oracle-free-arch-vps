#!/usr/bin/python3
"""Sample only weekly backup units; never start a backup or inspect its inputs."""
import datetime
import fcntl
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time

STATE = pathlib.Path('/var/lib/weekly-backup-telemetry')
CGROUP_ROOT = pathlib.Path('/sys/fs/cgroup')
UNIT_RE = re.compile(r'^arch-vps-b2-(?:v2-)?(worker|verify|prune)-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})(?:-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}))?\.service$')
def unit_match(name):
    match = UNIT_RE.fullmatch(name)
    if not match or bool(match[3]) != name.startswith('arch-vps-b2-v2-'):
        return None
    if match[1] == 'prune' and not match[3]:
        return None
    return match


MAX_SAMPLE_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 48
RETENTION_SECONDS = 90 * 86400
PROPERTIES = (
    'Id', 'InvocationID', 'ActiveState', 'SubState', 'Result', 'MainPID',
    'ExecMainCode', 'ExecMainStatus', 'ExecMainStartTimestamp',
    'ExecMainExitTimestamp', 'ActiveEnterTimestamp', 'InactiveEnterTimestamp',
    'MemoryCurrent', 'MemoryPeak', 'MemorySwapCurrent', 'MemorySwapPeak',
    'CPUUsageNSec', 'IOReadBytes', 'IOWriteBytes', 'IOReadOperations',
    'IOWriteOperations', 'TasksCurrent', 'ControlGroup', 'Slice',
    'MemoryHigh', 'MemoryMax', 'MemorySwapMax', 'EffectiveMemoryHigh',
    'EffectiveMemoryMax', 'TasksMax', 'EffectiveTasksMax',
    'CPUQuotaPerSecUSec', 'CPUWeight', 'Nice', 'RuntimeMaxUSec',
)
ACCOUNTING = (
    'MemoryCurrent', 'MemoryPeak', 'MemorySwapCurrent', 'MemorySwapPeak',
    'CPUUsageNSec', 'IOReadBytes', 'IOWriteBytes', 'IOReadOperations',
    'IOWriteOperations', 'TasksCurrent',
)
STATUS = (
    'InvocationID', 'ActiveState', 'SubState', 'Result', 'ExecMainCode',
    'ExecMainStatus', 'ExecMainStartTimestamp', 'ExecMainExitTimestamp',
    'ActiveEnterTimestamp', 'InactiveEnterTimestamp',
)
LIMITS = (
    'Slice', 'MemoryHigh', 'MemoryMax', 'MemorySwapMax', 'EffectiveMemoryHigh',
    'EffectiveMemoryMax', 'TasksMax', 'EffectiveTasksMax',
    'CPUQuotaPerSecUSec', 'CPUWeight', 'Nice', 'RuntimeMaxUSec',
)


def command(args):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=20, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}).stdout


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def value(raw):
    if raw is None or raw == '' or raw == '[not set]':
        return None
    if raw.isdigit():
        number = int(raw)
        return None if number == 18446744073709551615 else number
    return raw


def read_text(path):
    try:
        return path.read_text().strip()
    except (OSError, UnicodeError):
        return None


def counter(path):
    raw = read_text(path)
    return int(raw) if raw and raw.isdigit() else None


def counters(path):
    raw = read_text(path)
    result = {}
    for line in (raw or '').splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isdigit():
            result[fields[0]] = int(fields[1])
    return result or None


def io_counters(path):
    raw = read_text(path)
    result = {}
    for line in (raw or '').splitlines():
        fields = line.split()
        if not fields:
            continue
        device = {}
        for field in fields[1:]:
            key, sep, number = field.partition('=')
            if sep and number.isdigit():
                device[key] = int(number)
        result[fields[0]] = device
    return result or None


def cgroup_snapshot(raw_path):
    if not raw_path:
        return None
    path = CGROUP_ROOT / raw_path.lstrip('/')
    if not path.is_relative_to(CGROUP_ROOT) or not path.is_dir():
        return None
    stats = counters(path / 'memory.stat') or {}
    memory = {key: stats.get(key) for key in (
        'anon', 'file', 'kernel', 'sock', 'shmem', 'file_mapped',
        'file_dirty', 'file_writeback', 'slab',
    )}
    # Summed resident pages are sampled process RSS: shared pages can be counted
    # more than once. This is deliberately distinct from cgroup anonymous memory.
    pids = set()
    try:
        for current, dirs, files in os.walk(path):
            if 'cgroup.procs' in files:
                for pid in (read_text(pathlib.Path(current) / 'cgroup.procs') or '').split():
                    if pid.isdigit():
                        pids.add(pid)
    except OSError:
        pass
    rss = 0
    readable = 0
    for pid in pids:
        statm = read_text(pathlib.Path('/proc') / pid / 'statm')
        fields = (statm or '').split()
        if len(fields) > 1 and fields[1].isdigit():
            rss += int(fields[1]) * os.sysconf('SC_PAGE_SIZE')
            readable += 1
    ancestors = []
    current = path
    while True:
        ancestors.append({
            'scope': current.name if current != CGROUP_ROOT else 'root',
            'memory_high': read_text(current / 'memory.high'),
            'memory_max': read_text(current / 'memory.max'),
            'memory_swap_max': read_text(current / 'memory.swap.max'),
            'cpu_max': read_text(current / 'cpu.max'),
            'pids_max': read_text(current / 'pids.max'),
            'io_max': read_text(current / 'io.max'),
        })
        if current == CGROUP_ROOT:
            break
        current = current.parent
    return {
        'memory_current_bytes': counter(path / 'memory.current'),
        'memory_peak_bytes': counter(path / 'memory.peak'),
        'memory_swap_current_bytes': counter(path / 'memory.swap.current'),
        'memory_swap_peak_bytes': counter(path / 'memory.swap.peak'),
        'memory_stat_bytes': memory,
        'memory_events': counters(path / 'memory.events'),
        'memory_events_local': counters(path / 'memory.events.local'),
        'cpu_stat': counters(path / 'cpu.stat'),
        'io_stat': io_counters(path / 'io.stat'),
        'pids_current': counter(path / 'pids.current'),
        'pids_peak': counter(path / 'pids.peak'),
        'sampled_process_rss_sum_bytes': rss if readable else None,
        'sampled_process_count': len(pids),
        'sampled_process_rss_readable_count': readable,
        'limits_by_ancestor': ancestors,
    }


def atomic_json(path, record):
    fd, name = tempfile.mkstemp(prefix='.summary-', dir=STATE)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(record, stream, sort_keys=True, separators=(',', ':'))
            stream.write('\n')
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def append_sample(path, record):
    with path.open('a') as stream:
        json.dump(record, stream, sort_keys=True, separators=(',', ':'))
        stream.write('\n')
    os.chmod(path, 0o600)
    if path.stat().st_size > MAX_SAMPLE_BYTES:
        with path.open('rb') as stream:
            stream.seek(-MAX_SAMPLE_BYTES // 2, os.SEEK_END)
            stream.readline()
            recent = stream.read()
        fd, name = tempfile.mkstemp(prefix='.samples-', dir=STATE)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(recent)
        os.replace(name, path)
        return True
    return False


def maximum(target, key, number):
    if isinstance(number, int):
        target[key] = max(target.get(key, 0), number)


def maintain_summary(summary, sample):
    sampled = summary.setdefault('sampled_peaks', {})
    authoritative = summary.setdefault('authoritative_peaks', {})
    cg = sample.get('cgroup') or {}
    memory = cg.get('memory_stat_bytes') or {}
    for key, number in {
        'memory_current_bytes': cg.get('memory_current_bytes'),
        'anonymous_bytes': memory.get('anon'),
        'file_cache_bytes': memory.get('file'),
        'process_rss_sum_bytes': cg.get('sampled_process_rss_sum_bytes'),
        'memory_swap_current_bytes': cg.get('memory_swap_current_bytes'),
        'tasks_current': cg.get('pids_current'),
    }.items():
        maximum(sampled, key, number)
    acct = sample['systemd_accounting']
    for key, number in {
        'cgroup_memory_peak_bytes': cg.get('memory_peak_bytes'),
        'cgroup_memory_swap_peak_bytes': cg.get('memory_swap_peak_bytes'),
        'cgroup_tasks_peak': cg.get('pids_peak'),
        'systemd_memory_peak_bytes': acct.get('MemoryPeak'),
        'systemd_memory_swap_peak_bytes': acct.get('MemorySwapPeak'),
    }.items():
        maximum(authoritative, key, number)
    summary['last_systemd_accounting'] = acct
    if cg:
        summary['last_cgroup_counters'] = {key: cg.get(key) for key in (
            'memory_events', 'memory_events_local', 'cpu_stat', 'io_stat',
            'pids_current', 'pids_peak',
        )}
        summary['last_cgroup_timestamp'] = sample['timestamp']
        summary['last_cgroup_limits_by_ancestor'] = cg['limits_by_ancestor']


def prune():
    now = time.time()
    files = sorted(STATE.glob('*.summary.json'), key=lambda p: p.stat().st_mtime, reverse=True)
    for index, path in enumerate(files):
        if index < MAX_RECORDS and now - path.stat().st_mtime <= RETENTION_SECONDS:
            continue
        try:
            summary = json.loads(path.read_text())
            if not summary.get('completed'):
                continue
            path.with_name(path.name.removesuffix('.summary.json') + '.jsonl').unlink(missing_ok=True)
            path.unlink()
        except (OSError, ValueError):
            continue


def collect():
    output = command(['systemctl', 'list-units', '--all', '--plain', '--no-legend',
                      '--no-pager', '--type=service',
                      'arch-vps-b2-worker-*.service', 'arch-vps-b2-verify-*.service',
                      'arch-vps-b2-v2-worker-*.service', 'arch-vps-b2-v2-verify-*.service',
                      'arch-vps-b2-v2-prune-*.service'])
    units = [line.split()[0] for line in output.splitlines()
             if line.split() and unit_match(line.split()[0])]
    if not units:
        prune()
        return
    args = ['systemctl', 'show', '--no-pager']
    args.extend('-p' + prop for prop in PROPERTIES)
    output = command(args + units)
    for block in output.strip().split('\n\n'):
        raw = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        unit = raw.get('Id', '')
        match = unit_match(unit)
        if not match or not raw.get('InvocationID'):
            continue
        props = {key: value(raw.get(key)) for key in PROPERTIES}
        running = props.get('MainPID', 0) not in (None, 0) or props.get('SubState') in (
            'start-pre', 'start', 'start-post', 'stop', 'stop-sigterm', 'stop-sigkill', 'stop-post',
        )
        key = unit.removesuffix('.service') + '-' + raw['InvocationID'][:12]
        summary_path = STATE / (key + '.summary.json')
        try:
            summary = json.loads(summary_path.read_text())
        except (OSError, ValueError):
            summary = {
                'schema_version': 1, 'unit': unit, 'job_id': match[2],
                'role': match[1], 'invocation_id': raw['InvocationID'],
                'first_observed_at': utcnow(), 'sample_count': 0,
                'sampling_interval_seconds': 30,
                'peak_notes': {
                    'sampled': '30 second samples can miss short peaks; RSS sums can double count shared pages.',
                    'authoritative': 'Kernel/systemd peaks cover the invocation; final systemd counters survive cgroup removal when retained.',
                    'cgroup_counters': 'Last cgroup counters may precede completion if the cgroup is removed between samples.',
                },
            }
        status = {key: props.get(key) for key in STATUS}
        accounting = {key: props.get(key) for key in ACCOUNTING}
        fingerprint = {'status': status, 'accounting': accounting}
        if not running and summary.get('completed') and summary.get('final_fingerprint') == fingerprint:
            continue
        sample = {
            'timestamp': utcnow(), 'unit': unit, 'job_id': match[2],
            'invocation_id': raw['InvocationID'], 'running': running,
            'systemd_status': status, 'systemd_accounting': accounting,
            'systemd_limits': {key: props.get(key) for key in LIMITS},
            'cgroup': cgroup_snapshot(raw.get('ControlGroup')),
        }
        summary['last_observed_at'] = sample['timestamp']
        summary['sample_count'] += 1
        summary['completed'] = not running
        summary['last_systemd_status'] = status
        summary['last_systemd_limits'] = sample['systemd_limits']
        maintain_summary(summary, sample)
        if not running:
            summary['final_fingerprint'] = fingerprint
            summary['completion_observed_at'] = sample['timestamp']
        if append_sample(STATE / (key + '.jsonl'), sample):
            summary['older_samples_trimmed'] = True
        atomic_json(summary_path, summary)
    prune()


def main():
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True)
    with (STATE / '.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        collect()


if __name__ == '__main__':
    main()
