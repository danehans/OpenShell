"""Fixed real-Codex replacement for the retained fixture's Python workload.

No import-time effects. This file is source only until separately assembled and
admitted in the dedicated Native sandbox. Releases are operator input intent,
not Native authority, model proof or permission to bypass a current ACK.
"""
import argparse, json, os, stat, time
from pathlib import Path
from codex_driver import Refused, STEPS, unique, original_session

def gate_object(raw, run, actor, ordinal):
    v = unique(raw)
    expected = {'run': run, 'actor': actor, 'ordinal': ordinal, 'step': STEPS[actor][ordinal - 1]}
    if v != expected:
        raise Refused('original operator release mismatch')
    return v['step']

def read_release(path, run, actor, ordinal):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        a = os.fstat(fd)
        if (not stat.S_ISREG(a.st_mode) or a.st_uid != 0 or stat.S_IMODE(a.st_mode) != 0o444
                or a.st_nlink != 1 or a.st_size > 512):
            raise Refused('protected immutable release required')
        raw = os.read(fd, 513)
        b = os.fstat(fd)
        if (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns) != (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns) or len(raw) != a.st_size:
            raise Refused('release changed')
        return gate_object(raw, run, actor, ordinal)
    finally:
        os.close(fd)

def sequence(driver, run, actor, deadline, reader=read_release, clock=time.monotonic, pause=time.sleep, emit=None):
    ordinal = 1
    while clock() < deadline:
        if ordinal <= len(STEPS[actor]):
            step = reader(Path('/fixture/gates') / f'{actor}-{ordinal}.json', run, actor, ordinal)
            if step is not None:
                result = driver.step(step)
                row = {'record': 'm1_codex_client_outcome', 'actor': actor, 'step': step,
                       'ordinal': ordinal, 'client_status': result['status'],
                       'same_original_thread': result['same_original_thread'],
                       'native_proof': False, 'billed_usage_verified': False}
                if emit is not None:
                    emit(row)
                ordinal += 1
        # Retain the original process and original phase for the independent
        # Native current read. Never terminate early merely on client status.
        pause(min(.05, max(0, deadline - clock())))
    return ordinal - 1

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--actor', choices=('A', 'B'), required=True)
    p.add_argument('--nonce', required=True)
    p.add_argument('--deadline-unix-ms', type=int, required=True)
    args = p.parse_args()
    remaining = args.deadline_unix_ms / 1000 - time.time()
    if not 0 < remaining <= 300 or len(args.nonce) != 32 or any(c not in '0123456789abcdef' for c in args.nonce):
        raise Refused('closed original run and window')
    deadline = time.monotonic() + remaining
    reference = os.environ.get('OPENAI_API_KEY', '')
    with original_session(Path('/tmp') / f'm1-codex-{args.nonce}-{args.actor}', args.nonce, args.actor,
                          reference, '/opt/m1/native-ca.pem', seconds=remaining) as driver:
        sequence(driver, args.nonce, args.actor, deadline,
                 emit=lambda row: print(json.dumps(row, separators=(',', ':')), flush=True))

if __name__ == '__main__':
    try:
        main()
    except Exception:
        # No provider response/error/credential/reference/body in stdout/stderr.
        raise SystemExit('fixed Codex workload refused; no replay')
