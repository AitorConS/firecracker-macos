#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real HVF inherited-capability regression, including FDs above lowered limits."""
import argparse
import json
import os
from pathlib import Path
import resource
import re
import socket
import subprocess
import tempfile
import time
from test_control import BINARY, api, elf


def state(sock, expected):
    deadline = time.monotonic() + 5
    while True:
        value = api(sock, 'GET', '/')[1]
        if value['state'] == expected:
            return value
        assert value['state'] != 'Failed' and time.monotonic() < deadline, value
        time.sleep(.02)


def scenario(binary, output, high):
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix='hvf-fd-') as temporary:
        work = Path(temporary).resolve()
        runtime = work / 'tmp'
        runtime.mkdir()
        kernel = work / 'kernel'
        kernel.write_bytes(elf())
        disk = work / 'selected-disk'
        disk.write_bytes(bytes(4096))
        paths = [work / 'ambient-file', work / 'ambient-socket']
        paths[0].write_text('HVF_AMBIENT_FD_CANARY')
        sock = work / 'api'
        with paths[0].open('r') as file, socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel, (output / 'supervisor.log').open('w') as log:
            channel.bind(str(paths[1]))
            inherited = [file.fileno(), channel.fileno()]
            extra = []
            if high:
                for source, target in zip(inherited, [8192, 8193]):
                    os.dup2(source, target)
                    extra.append(target)
                inherited += extra
            def lower_limit():
                resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
            try:
                process = subprocess.Popen(
                    [str(binary), '--api-sock', str(sock)], pass_fds=inherited,
                    preexec_fn=lower_limit if high else None,
                    stdout=log, stderr=log, env={**os.environ, 'TMPDIR': str(runtime)})
            finally:
                for fd in extra:
                    os.close(fd)
            try:
                deadline = time.monotonic() + 5
                while not sock.exists():
                    assert process.poll() is None and time.monotonic() < deadline
                    time.sleep(.02)
                for endpoint, value in [
                    ('/boot-source', {'kernel_image_path': str(kernel)}),
                    ('/drives/d', {'drive_id': 'd', 'path_on_host': str(disk)}),
                    ('/network-interfaces', [{'iface_id': 'n', 'backend': 'slirp', 'guest_mac': '02:00:00:00:00:01'}]),
                ]:
                    reply = api(sock, 'PUT', endpoint, value)
                    assert reply[0] == 204, reply
                assert api(sock, 'PUT', '/actions', {'action_type': 'InstanceStart'})[0] == 202
                state(sock, 'Running')
                rows = [list(map(int, line.split())) for line in subprocess.check_output(['ps', '-axo', 'pid=,ppid='], text=True).splitlines()]
                pids = [process.pid]
                for _ in range(3):
                    pids += [pid for pid, parent in rows if parent in pids and pid not in pids]
                assert len(pids) == 4, pids
                results = []
                for pid in pids:
                    listing = subprocess.run(['/usr/sbin/lsof', '-nP', '-p', str(pid)], capture_output=True, text=True)
                    (output / f'fd-{pid}.log').write_text(listing.stdout + listing.stderr)
                    assert listing.returncode == 0, listing.stderr
                    if high and pid == process.pid:
                        assert all(re.search(r'\s' + str(fd) + r'[a-z]*\s', listing.stdout) for fd in [8192, 8193]), 'high FD positive controls absent'
                    results.append({'pid': pid, 'ambient': [str(path) in listing.stdout for path in paths], 'selected_disk': str(disk) in listing.stdout})
                assert all(results[0]['ambient']), 'supervisor positive controls absent'
                assert results[1]['selected_disk'], 'selected disk capability missing in VMM'
                assert all(not row['selected_disk'] for row in results[2:]), 'selected disk leaked to broker/authority'
                # Control and telemetry channels must survive the capability revocation.
                deadline = time.monotonic() + 3
                while True:
                    metrics = api(sock, 'GET', '/metrics')[1]
                    if 'vcpu_0_exits_total' in metrics:
                        break
                    assert time.monotonic() < deadline, metrics
                    time.sleep(.02)
                for action, expected in [('Pause', 'Paused'), ('Resume', 'Running'), ('ForceStop', 'Exited')]:
                    assert api(sock, 'PUT', '/actions', {'action_type': action})[0] == 202
                    state(sock, expected)
                result = {'high_fds': high, 'launcher_hard_limit': 4096 if high else None,
                          'processes': results, 'ambient_leaked': any(any(row['ambient']) for row in results[1:]),
                          'disk_control_metrics_passed': True}
                (output / 'results.json').write_text(json.dumps(result, indent=2))
                return result
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                assert not list(runtime.iterdir()), list(runtime.iterdir())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=BINARY)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expect-leak', action='store_true', help='Require the old failure in both control cases')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = [scenario(args.binary.resolve(), args.output / name, high) for name, high in [('ordinary', False), ('above-lowered-limit', True)]]
    (args.output / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
    assert all(row['ambient_leaked'] == args.expect_leak for row in results), 'inherited capability invariant failed'


if __name__ == '__main__':
    main()
