#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Repeat real HVF start/force-stop with private synthetic guest fixtures."""
import argparse
import json
import os
import time
from test_control import ControlTests, api


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cycles', type=int, default=100)
    parser.add_argument('--output', required=True)
    parser.add_argument('--network', action='store_true', help='Include a network broker in every cycle')
    args = parser.parse_args()
    if not 1 <= args.cycles <= 10000:
        parser.error('cycles must be 1..10000')
    case = ControlTests()
    result = {'requested': args.cycles, 'completed': 0, 'passed': False, 'network': args.network}
    begin = time.monotonic()
    try:
        case.setUp()
        try:
            if args.network:
                case.put('/network-interfaces',[{'iface_id':'n','guest_mac':'02:00:00:00:00:01','backend':'slirp'}])
            for _ in range(args.cycles):
                case.start()
                broker = case.broker() if args.network else None
                case.assertEqual(api(case.sock, 'PUT', '/actions', {'action_type': 'ForceStop'})[0], 202)
                state = case.wait_state('Exited')
                operation = api(case.sock, 'GET', f"/operations/{state['operation_id']}")[1]
                case.assertEqual(operation['status'], 'succeeded')
                if broker:
                    deadline = time.monotonic() + 2
                    while True:
                        try:
                            os.kill(broker, 0)
                        except ProcessLookupError:
                            break
                        case.assertLess(time.monotonic(), deadline, 'orphan network broker')
                        time.sleep(.01)
                result['completed'] += 1
            result['passed'] = True
        finally:
            case.tearDown()
    finally:
        result['elapsed_seconds'] = time.monotonic() - begin
        with open(args.output, 'w') as output:
            json.dump(result, output, indent=2)
            output.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
