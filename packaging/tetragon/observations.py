#!/usr/bin/env python3
"""Explicit opt-in observation policy command. No arguments make no changes."""

import argparse
import signal
import sys


def main(argv=None):
    if sys.version_info < (3, 9):
        print("관측 정책 설치에 Python 3.9 이상이 필요합니다.", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(description="고정 monitor-only 관측 정책을 적용하고 실제 이벤트를 검증합니다.")
    parser.add_argument("--apply", action="store_true", help="인라인 옵션·파일 쓰기·TCP 시작 관측을 명시적으로 적용")
    parser.add_argument("--file-prefix", action="append", metavar="ABSOLUTE/DIR/", help="파일 관측 디렉터리 접두사; 반복 가능, /tmp/ 포함 필수")
    args = parser.parse_args(argv)
    if not args.apply:
        parser.print_help()
        return 0
    try:
        from observation_workflow import run_observations
        from setup_common import SetupError
    except ImportError:
        print("관측 정책 설치에 Python 3.9 이상과 PyYAML이 필요합니다.", file=sys.stderr)
        return 1
    previous = {}

    def interrupted(number, frame):
        raise KeyboardInterrupt

    try:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[number] = signal.signal(number, interrupted)
        document = run_observations(args.file_prefix, announce=True)
    except SetupError as error:
        print("관측 정책 적용 실패: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("관측 정책 적용을 중단하고 이전 상태로 복구했습니다.", file=sys.stderr)
        return 130
    except Exception:
        print("관측 정책 적용 실패: root 전용 진단 백업과 서비스 상태를 확인하십시오.", file=sys.stderr)
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    print("monitor-only 관측 정책의 Tetragon 센서 이벤트와 에이전트의 기능별 실제 수신을 각각 확인했습니다.")
    print("탐지 대상 필터에 따른 이력 보존과 중앙 전달은 별도 확인이 필요합니다.")
    if len(document["verified_runtime_policies"]) < 9 or "ipv6" not in document["verified_network_families"]:
        print("일부 런타임 또는 IPv6는 미설치·미검증 상태입니다. 소유권 메타데이터에서 범위를 확인하십시오.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
