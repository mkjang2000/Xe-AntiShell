#!/usr/bin/env python3
"""Opt-in pinned standalone Tetragon setup; never executes upstream install.sh."""

import argparse
import signal
import sys


def main(argv=None):
    if sys.version_info < (3, 9):
        print("Tetragon 설치에 Python 3.9 이상이 필요합니다.", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(description="검증된 Tetragon을 설치하고 실제 수집 후 전환합니다.")
    parser.add_argument("--archive", metavar="PATH", help="고정 SHA256으로 검증할 오프라인 릴리스 archive")
    args = parser.parse_args(argv)
    try:
        from artifacts import ArtifactError
        from setup_common import SetupError
        from setup_workflow import run_setup
    except ImportError:
        print("Tetragon 설치에 Python 3.9 이상과 PyYAML이 필요합니다.", file=sys.stderr)
        return 1
    previous = {}

    def interrupted(number, frame):
        raise KeyboardInterrupt

    try:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[number] = signal.signal(number, interrupted)
        run_setup(args.archive)
    except (SetupError, ArtifactError) as error:
        print("Tetragon 설치 실패: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Tetragon 설치를 중단하고 이전 설정으로 복구했습니다.", file=sys.stderr)
        return 130
    except Exception:
        print("Tetragon 설치 실패: 이전 설정 복구를 시도했습니다. root 전용 진단 백업을 확인하십시오.", file=sys.stderr)
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    print("Tetragon 실제 실행 이벤트와 에이전트 수집을 확인했습니다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
