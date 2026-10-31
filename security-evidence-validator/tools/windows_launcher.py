"""stdlib-only entry point: can run before project dependencies are installed."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import venv

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = os.name == 'nt'


def environment_python():
    return ROOT / '.venv' / ('Scripts/python.exe' if WINDOWS else 'bin/python')


def run(arguments, quiet=False):
    try:
        result = subprocess.run([str(x) for x in arguments], cwd=ROOT, check=False,
                                stdout=subprocess.DEVNULL if quiet else None,
                                stderr=subprocess.DEVNULL if quiet else None)
        return result.returncode
    except OSError:
        print('프로세스를 실행하지 못했습니다. 01_setup.cmd를 다시 실행하세요.')
        return 2


def folders():
    (ROOT / 'private' / 'input_txt').mkdir(parents=True, exist_ok=True)
    (ROOT / 'output').mkdir(parents=True, exist_ok=True)


def usable_python(python):
    return python.is_file() and run([python, '-c', 'import sys; raise SystemExit(sys.version_info < (3,13))'], quiet=True) == 0


def require_environment():
    python = environment_python()
    if not usable_python(python):
        print('이 PC의 실행 환경이 없습니다. 먼저 01_setup.cmd를 실행하세요.')
        return None
    if run([python, '-c', 'import jsonschema'], quiet=True) != 0:
        print('필요한 패키지가 없습니다. 01_setup.cmd를 실행하세요.')
        return None
    return python


def model_help():
    print('Ollama 앱을 실행하고 qwen3.5:9b 모델을 준비하세요.')
    print('설치: https://ollama.com/download/windows')
    print('모델 설치 명령: ollama pull qwen3.5:9b')
    print('메모리 부족/시간 초과는 config/settings.json의 num_ctx를 4096으로 낮춰 확인하세요.')


def setup():
    if sys.version_info < (3, 13):
        print('Python 3.13 이상이 필요합니다: https://www.python.org/downloads/windows/')
        return 2
    python = environment_python()
    if not usable_python(python):
        if python.exists():
            print('기존 .venv가 이 PC에서 작동하지 않습니다. .venv 폴더를 다른 이름으로 보관한 뒤 01_setup.cmd를 다시 실행하세요.')
            return 2
        try:
            print('이 PC 전용 Python 실행 환경을 만드는 중입니다.')
            venv.EnvBuilder(with_pip=True).create(ROOT / '.venv')
        except (OSError, subprocess.SubprocessError):
            print('실행 환경 생성 실패. Python 설치 상태와 압축을 푼 폴더의 쓰기 권한을 확인하세요.')
            return 2
    if run([python, '-m', 'pip', '--version'], quiet=True) != 0:
        if run([python, '-m', 'ensurepip', '--upgrade']) != 0:
            print('pip 준비 실패. Python 설치를 복구한 뒤 다시 실행하세요.')
            return 2
    print('필요한 패키지를 설치합니다. 이 단계에는 인터넷이 필요합니다.')
    if run([python, '-m', 'pip', '--disable-pip-version-check', 'install', '-r', ROOT / 'requirements.txt']) != 0:
        print('패키지 설치 실패. 인터넷 연결과 앞의 오류를 확인하세요. 분석은 시작하지 않았습니다.')
        return 2
    folders()
    print('Python 실행 환경과 입력 폴더 준비 완료.')
    return check(python)


def check(python=None):
    python = python or require_environment()
    if python is None:
        return 2
    code = run([python, ROOT / 'main.py', 'doctor'])
    if code != 0:
        model_help()
        return code
    print('준비 확인 완료. private/input_txt에 TXT를 넣고 02_analyze_txt.cmd를 실행하세요.')
    return 0


def open_file(path):
    try:
        if WINDOWS:
            os.startfile(str(path.resolve()))
        else:
            print('파일 위치: ' + str(path.resolve()))
        return 0
    except OSError:
        print('파일 자동 열기 실패. 탐색기에서 다음 전체 경로를 여세요: ' + str(path.resolve()))
        return 2


def open_results():
    # Prefer HTML: no Notepad command parsing or relative path ambiguity.
    for name in ('text_review.html', 'text_review.md'):
        path = ROOT / 'output' / name
        if path.is_file():
            return open_file(path)
    print('분석 결과가 없습니다. TXT를 넣고 02_analyze_txt.cmd를 먼저 실행하세요.')
    return 2


def analyze(args):
    python = require_environment()
    if python is None:
        return 2
    folders()
    source = Path(args.input) if args.input else ROOT / 'private' / 'input_txt'
    if not source.is_absolute():
        source = ROOT / source
    if source.is_dir() and not any(p.is_file() and p.suffix.lower() == '.txt' for p in source.iterdir()):
        print('입력 폴더에 TXT 파일이 없습니다. 열린 폴더에 TXT 파일 자체를 복사하고 다시 실행하세요.')
        open_file(source)
        return 2
    if check(python) != 0:
        return 2
    command = [python, ROOT / 'main.py', 'ai-text', '--input', source, '--encoding', args.encoding]
    if args.context is not None:
        command += ['--context', str(args.context)]
    code = run(command)
    if code != 0:
        print('이번 분석에 실패했습니다. 이전 결과는 자동으로 열지 않습니다.')
        return code
    print('이번 분석이 완료되었습니다. 결과를 엽니다. 원문 불일치 항목은 증거로 사용하지 마세요.')
    return open_results()


def main(argv=None):
    parser = argparse.ArgumentParser(description='다른 PC에서 설치·실행하는 Windows 도우미')
    parser.add_argument('action', choices=['setup', 'check', 'analyze', 'results', 'input', 'test'])
    parser.add_argument('--input')
    parser.add_argument('--encoding', choices=['utf-8-sig', 'cp949', 'utf-16'], default='utf-8-sig')
    parser.add_argument('--context', type=int, choices=[4096,8192,16384])
    args = parser.parse_args(argv)
    try:
        if args.action == 'setup':
            return setup()
        if args.action == 'check':
            return check()
        if args.action == 'analyze':
            return analyze(args)
        if args.action == 'results':
            return open_results()
        if args.action == 'input':
            folders()
            return open_file(ROOT / 'private' / 'input_txt')
        python = require_environment()
        return run([python, '-m', 'unittest', 'discover', '-s', ROOT / 'tests', '-v']) if python else 2
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError):
        print('폴더 또는 파일을 사용할 수 없습니다. 쓰기 권한과 경로를 확인하세요.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
