"""허용한 소스/설치 파일만 배포. 개인 입력·결과·실행 환경은 포함하지 않습니다."""
import argparse
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = ('sev', 'tests', 'config', 'examples', 'integrations', 'docs', 'tools',
           'README.md', 'START_HERE.txt', 'main.py', 'requirements.txt',
           'requirements-lock.txt', 'pyproject.toml', '.gitignore', '.gitattributes', 'windows.cmd',
           '01_setup.cmd', '02_analyze_txt.cmd', '03_open_results.cmd',
           '04_check.cmd', '05_open_input.cmd')
EXCLUDED_PARTS = {'.git', '.venv', 'private', 'output', 'delivery', '__pycache__'}


def package(output):
    root = ROOT.resolve()
    output = Path(output).resolve()
    for name in ALLOWED:
        path = root / name
        if not path.exists() or path.is_symlink():
            raise ValueError('필수 배포 파일이 없거나 링크입니다: ' + name)
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, 'w', ZIP_DEFLATED) as archive:
        for name in ALLOWED:
            path = root / name
            for child in sorted(path.rglob('*')) if path.is_dir() else [path]:
                relative = child.relative_to(root)
                if (not child.is_file() or child.is_symlink()
                        or any(part in EXCLUDED_PARTS for part in relative.parts)
                        or child.suffix in ('.pyc', '.pyo') or child.name == '.env'
                        or not child.resolve().is_relative_to(root)
                        or child.resolve() == output):
                    continue
                archive.write(child, Path('Security-Evidence-Validator') / relative)
    with ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError('배포 ZIP 무결성 검사 실패')
    print('프로젝트 ZIP 생성 및 CRC 검증 완료')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    package(parser.parse_args().output)
