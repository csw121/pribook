"""명시적인 소스 목록만 ZIP에 포함합니다. .git·venv·private·실행 결과는 제외합니다."""
import argparse
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
ROOT=Path(__file__).resolve().parents[1]
ALLOWED=('sev','tests','config','examples','integrations','docs','tools','README.md','main.py','requirements.txt','pyproject.toml','.gitignore')

def package(output):
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    with ZipFile(output,'w',ZIP_DEFLATED) as z:
        for name in ALLOWED:
            p=ROOT/name
            for child in sorted(p.rglob('*')) if p.is_dir() else [p]:
                if child.is_file() and not child.is_symlink() and '__pycache__' not in child.parts and child.suffix not in ('.pyc','.pyo'):
                    z.write(child,Path('Security-Evidence-Validator')/child.relative_to(ROOT))
    with ZipFile(output) as z:assert z.testzip() is None
    print('프로젝트 ZIP 생성 및 CRC 검증 완료')
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);package(parser.parse_args().output)
