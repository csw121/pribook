# 배포와 재현

## 구조

루트의 01_setup.cmd / 02_analyze_txt.cmd / 03_open_results.cmd / 04_check.cmd / 05_open_input.cmd가 공통 windows.cmd를 호출합니다. 공통 실행 파일은 Python 3.13 이상을 가진 .venv, py -3, python 순서로 실행기를 찾고 프로젝트 위치를 작업 디렉터리로 사용합니다. stdlib 전용 tools/windows_launcher.py가 의존성 설치 전에도 시작할 수 있습니다.

setup은 PC 전용 venv를 만들고 필요한 경우 ensurepip, 이어서 고정된 requirements를 설치합니다. 이미 정상 작동하는 venv는 지우지 않습니다. 복사한 venv가 작동하지 않으면 자동 삭제하지 않고 보관/재생성을 안내합니다. TLS 검증을 끄거나 시스템 실행 정책을 변경하지 않습니다. Python/Ollama 자체는 설치하지 않고 공식 설치 경로를 안내합니다.

analyze는 환경과 모델을 확인하고, TXT가 비었으면 입력 폴더를 엽니다. 기본 입력은 프로젝트/private/input_txt입니다. 성공한 이번 실행의 HTML만 자동으로 열고, 실패하면 예전 결과는 자동으로 열지 않습니다. 결과 보기 버튼은 마지막 저장 결과를 여는 기능이며 생성 시각/실행 ID를 확인해야 합니다. HTML은 모든 문서/AI 텍스트를 escape하고 외부 자원을 사용하지 않습니다.

## CLI

```powershell
.\windows.cmd check
.\windows.cmd analyze --encoding cp949 --context 4096
.\windows.cmd test
```

Python만 직접 실행할 수도 있습니다.

```powershell
.\.venv\Scripts\python.exe main.py ai-text --input .\private\input_txt --context 4096
```

--output/--markdown/--html로 JSON/Markdown/HTML 저장 위치를 각각 지정합니다. 일반 TXT 결과로 verify/report를 실행하지 않습니다. 원본 HTTP 증거 워크플로는 REFERENCE.md를 참고합니다.

## 패키지 빌드

```powershell
.\.venv\Scripts\python.exe tools/package_project.py --output delivery/Security-Evidence-Validator-1.2.0.zip
```

허용된 소스/설정/설명/테스트/실행 파일만 포함합니다. private, output, .venv, .git, 이전 delivery ZIP은 포함하지 않습니다. requirements-lock.txt는 검증 시점의 전이 의존성 버전을 고정합니다. Python 설치 파일/모델/Windows 휠은 배포에 포함하지 않으므로 새 PC의 첫 설치는 인터넷이 필요합니다. 완전 오프라인 설치 및 EXE 단독 배포는 제공하지 않습니다.

## 실제 PC에서 확인할 사항

이 클라우드에는 Windows cmd.exe가 없어 .cmd 더블클릭을 실행하지 못했습니다. Python 설치/실행/경로·실패 처리 로직은 자동 테스트하고, 패키지를 공백·한글 경로로 풀어 실행 흐름을 확인합니다. 실제 Windows 셸, 브라우저 파일 연결, 실제 Qwen 추론, 두 GPU 메모리 적합성은 PC에서 추가 확인해야 합니다.

학교 PC와 노트북에서 먼저 가상 examples/synthetic_security_notes.txt를 private/input_txt에 복사해 소규모 추론을 확인한 뒤 실제 자료를 사용하세요. 비공개 원본은 클라우드에 보내지 않습니다.
