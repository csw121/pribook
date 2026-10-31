# Security Evidence Validator 1.2.0

## 다른 Windows PC에서 사용하기

1. ZIP을 **압축 해제**합니다. ZIP 내부에서 바로 실행하지 마세요.
2. 해당 PC에 **Python 3.13 이상**과 **Ollama**를 설치합니다.
3. Ollama를 실행하고 `ollama pull qwen3.5:9b`로 모델을 한 번 설치합니다. 기존에 설치했다면 다시 받을 필요가 없습니다.
4. **`01_setup.cmd`를 더블클릭**합니다. 이 PC 전용 실행 환경·패키지·입력 폴더를 준비하고 Ollama를 확인합니다.
5. **`05_open_input.cmd`를 더블클릭**해서 열린 폴더에 TXT 파일 자체를 넣습니다.
6. **`02_analyze_txt.cmd`를 더블클릭**합니다. 분석이 끝나면 이번 결과를 브라우저로 엽니다.

나중에 결과만 다시 보려면 **`03_open_results.cmd`**, 실행 환경 확인은 **`04_check.cmd`**입니다.

`.venv`는 다른 PC에서 복사하지 않습니다. PC마다 `01_setup.cmd`로 만드세요. 이 ZIP에는 Python, Ollama 프로그램, 모델, 개인 자료가 들어 있지 않습니다. 설치·모델 다운로드에는 인터넷이 필요하고 자료 분석은 로컬 Ollama에서 실행합니다. 설정 파일은 `config/settings.json`입니다.

## 설치 파일이 없다고 나오면

Python: https://www.python.org/downloads/windows/

Ollama: https://ollama.com/download/windows

Python을 설치한 직후에는 열려 있는 창을 닫고 `01_setup.cmd`를 다시 실행하세요. Python 설치가 필요한 경우 출력되는 winget 명령도 사용할 수 있습니다. PowerShell 스크립트 활성화나 시스템 실행 정책 변경은 필요하지 않습니다.

## 다른 PC로 옮길 때

가장 쉬운 방법은 **배포 ZIP만 새 PC에 복사**하는 것입니다. 개인 자료를 옮길 필요가 있을 때만 `private/input_txt`의 필요한 TXT와 `output`의 결과를 별도로 직접 복사하세요. 실제 자료는 GitHub/이 채팅에 올리지 않습니다. 배포 ZIP은 개인 입력·분석 결과·venv를 제외합니다.

기존 PC 업데이트는 새 ZIP의 내용물을 `main.py`가 있는 기존 폴더에 덮어쓰면 됩니다. 입력·결과·실행 환경은 덮어쓰지 않습니다. 이후 `01_setup.cmd`로 패키지를 확인하세요. 기존 결과는 자동 재검증되거나 새 결과로 바뀌지 않습니다. HTML에는 생성 시각과 실행 ID를 표시합니다.

## 오류가 나면

- TXT가 없다는 메시지: `05_open_input.cmd`로 연 폴더에 **파일 자체**를 넣으세요. 하위 폴더는 읽지 않습니다.
- Ollama/모델 오류: Ollama를 실행하고 `ollama pull qwen3.5:9b` 후 다시 실행합니다.
- 메모리 부족·시간 초과: PowerShell에서 `./02_analyze_txt.cmd --context 4096`으로 실행합니다. RTX4060 8GB 노트북은 이 설정부터 확인할 수 있습니다. 두 PC의 실제 VRAM 적합성은 직접 확인해야 합니다.
- 인코딩 오류: `./02_analyze_txt.cmd --encoding cp949` 또는 `--encoding utf-16`을 사용합니다.
- 결과 창이 안 열림: `output/text_review.html` 파일을 직접 여세요. 경로에 공백·한글이 있어도 실행 파일은 전체 경로를 사용합니다.
- 분석이 실패하면 이번 결과를 자동으로 열지 않습니다. 예전 결과가 남을 수 있으니 오류를 먼저 해결하세요.

## 알아둘 점

결과는 **TXT 요약과 미검증 주장 정리**입니다. 인용 미확인 건수는 취약점 개수가 아닙니다. 원문 불일치 항목은 근거로 쓰지 마세요. 인용을 한 번 재요청하고, 계속 불일치하는 주장은 별도 표시합니다. `blocked`는 이 모드의 기본 상태이며 원본 HTTP 증거 검증이나 최종 보고서 승인을 의미하지 않습니다.

HWP 직접 읽기/생성은 미구현입니다. 현재 DOCX 분석은 문서 구조만 다룹니다.

파일당 2MB·최대 32파일·전체 64조각, context에 따라 최대 2500문자로 나눠 읽습니다. 민감 키 일부는 마스킹하지만 모든 개인정보를 탐지하지는 않습니다. 출력도 로컬 민감자료로 보관하세요.

[명령어와 HTTP 증거 검증](docs/REFERENCE.md) · [개발 및 배포 안내](docs/PORTABLE.md) · [검증 기록](docs/VALIDATION.md)
