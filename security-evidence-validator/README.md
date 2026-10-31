# Security Evidence Validator 1.1.1

## 1.1.0에서 업데이트

`Security-Evidence-Validator-update-1.1.1.zip`을 풀어 나온 `sev`, `docs`, `tests`, README 등의 파일을 기존 **main.py가 있는 폴더에 덮어쓰기**하면 됩니다. 실행 환경과 입력 TXT를 다시 만들 필요가 없습니다. 완료 메시지의 인용 미확인 건수와 결과의 별도 검토 항목을 확인하세요.

## 일반 보안 분석 TXT를 Qwen에게 읽히기

이 명령은 HTTP 형식이 아닌 동료의 분석 메모·설명문도 읽습니다. 기존 `analyze`는 HTTP 로그 전용이고, 일반 문서는 **`ai-text`**를 사용합니다. HWP는 이번 작업에서 사용하지 않습니다.

### 1. 설치 (새 폴더에서 처음 한 번)

`main.py`가 보이는 폴더에서 PowerShell을 엽니다. Python 3.13과 Ollama가 필요합니다.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

이미 이 폴더에 설치했다면 다시 만들 필요가 없습니다. Ollama 앱을 실행해 두고 모델이 없을 때만 내려받습니다.

```powershell
ollama list
ollama pull qwen3.5:9b
```

### 2. TXT 넣기

`main.py` 옆에 `private` 폴더를 만들고 그 안에 `input_txt` 폴더를 만드세요. 분석 자료의 TXT 사본을 `private\input_txt`에 넣습니다. 이 경로는 Git에서 제외합니다. 원본 자료는 PC에 보관하고 채팅에 올리지 마세요.

### 3. 분석 실행

```powershell
.\.venv\Scripts\python.exe main.py doctor
.\.venv\Scripts\python.exe main.py ai-text --input .\private\input_txt
notepad .\output\text_review.md
```

중간에 오류가 나오면 다음 명령으로 넘어가지 마세요. `doctor`는 Ollama 연결/모델 목록만 확인하고, `ai-text`가 실제 Qwen 추론을 요청합니다. 긴 파일은 나눠 읽으므로 시간이 걸립니다. 분석 중 조각 번호를 표시합니다.

한 파일만 지정할 수도 있습니다.

```powershell
.\.venv\Scripts\python.exe main.py ai-text --input ".\private\input_txt\분석자료.txt"
```

한글 인코딩 오류가 나면 같은 명령 끝에 `--encoding cp949`를 붙입니다. UTF-16 파일은 `--encoding utf-16`을 사용합니다. 기본은 UTF-8입니다. 폴더의 TXT 파일만 읽으며 하위 폴더는 읽지 않습니다.

### 4. 결과 확인

- `output/text_review.md`: 메모장으로 읽는 한국어 검토 결과.
- `output/text_review.json`: 파일별 지문·파일명·AI 결과·마스킹 후 원문 인용 위치.
- 결과는 **문서 요약/미검증 주장 정리**입니다. 인용 일치는 그 문장이 TXT에 존재한다는 뜻이며, 취약점 성공을 입증하지 않습니다.
- 이 결과로 기존 `verify`/`report`를 실행하지 마세요. HTTP 증거 검증 결과와 다른 형식이며 보고서 게이트는 항상 `blocked`입니다.
- 원본 HTTP 요청·응답과 정책이 나중에 확보되면 별도 증거 검증 흐름을 사용합니다.

기본 연결: `http://127.0.0.1:11434`, 모델 `qwen3.5:9b`, context 8192, temperature 0.2, Thinking OFF. `config/settings.json`에서 조정합니다. 인증 헤더·쿠키·일부 비밀번호/토큰 패턴을 보내기 전에 가리지만 모든 개인정보를 탐지하지는 않습니다. 결과 파일도 민감자료로 관리하세요.

파일당 2MB, 파일 32개, 전체 최대 64조각입니다. 한 조각은 context에 따라 최대 2500문자이며 경계에 걸친 문맥은 불완전할 수 있습니다. AI 요약·검토 의견은 자동 사실 검증되지 않습니다. 원문에 없는 인용이면 해당 조각을 한 번 더 요청합니다. 재요청에도 원문과 다르거나 주장이 사라지면 원문 불일치 주장으로 분리해 저장하고 다음 조각을 분석합니다. 원문과 일치한 인용만 문서 인용에 포함되며, 틀린 인용을 수정하거나 유사 문자열로 통과시키지 않습니다. 잘못된 JSON·스키마·Ollama 연결 오류는 여전히 실행을 중단합니다. 실패 시 이전 실행 결과가 남을 수 있으니 새 완료 메시지와 결과 실행 ID를 확인하세요.

[HTTP 증거 검증과 기타 기능](docs/REFERENCE.md) · [검증 기록](docs/VALIDATION.md) · [DOCX/한글 처리](docs/DOCUMENTS.md)
