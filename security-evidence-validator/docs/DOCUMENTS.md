# 한글 문서의 로컬 분석

HWP 원본을 Work에 업로드하지 않습니다. 학교 PC 한컴오피스에서 원본을 보존하고 **다른 이름으로 저장 → DOCX** 사본을 만드세요. 표 병합·글꼴·이미지·페이지 나눔이 유지되는지 로컬에서 확인합니다. PDF 사본도 보관 가능하지만 이 도구의 분석 입력은 DOCX만 지원합니다.

```powershell
python main.py document-analyze --input private/report.docx --output private/structure.json
```

제목 스타일/반복 수, 표별 행/셀 수, 이미지 수 및 inline/anchor 개수를 분석합니다. 기본 제목 텍스트는 가립니다. `--include-local-text`는 제목 원문을 로컬 결과에 남기므로 공유하지 마세요. 외부 관계/이미지를 내려받지 않습니다. 실제 페이지 좌표·이미지 내용·복잡한 병합 논리·사용자 지정 제목 스타일 추론·특정 대회 양식 복제는 지원하지 않습니다.

생성한 DOCX는 간단한 OOXML 문서입니다. ZIP/XML 왕복만 테스트했으며 한글/Word 열기·편집·HWP 저장은 실제 PC에서 확인해야 합니다. HWP 직접 읽기/생성, PDF 파싱, COM 자동화는 미구현입니다. 구조 JSON을 참고해 로컬 템플릿을 정리할 수 있으나 비공개 양식을 자동 복제하거나 동일하다고 주장하지 않습니다.
