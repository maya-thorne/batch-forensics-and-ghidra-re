# 📋 Worker 3 액티브 태스크 체크리스트 (batch-forensics-and-ghidra-re)

## 📌 6대 필수 품질 과업 및 블루팀 탐지 엔지니어링 완수 현황

- [x] **1. 실제 깃허브 웹페이지 접속 및 인간 관점 UI/UX 실측 검증**:
  - Chrome CDP(포트 9227) 격리 탭으로 `https://github.com/maya-thorne/batch-forensics-and-ghidra-re` 접속.
  - 블루팀 탐지 룰셋 구조, YARA 32종/Sigma 52종 룰 목록, 엔트로피 알고리즘, 배너 가독성 실측 완료.
  - 모든 이미지는 클릭 시 raw 미디어 뷰어로 튕기지 않도록 `<a href="...">` 래핑 유지.

- [x] **2. 10개국어 다국어 네비게이션 및 시각 자료 현지화**:
  - 10개국어 문서(`docs/locales/*.md`) 링크 100% 정상 작동 검증.
  - Sigma/YARA 룰셋 구조도, MITRE ATT&CK 프레임워크 맵핑, 엔트로피 분석 흐름도의 레이블 현지화 완비.

- [x] **3. 시각적 에셋(탐지 아키텍처 다이어그램 / 이상치 차트 SVG) 고도화**:
  - EDR/SIEM 파이프라인(로그 수집 ➔ 정규화 ➔ Sigma/YARA 매칭 ➔ 경보 발령) 고해상도 SVG (`assets/detection_pipeline.svg`) 탑재.
  - 섀넌 엔트로피 및 비정상 캐럿 밀도 스코어링 모듈 (`src/entropy_detector.py`) 및 애니메이션 터미널 데모 SVG 완비.

- [x] **4. GitHub 공식 Release 및 Git Tag (`v1.0.0` / `v1.1.0`) 발행**:
  - Git Tag 생성 및 원격 푸시 완료.
  - EDR/SOC 탐지 룰셋 패키지(52 Sigma / 32 YARA), 테스트 벡터 검증 결과, 릴리즈 노트 등록 완료.

- [x] **5. 라이선스(LICENSE) 규격화 및 오픈소스 크레딧**:
  - 공식 LICENSE (MIT License) 완비 및 관제 룰셋 활용 시 방어 연구 면책 조항 명시.

- [x] **6. 전역 규칙 준수 (AI 도구명/워터마크 0건)**:
  - 룰셋 파일, 코드, 주석, 문서 어디에도 AI 도구명이나 워터마크가 들어가지 않도록 전수 감사 완료 (`Engineered & Audited by Maya Thorne`).

---

## 🎯 도메인 특화 핵심 산출물 현황
1. **52 Modular Sigma Rules** (`rules/sigma/`):
   - 24 Defense Evasion (`rules/sigma/defense_evasion/`)
   - 12 Execution (`rules/sigma/execution/`)
   - 10 Discovery (`rules/sigma/discovery/`)
   - 6 Persistence (`rules/sigma/persistence/`)
2. **32 Modular YARA Rules** (`rules/yara/`):
   - 12 Obfuscator Signatures (`rules/yara/obfuscators/`)
   - 10 PE Container Packers (`rules/yara/packers/`)
   - 10 Anomaly Heuristics (`rules/yara/heuristics/`)
3. **SIEM Query Feeds** (`rules/siem_queries/`):
   - `splunk_queries.spl` (Splunk SPL Production Searches)
   - `elastic_kql_queries.kql` (Elasticsearch KQL Production Alerts)
4. **MITRE ATT&CK Enterprise Matrix** (`docs/MITRE_ATTACK_DEFENSE_MATRIX.md`):
   - 15종 핵심 TTP와 52 Sigma / 32 YARA 매핑 테이블.
5. **Statistical Anomaly Scorer** (`src/entropy_detector.py`):
   - 섀넌 엔트로피, 캐럿 밀도, 구분자 편향도 통합 스코어링 (단위 테스트 100% 통과).

---

## 🔍 피드백 리팩토링 & 키워드 기억 리트리벌 (Memory Recall Protocol)
> **[전담 피드백 체크리스트]**: `memory/feedback_audit.md` (상위: `_BY_PASSS/WORKER_FEEDBACK_GUIDE.md`)
> **[기억 소환 키워드]**: 프롬프트나 태스크에서 아래 키워드가 언급되면 즉시 해당 규칙을 엄격히 소환하여 실행합니다:
- **`@clean-root`**: 루트 항목을 6~7개로 극도 슬림화 (백서는 `docs/whitepapers/`, 레퍼런스는 `references/`로 이동하여 첫 뷰포트 배너 노출 보장).
- **`@english-naming`**: 한글 폴더/파일명 전면 금지, 100% 영문 표준 네이밍 치환.
- **`@semantic-commit`**: 일괄 커밋 도배 금지, 파일/모듈별 개별 맥락 커밋 메시지 적용.
- **`@security-audit`**: `.env`, 캐시, 불필요 바이너리 등 배제 및 클린 커밋 검증.
- **`@custom-license`**: Maya Thorne 전용 연구 라이선스(MT-SRL) 적용.
- **`@feedback`**: 사용자 3대 시각 피드백 종합 반영 체크리스트 완수.
