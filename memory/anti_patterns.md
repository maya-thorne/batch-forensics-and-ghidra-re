# 🚫 Worker 3 중복 방지 규칙 (Anti-Patterns)

1. **난독화 생성 및 이론 백서 중복 금지**:
   - `batch-forensics-and-ghidra-re`는 순수 블루팀 탐지/포렌식 전담이므로, 공격용 난독화 생성 기법이나 역사적 백서를 나열하지 않는다. (해당 내용은 Worker 1의 `batch-obfuscation-research`에 위임)

2. **엔드유저 CLI 탈난독화 툴체인 중복 금지**:
   - 사용자가 스크립트를 넣고 푸는 상용 수준의 탈난독화 CLI 툴을 구현하지 않는다. (해당 기능은 Worker 2의 `batch-deobfuscator-re`에 위임)

3. **Ghidra 바이너리 언패킹 중복 금지**:
   - Ghidra 역공학이나 PE 스터브 분석을 메인 기능으로 내세우지 않는다. (해당 기능은 Worker 5의 `bat2exe-ghidra-forensics`에 위임)

4. **AST 컴파일러 파서 중복 금지**:
   - 오토마타 기반 AST 구문 트리 파서를 구현하지 않는다. (해당 기능은 Worker 4의 `cmd-ast-deobfuscator`에 위임)
