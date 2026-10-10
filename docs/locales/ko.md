<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <strong>🇰🇷 한국어</strong> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <a href="https://github.com/maya-thorne/batch-forensics-and-ghidra-re"><img src="../assets/locales/ko/banner.svg" alt="batch-forensics-and-ghidra-re banner" width="100%" /></a>
</p>

# 🛡️ batch-forensics-and-ghidra-re

**3계층 포렌식 분해, 파서 시뮬레이션 및 방어 탐지 프레임워크**

[![Release](https://img.shields.io/github/v/release/maya-thorne/batch-forensics-and-ghidra-re?color=10b981)](https://github.com/maya-thorne/batch-forensics-and-ghidra-re/releases/latest)
[![Ghidra MCP](https://img.shields.io/badge/Ghidra_MCP-Binary_RE-10b981.svg)](../01_DEEP_REVERSE_ENGINEERING_AND_SOURCE_ANALYSIS.md)
[![Parser](https://img.shields.io/badge/cmd.exe-5--Stage_Parser-38bdf8.svg)](../../src/cmd_parser_simulator.py)
[![References](https://img.shields.io/badge/References-41_Mirrors-818cf8.svg)](../../references)
[![Tests](https://img.shields.io/badge/Tests-100%25_Passing-10b981.svg)](../../tests)
[![Rules](https://img.shields.io/badge/Rules-Sigma_%26_YARA-f59e0b.svg)](../../rules)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

<sub>Engineered &amp; Audited by **[Maya Thorne](https://github.com/maya-thorne)** · Systems &amp; Reverse Engineering Research</sub>

</div>

---

## 🎨 batch-forensics-and-ghidra-re : 파이프라인 아키텍처 (Local Architecture Diagram)

<p align="center">
  <a href="https://github.com/maya-thorne/batch-forensics-and-ghidra-re"><img src="../assets/locales/ko/architecture.svg" alt="architecture diagram" width="100%" /></a>
</p>

---

## 💻 Interactive Terminal Demonstration Asset

<p align="center">
  <a href="https://github.com/maya-thorne/batch-forensics-and-ghidra-re"><img src="../assets/demo_parser_terminal.svg" alt="Terminal Demo" width="100%" /></a>
</p>

---

## 📚 Master Technical Documentation

1. 🔬 **[01_DEEP_REVERSE_ENGINEERING_AND_SOURCE_ANALYSIS.md](../01_DEEP_REVERSE_ENGINEERING_AND_SOURCE_ANALYSIS.md)**
   - **Ghidra MCP PE Binary Reverse Engineering**:
     - `bat2exe_12.exe` (UPX Native Stub `0x20ea0`)
     - `BEDeCode.exe` (VB6 Native `ThunRTMain` `0x1670` & `CHRMAPSET`)
     - `example.exe` (.NET CLR `0x337e` `_CorExeMain` & `"batch_cmd"`)
     - `example_bytepressed.exe` (LZMA RangeCoder Decompressor Stub `0x2077`)
   - **5 Core Tools Source Code Dissection**:
     - `Invoke-DOSfuscation` (PowerShell Environment Slicing)
     - `SomalifuscatorV2` (Python Dynamic Caesar Cipher)
     - `batch_deobfuscator` (Static Pushdown Automaton AST)
     - `Exorcism` (`cmd.exe!FindFixAndRun` API Hook Engine)
     - `0xidiz3r` (Rust Zero-Literal Bootstrapping)
2. 📖 **[02_CLASSIC_TO_MODERN_EVOLUTION_1990_2026.md](../02_CLASSIC_TO_MODERN_EVOLUTION_1990_2026.md)**
   - 30-Year Evolution from MS-DOS ASCII techniques to 2026 AI/LLM Deobfuscation models.
3. 🛡️ **[03_BATCLOAK_MULTI_STAGE_LOADER_FORENSICS.md](../03_BATCLOAK_MULTI_STAGE_LOADER_FORENSICS.md)**
   - Multi-Stage forensic analysis of BatCloak / ScrubCrypt obfuscated loaders and EDR telemetry.
4. 📑 **[04_BATCH_OBFUSCATION_ENCYCLOPEDIA.md](../04_BATCH_OBFUSCATION_ENCYCLOPEDIA.md)** & **[05_BATCH_OBFUSCATION_MASTER_GUIDE.md](../05_BATCH_OBFUSCATION_MASTER_GUIDE.md)**
   - Theoretical taxonomy and comprehensive detection framework.

---

## 📁 Repository Directory Structure

- 📁 [`docs/assets/`](../assets) &mdash; Localized SVG hero banners, architecture schematics, and interactive terminal demo SVG.
- 📁 [`docs/`](../../docs) &mdash; Unabridged reverse engineering whitepapers and localized documentation.
- 📁 [`references/`](../../references) &mdash; 41 clean flattened open-source mirrors (zero nested `.git` and zero binaries).
- 📁 [`rules/`](../../rules) &mdash; Production Sigma and YARA defensive rulesets.
- 📁 [`samples/parser-test-vectors/`](../../samples/parser-test-vectors) &mdash; 6 benign educational test vectors.
- 📁 [`src/`](../../src) &mdash; Python `cmd_parser_simulator.py` (5-stage deterministic AST deobfuscator).
- 📁 [`tests/`](../../tests) &mdash; Automated unit test suite (100% passing).
