<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <strong>🇧🇷 Português</strong> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <a href="https://github.com/maya-thorne/batch-forensics-and-ghidra-re"><img src="../../assets/locales/pt-BR/banner.svg" alt="batch-forensics-and-ghidra-re banner" width="100%" /></a>
</p>

# 🛡️ batch-forensics-and-ghidra-re

**Forense de Arquivos Batch, Internos do CMD e Engenharia Reversa Binária**

[![Ghidra MCP](https://img.shields.io/badge/Ghidra_MCP-Binary_RE-10b981.svg)](../01_DEEP_REVERSE_ENGINEERING_AND_SOURCE_ANALYSIS.md)
[![Parser](https://img.shields.io/badge/cmd.exe-5--Stage_Parser-38bdf8.svg)](../../src/cmd_parser_simulator.py)
[![References](https://img.shields.io/badge/References-41_Mirrors-818cf8.svg)](../../references)
[![Tests](https://img.shields.io/badge/Tests-100%25_Passing-10b981.svg)](../../tests)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

<sub>Engineered &amp; Audited by **[Maya Thorne](https://github.com/maya-thorne)** · Systems &amp; Reverse Engineering Research</sub>

</div>

---

## 📚 Master Technical Documentation

1. 🔬 **[01_DEEP_REVERSE_ENGINEERING_AND_SOURCE_ANALYSIS.md](../01_DEEP_REVERSE_ENGINEERING_AND_SOURCE_ANALYSIS.md)**
   - **Ghidra MCP PE Binary Reverse Engineering**: `bat2exe_12.exe` (UPX Native Stub `0x20ea0`), `BEDeCode.exe` (VB6 Native `ThunRTMain` `0x1670`), `example.exe` (.NET CLR `0x337e`), `example_bytepressed.exe` (LZMA RangeCoder).
   - **5 Core Tools Source Code Dissection**: `Invoke-DOSfuscation`, `SomalifuscatorV2`, `batch_deobfuscator`, `Exorcism` (`cmd.exe!FindFixAndRun` Hook), `0xidiz3r`.
2. 📖 **[02_CLASSIC_TO_MODERN_EVOLUTION_1990_2026.md](../02_CLASSIC_TO_MODERN_EVOLUTION_1990_2026.md)**
   - 30-Year Evolution from MS-DOS ASCII techniques to 2026 AI/LLM Deobfuscation models.
3. 🛡️ **[03_BATCLOAK_MULTI_STAGE_LOADER_FORENSICS.md](../03_BATCLOAK_MULTI_STAGE_LOADER_FORENSICS.md)**
   - Multi-Stage forensic analysis of BatCloak / ScrubCrypt obfuscated loaders and EDR telemetry.
4. 📑 **[04_BATCH_OBFUSCATION_ENCYCLOPEDIA.md](../04_BATCH_OBFUSCATION_ENCYCLOPEDIA.md)** & **[05_BATCH_OBFUSCATION_MASTER_GUIDE.md](../05_BATCH_OBFUSCATION_MASTER_GUIDE.md)**
   - Theoretical taxonomy and comprehensive detection framework.

---

## 🏗️ Architecture & Defensive Verification

```mermaid
flowchart TD
    subgraph "Obfuscation & Compilation Techniques"
        RAW["Raw Batch Script (.bat/.cmd)"] --> T1["Invoke-DOSfuscation\nEnv Slicing & Reversed Loops"]
        RAW --> T2["BatCloak / BEncoder\nUTF-16LE BOM Disguise"]
        RAW --> T3["SomalifuscatorV2 / 0xidiz3r\nDynamic Caesar & Zero-Literal"]
        T1 & T2 & T3 --> OBF["Obfuscated Batch Payload"]
        OBF --> PE["Bat2Exe Native/VB6/.NET Compilers"]
    end

    subgraph "Defensive Analysis & Ghidra MCP Reverse Engineering"
        PE --> G1["Ghidra MCP PE Triage\nEntrypoints, UPX/LZMA Unpacking"]
        OBF --> P1["Python AST Simulator\n(src/cmd_parser_simulator.py)"]
        OBF --> D1["Dynamic Hooking\n(Exorcism cmd.exe!FindFixAndRun)"]
        P1 & G1 & D1 --> DET["SOC/EDR Detection (Sigma & YARA)"]
    end
```
