# 🛡️ MITRE ATT&CK Enterprise Defense & Detection Matrix

> **Repository**: [`maya-thorne/batch-forensics-and-ghidra-re`](https://github.com/maya-thorne/batch-forensics-and-ghidra-re)  
> **Author & Research Lead**: Maya Thorne (Blue Team Detection Engineering & Reverse Engineering)  
> **Total Rules**: 52 Modular Sigma Rules · 32 Modular YARA Signatures · Splunk SPL & Elastic KQL Feeds

---

## 🗺️ MITRE ATT&CK Matrix Cross-Reference

| Tactic | Technique ID | Technique Name | Primary Detection Mechanism | Matching Sigma Rules | Matching YARA Signatures | SOC Triage Severity |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **Defense Evasion** | **T1027.010** | Command Obfuscation | Caret (`^`) interleaving lexer state | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>caret_<wbr>interleaving.yml</code><br><code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>double_<wbr>caret_<wbr>escaping.yml</code> | <code>batch_<wbr>heuristic_<wbr>high_<wbr>caret_<wbr>density.yar</code><br><code>batch_<wbr>heuristic_<wbr>delimiter_<wbr>collapsing_<wbr>chain.yar</code> | **HIGH** |
| **Defense Evasion** | **T1027.010** | Variable Slicing Evasion | Single-char harvesting (`:~x,1`) & negative offsets (`:~-x`) | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>env_<wbr>slicing_<wbr>single_<wbr>char.yml</code><br><code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>env_<wbr>slicing_<wbr>negative_<wbr>offset.yml</code> | <code>batch_<wbr>heuristic_<wbr>excessive_<wbr>var_<wbr>slicing.yar</code><br><code>batch_<wbr>obf_<wbr>invoke_<wbr>dosfuscation.yar</code> | **HIGH** |
| **Defense Evasion** | **T1027** | Binary Padding & Dead Code | Abobus junk labels, BatchAlchemy arithmetic mutation | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>abobus_<wbr>obfuscator.yml</code><br><code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>batchalchemy_<wbr>junk_<wbr>loops.yml</code> | <code>batch_<wbr>obf_<wbr>abobus_<wbr>junk.yar</code><br><code>batch_<wbr>obf_<wbr>batchalchemy_<wbr>tree.yar</code> | **MEDIUM** |
| **Defense Evasion** | **T1027** | Polyglot Header Disguise | UTF-16LE BOM (`0xFF 0xFE`) header with non-wide ASCII body | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>batcloak_<wbr>polyglot_<wbr>bom.yml</code> | <code>batch_<wbr>obf_<wbr>batcloak_<wbr>utf16le_<wbr>bom.yar</code><br><code>batch_<wbr>obf_<wbr>scrubcrypt_<wbr>loader.yar</code> | **CRITICAL** |
| **Defense Evasion** | **T1027.002** | Software Packing | PE container packing via UPX and Bytepress LZMA | (Sysmon process lineage / file drop) | <code>batch_<wbr>packer_<wbr>bat2exe_<wbr>upx_<wbr>stub.yar</code><br><code>batch_<wbr>packer_<wbr>bytepress_<wbr>lzma_<wbr>rangecoder.yar</code> | **CRITICAL** |
| **Defense Evasion** | **T1027.009** | Embedded Payloads | .NET CLR assembly resource drop (<code>batch_<wbr>cmd</code>) | (Process creation from %TEMP%) | <code>batch_<wbr>packer_<wbr>bat2exe_<wbr>dotnet_<wbr>resource.yar</code><br><code>batch_<wbr>packer_<wbr>bat2exe_<wbr>vb6_<wbr>thunrtmain.yar</code> | **HIGH** |
| **Defense Evasion** | **T1140** | Deobfuscate/Decode Files | Certutil silent base64/hex decode pipelines | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>certutil_<wbr>decode_<wbr>hidden.yml</code> | <code>batch_<wbr>heuristic_<wbr>certutil_<wbr>hex_<wbr>decode_<wbr>chain.yar</code><br><code>batch_<wbr>obf_<wbr>bencoder_<wbr>base64.yar</code> | **HIGH** |
| **Defense Evasion** | **T1202** | Indirect Command Execution | Forfiles proxy command launch (`forfiles /C`) | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>forfiles_<wbr>execution.yml</code><br><code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>pcalua_<wbr>indirect_<wbr>exec.yml</code> | <code>batch_<wbr>heuristic_<wbr>delimiter_<wbr>collapsing_<wbr>chain.yar</code> | **HIGH** |
| **Execution** | **T1059.003** | Windows Command Shell | Delayed variable expansion (`!VAR!`) & switches | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>delayed_<wbr>expansion_<wbr>flag.yml</code><br><code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>delayed_<wbr>var_<wbr>expansion.yml</code> | <code>batch_<wbr>obf_<wbr>somalifuscator_<wbr>v1.yar</code><br><code>batch_<wbr>obf_<wbr>0xidiz3r_<wbr>rust.yar</code> | **MEDIUM** |
| **Execution** | **T1059.003** | Reversed String Loop | Loop index countdown (`for /L %i in (n,-1,0)`) | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>reversed_<wbr>for_<wbr>loop.yml</code> | <code>batch_<wbr>heuristic_<wbr>reversed_<wbr>execution_<wbr>for_<wbr>loop.yar</code> | **CRITICAL** |
| **Execution** | **T1059.001** | PowerShell Staging | Batch launching base64 encoded PowerShell | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>powershell_<wbr>base64_<wbr>pipe.yml</code> | <code>batch_<wbr>heuristic_<wbr>powershell_<wbr>download_<wbr>cradle.yar</code><br><code>batch_<wbr>obf_<wbr>cradlecrafter_<wbr>batch.yar</code> | **HIGH** |
| **Execution** | **T1218.005** | Mshta VBScript Inline | Batch invoking `mshta vbscript:...` | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>mshta_<wbr>vbscript_<wbr>inline.yml</code> | <code>batch_<wbr>heuristic_<wbr>amsi_<wbr>etw_<wbr>patch_<wbr>attempt.yar</code> | **HIGH** |
| **Execution** | **T1218.010** | Regsvr32 Scriptlet | Remote XML/scrobj execution | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>regsvr32_<wbr>scrobj_<wbr>exec.yml</code> | (Dynamic memory rule) | **CRITICAL** |
| **Execution** | **T1047** | WMI Process Call | Indirect process launch via `wmic process call` | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>wmic_<wbr>process_<wbr>call.yml</code> | (Process tree anomaly) | **HIGH** |
| **Discovery** | **T1497.001** | System Virtualization Discovery | Querying hypervisor MAC OUIs or disk captions | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>anti_<wbr>vm_<wbr>mac_<wbr>check.yml</code><br><code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>wmic_<wbr>diskdrive_<wbr>check.yml</code> | <code>batch_<wbr>heuristic_<wbr>anti_<wbr>vm_<wbr>hardware_<wbr>fingerprint.yar</code><br><code>batch_<wbr>obf_<wbr>somalifuscator_<wbr>v2.yar</code> | **HIGH** |
| **Discovery** | **T1497.003** | Time-based Evasion | High-count localhost ping delays (`ping -n 30`) | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>anti_<wbr>sandbox_<wbr>sleep.yml</code> | (Behavioral process trace) | **MEDIUM** |
| **Discovery** | **T1057** | Process Discovery | Interrogating tasklist for debuggers / sniffers | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>process_<wbr>list_<wbr>analysis.yml</code> | (Behavioral command trace) | **HIGH** |
| **Discovery** | **T1482** | Domain Trust Discovery | Automated <code>nltest /domain_<wbr>trusts</code> from batch | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>domain_<wbr>trust_<wbr>discovery.yml</code> | (Network discovery rule) | **HIGH** |
| **Persistence** | **T1547.001** | Registry Run Keys | Batch adding `CurrentVersion\Run` entries | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>run_<wbr>key_<wbr>registry_<wbr>add.yml</code><br><code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>startup_<wbr>folder_<wbr>drop.yml</code> | (Registry event correlation) | **CRITICAL** |
| **Persistence** | **T1543.003** | Windows Service Creation | Batch creating background services (`sc create`) | <code>proc_<wbr>creation_<wbr>win_<wbr>cmd_<wbr>service_<wbr>creation.yml</code> | (Service manager trace) | **CRITICAL** |

---

## 📈 Detection Engineering Metrics & Quality Assurance

```text
========================================================================================
RULE METRIC CATEGORY                     TARGET LEVEL         ACHIEVED LEVEL
========================================================================================
Total Production Sigma Rules             >= 50 Rules          52 Modular Rules
Total Modular YARA Rules                 >= 30 Rules          32 Modular Signatures
MITRE ATT&CK Techniques Mapped           >= 10 Techniques     15 Distinct Techniques
SIEM Search Query Translations           Splunk & Elastic     Splunk SPL + Elastic KQL
False Positive Minimization              Strict Image Filter  Process & Argument Scoped
Testing & Automated Verification         100% Deterministic   Passing Unit Test Suite
========================================================================================
```

---

## 💡 Blue Team SOC Triage Guide

1. **Initial Alert Triage**:
   - Verify parent process lineage: Was `cmd.exe` spawned by an anomalous parent (`word.exe`, `excel.exe`, `w3wp.exe`, `powershell.exe`)?
   - Check CommandLine arguments against `proc_creation_win_cmd_caret_interleaving.yml` and `proc_creation_win_cmd_env_slicing_single_char.yml`.
2. **Deobfuscation Normalization**:
   - Pass the raw command line into `src/cmd_parser_simulator.py` to evaluate the 5-stage deobfuscated payload safely in memory without execution.
3. **Static File Inspection**:
   - Run the YARA rule suite (`yara -r rules/yara/ target_script.bat`) to immediately identify obfuscator origins (`BatCloak`, `ScrubCrypt`, `SomalifuscatorV2`, `0xidiz3r`).
4. **Containment & Remediation**:
   - If `BatCloak` polyglot BOM or `Certutil` decoding is confirmed, isolate host and inspect dropped binaries in `%TEMP%` and `%PUBLIC%`.
