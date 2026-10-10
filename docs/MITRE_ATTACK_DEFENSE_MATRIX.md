# 🛡️ MITRE ATT&CK Enterprise Defense & Detection Matrix

> **Repository**: [`maya-thorne/batch-forensics-and-ghidra-re`](https://github.com/maya-thorne/batch-forensics-and-ghidra-re)  
> **Author & Research Lead**: Maya Thorne (Blue Team Detection Engineering & Reverse Engineering)  
> **Total Rules**: 52 Modular Sigma Rules · 32 Modular YARA Signatures · Splunk SPL & Elastic KQL Feeds

---

## 🗺️ MITRE ATT&CK Matrix Cross-Reference

| Tactic | Technique ID | Technique Name | Primary Detection Mechanism | Matching Sigma Rules | Matching YARA Signatures | SOC Triage Severity |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **Defense Evasion** | **T1027.010** | Command Obfuscation | Caret (`^`) interleaving lexer state | `proc_creation_win_cmd_caret_interleaving.yml`<br>`proc_creation_win_cmd_double_caret_escaping.yml` | `batch_heuristic_high_caret_density.yar`<br>`batch_heuristic_delimiter_collapsing_chain.yar` | **HIGH** |
| **Defense Evasion** | **T1027.010** | Variable Slicing Evasion | Single-char harvesting (`:~x,1`) & negative offsets (`:~-x`) | `proc_creation_win_cmd_env_slicing_single_char.yml`<br>`proc_creation_win_cmd_env_slicing_negative_offset.yml` | `batch_heuristic_excessive_var_slicing.yar`<br>`batch_obf_invoke_dosfuscation.yar` | **HIGH** |
| **Defense Evasion** | **T1027** | Binary Padding & Dead Code | Abobus junk labels, BatchAlchemy arithmetic mutation | `proc_creation_win_cmd_abobus_obfuscator.yml`<br>`proc_creation_win_cmd_batchalchemy_junk_loops.yml` | `batch_obf_abobus_junk.yar`<br>`batch_obf_batchalchemy_tree.yar` | **MEDIUM** |
| **Defense Evasion** | **T1027** | Polyglot Header Disguise | UTF-16LE BOM (`0xFF 0xFE`) header with non-wide ASCII body | `proc_creation_win_cmd_batcloak_polyglot_bom.yml` | `batch_obf_batcloak_utf16le_bom.yar`<br>`batch_obf_scrubcrypt_loader.yar` | **CRITICAL** |
| **Defense Evasion** | **T1027.002** | Software Packing | PE container packing via UPX and Bytepress LZMA | (Sysmon process lineage / file drop) | `batch_packer_bat2exe_upx_stub.yar`<br>`batch_packer_bytepress_lzma_rangecoder.yar` | **CRITICAL** |
| **Defense Evasion** | **T1027.009** | Embedded Payloads | .NET CLR assembly resource drop (`batch_cmd`) | (Process creation from %TEMP%) | `batch_packer_bat2exe_dotnet_resource.yar`<br>`batch_packer_bat2exe_vb6_thunrtmain.yar` | **HIGH** |
| **Defense Evasion** | **T1140** | Deobfuscate/Decode Files | Certutil silent base64/hex decode pipelines | `proc_creation_win_cmd_certutil_decode_hidden.yml` | `batch_heuristic_certutil_hex_decode_chain.yar`<br>`batch_obf_bencoder_base64.yar` | **HIGH** |
| **Defense Evasion** | **T1202** | Indirect Command Execution | Forfiles proxy command launch (`forfiles /C`) | `proc_creation_win_cmd_forfiles_execution.yml`<br>`proc_creation_win_cmd_pcalua_indirect_exec.yml` | `batch_heuristic_delimiter_collapsing_chain.yar` | **HIGH** |
| **Execution** | **T1059.003** | Windows Command Shell | Delayed variable expansion (`!VAR!`) & switches | `proc_creation_win_cmd_delayed_expansion_flag.yml`<br>`proc_creation_win_cmd_delayed_var_expansion.yml` | `batch_obf_somalifuscator_v1.yar`<br>`batch_obf_0xidiz3r_rust.yar` | **MEDIUM** |
| **Execution** | **T1059.003** | Reversed String Loop | Loop index countdown (`for /L %i in (n,-1,0)`) | `proc_creation_win_cmd_reversed_for_loop.yml` | `batch_heuristic_reversed_execution_for_loop.yar` | **CRITICAL** |
| **Execution** | **T1059.001** | PowerShell Staging | Batch launching base64 encoded PowerShell | `proc_creation_win_cmd_powershell_base64_pipe.yml` | `batch_heuristic_powershell_download_cradle.yar`<br>`batch_obf_cradlecrafter_batch.yar` | **HIGH** |
| **Execution** | **T1218.005** | Mshta VBScript Inline | Batch invoking `mshta vbscript:...` | `proc_creation_win_cmd_mshta_vbscript_inline.yml` | `batch_heuristic_amsi_etw_patch_attempt.yar` | **HIGH** |
| **Execution** | **T1218.010** | Regsvr32 Scriptlet | Remote XML/scrobj execution | `proc_creation_win_cmd_regsvr32_scrobj_exec.yml` | (Dynamic memory rule) | **CRITICAL** |
| **Execution** | **T1047** | WMI Process Call | Indirect process launch via `wmic process call` | `proc_creation_win_cmd_wmic_process_call.yml` | (Process tree anomaly) | **HIGH** |
| **Discovery** | **T1497.001** | System Virtualization Discovery | Querying hypervisor MAC OUIs or disk captions | `proc_creation_win_cmd_anti_vm_mac_check.yml`<br>`proc_creation_win_cmd_wmic_diskdrive_check.yml` | `batch_heuristic_anti_vm_hardware_fingerprint.yar`<br>`batch_obf_somalifuscator_v2.yar` | **HIGH** |
| **Discovery** | **T1497.003** | Time-based Evasion | High-count localhost ping delays (`ping -n 30`) | `proc_creation_win_cmd_anti_sandbox_sleep.yml` | (Behavioral process trace) | **MEDIUM** |
| **Discovery** | **T1057** | Process Discovery | Interrogating tasklist for debuggers / sniffers | `proc_creation_win_cmd_process_list_analysis.yml` | (Behavioral command trace) | **HIGH** |
| **Discovery** | **T1482** | Domain Trust Discovery | Automated `nltest /domain_trusts` from batch | `proc_creation_win_cmd_domain_trust_discovery.yml` | (Network discovery rule) | **HIGH** |
| **Persistence** | **T1547.001** | Registry Run Keys | Batch adding `CurrentVersion\Run` entries | `proc_creation_win_cmd_run_key_registry_add.yml`<br>`proc_creation_win_cmd_startup_folder_drop.yml` | (Registry event correlation) | **CRITICAL** |
| **Persistence** | **T1543.003** | Windows Service Creation | Batch creating background services (`sc create`) | `proc_creation_win_cmd_service_creation.yml` | (Service manager trace) | **CRITICAL** |

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
