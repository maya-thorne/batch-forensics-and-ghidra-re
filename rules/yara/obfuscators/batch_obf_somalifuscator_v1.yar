rule Batch_Obfuscator_Somalifuscator_V1 {
    meta:
        description = "Detects Somalifuscator V1 variable mapping and obfuscated cmd launcher"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027"

    strings:
        $v1 = "Somalifuscator" nocase
        $v2 = /%[a-zA-Z0-9_]{6,}:~[0-9]+,1%/ ascii
        $v3 = "@echo off\r\nsetlocal enabledelayedexpansion" nocase

    condition:
        $v1 or (#v2 > 15 and $v3)
}
