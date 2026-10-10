rule Batch_Obfuscator_InvokeDOSfuscation {
    meta:
        description = "Detects Invoke-DOSfuscation generator tokens, reversed loops and environment maps"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027.010"

    strings:
        $s1 = /for\s+\/[lL]\s+%+[a-zA-Z]\s+in\s*\([0-9]+,-1,[0-9]+\)/ nocase
        $s2 = /set\s+[a-zA-Z0-9_]+=[a-zA-Z0-9_]{30,}/ nocase
        $s3 = /cmd(\.exe)?\s*\/v:[1oO]/ nocase

    condition:
        2 of them
}
