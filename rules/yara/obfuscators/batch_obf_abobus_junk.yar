rule Batch_Obfuscator_Abobus_JunkChains {
    meta:
        description = "Detects Abobus batch obfuscator dead code jumps and random variable spam"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "MEDIUM"
        mitre_technique = "T1027"

    strings:
        $abobus = "Abobus" nocase
        $goto = /goto\s+label_[0-9a-f]{6,}/ nocase
        $setjunk = /set\s+[0-9a-f]{8,}=[0-9a-f]{8,}/ nocase

    condition:
        $abobus or (#goto > 10 and #setjunk > 10)
}
