rule Batch_Obfuscator_0xidiz3r_Rust {
    meta:
        description = "Detects 0xidiz3r Rust zero-literal 3-seed bootstrap environment maps"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "CRITICAL"
        mitre_technique = "T1027.010"

    strings:
        $seed = "0xidiz3r" nocase
        $b1 = "%__0x%" ascii
        $b2 = "%__seed%" ascii
        $zero = /%[0-9a-f]{4}:~[0-9]+,[0-9]+%/ ascii

    condition:
        $seed or (2 of ($b*) and #zero > 10)
}
