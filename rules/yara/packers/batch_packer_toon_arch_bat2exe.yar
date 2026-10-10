rule Batch_Packer_ToonArch_Bat2Exe {
    meta:
        description = "Detects Toon-arch bat2exe payload embedding structure"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "MEDIUM"
        mitre_technique = "T1027"

    strings:
        $mz = { 4D 5A }
        $toon = "toon-arch" nocase
        $payload = "PAYLOAD_BATCH_DATA" ascii

    condition:
        $mz at 0 and ($toon or $payload)
}
