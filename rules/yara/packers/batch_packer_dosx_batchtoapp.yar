rule Batch_Packer_DosX_BatchToApp {
    meta:
        description = "Detects DosX BatchToApp converted PE executable"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "MEDIUM"
        mitre_technique = "T1027"

    strings:
        $mz = { 4D 5A }
        $dosx = "DosX" nocase
        $b2a = "BatchToApp" nocase

    condition:
        $mz at 0 and ($dosx or $b2a)
}
