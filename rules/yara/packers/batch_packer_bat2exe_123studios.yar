rule Batch_Packer_Bat2Exe_123Studios {
    meta:
        description = "Detects 123Studios bat2exe compiled container"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "MEDIUM"
        mitre_technique = "T1027"

    strings:
        $mz = { 4D 5A }
        $sig = "123Studios" nocase
        $drop = "batch_exec.bat" ascii

    condition:
        $mz at 0 and ($sig and $drop)
}
