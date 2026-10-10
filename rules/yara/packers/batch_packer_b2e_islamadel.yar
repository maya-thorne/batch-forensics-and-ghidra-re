rule Batch_Packer_Bat2Exe_IslamAdel {
    meta:
        description = "Detects Islam Adel Bat2Exe PE converter signature and extraction routine"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "MEDIUM"
        mitre_technique = "T1027"

    strings:
        $mz = { 4D 5A }
        $sig = "islamadel/bat2exe" nocase
        $temp = "%TEMP%\\" ascii

    condition:
        $mz at 0 and ($sig or $temp)
}
