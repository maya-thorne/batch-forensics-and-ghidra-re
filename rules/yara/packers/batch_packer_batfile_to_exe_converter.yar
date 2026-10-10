rule Batch_Packer_F2KO_BatToExe {
    meta:
        description = "Detects F2KO Software Bat to Exe Converter compiled binaries"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "MEDIUM"
        mitre_technique = "T1027"

    strings:
        $mz = { 4D 5A }
        $f2ko = "F2KO" ascii
        $b2e = "Bat_To_Exe_Converter" nocase

    condition:
        $mz at 0 and ($f2ko or $b2e)
}
