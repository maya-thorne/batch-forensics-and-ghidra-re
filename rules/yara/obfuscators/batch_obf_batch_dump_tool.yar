rule Batch_Tool_Batch_Dump_Marker {
    meta:
        description = "Detects Batch-Dump extraction indicators and runtime hook scripts"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "INFO"
        mitre_technique = "T1059.003"

    strings:
        $bd1 = "Batch-Dump" nocase
        $bd2 = "Dumped with Batch-Dump" nocase
        $hook = "FindFixAndRun" ascii

    condition:
        1 of them
}
