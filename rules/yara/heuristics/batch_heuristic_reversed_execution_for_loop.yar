rule Batch_Heuristic_Reversed_Execution_Loop {
    meta:
        description = "Detects reversed numeric loop index unpacking strings backwards"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "CRITICAL"
        mitre_technique = "T1027.010"

    strings:
        $for_rev = /for\s+\/[lL]\s+%%[a-zA-Z]\s+in\s*\([0-9]+,-1,0\)/ nocase

    condition:
        $for_rev
}
