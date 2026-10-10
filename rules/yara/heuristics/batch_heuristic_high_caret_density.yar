rule Batch_Heuristic_High_Caret_Density {
    meta:
        description = "Detects unusually high ratio of caret escape characters in script text"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027.010"

    strings:
        $c1 = "^" ascii
        $c2 = "^^" ascii
        $echo = "@echo" nocase

    condition:
        #c1 > 40 or #c2 > 20
}
