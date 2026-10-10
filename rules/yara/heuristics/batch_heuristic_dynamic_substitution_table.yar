rule Batch_Heuristic_Dynamic_Substitution_Table {
    meta:
        description = "Detects large single-line alphabet character substitution arrays"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027"

    strings:
        $alpha = /set\s+[a-zA-Z0-9_]+=[a-zA-Z0-9!@#$%^&*()_+=\-{}[\]:;"'<>,.?\/]{50,}/ nocase

    condition:
        $alpha
}
