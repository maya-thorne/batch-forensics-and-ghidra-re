rule Batch_Heuristic_Delimiter_Collapsing_Chain {
    meta:
        description = "Detects command tokens joined by semicolons, commas, or equals signs"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027.010"

    strings:
        $comma = /cmd(\.exe)?,+[\/\-][cCaAkK]/ nocase
        $semi  = /cmd(\.exe)?;+[\/\-][cCaAkK]/ nocase
        $equal = /cmd(\.exe)?=+[\/\-][cCaAkK]/ nocase

    condition:
        1 of them
}
