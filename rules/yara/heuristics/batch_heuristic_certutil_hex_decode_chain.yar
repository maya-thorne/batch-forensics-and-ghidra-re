rule Batch_Heuristic_Certutil_Hex_Chain {
    meta:
        description = "Detects hex stream followed by certutil -decodehex execution"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1140"

    strings:
        $hex = /[0-9a-fA-F]{32,}/ ascii
        $cu1 = "certutil -decodehex" nocase
        $cu2 = "certutil /decodehex" nocase

    condition:
        $hex and ($cu1 or $cu2)
}
