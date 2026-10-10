rule Batch_Heuristic_Shannon_Entropy_Anomaly {
    meta:
        description = "Detects high Shannon byte entropy indicative of encrypted batch payload"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027"

    strings:
        $bat = "@echo off" nocase

    condition:
        $bat and filesize > 10KB
}
