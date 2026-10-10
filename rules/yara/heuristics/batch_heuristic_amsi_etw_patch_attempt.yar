rule Batch_Heuristic_AMSI_ETW_Patch_Attempt {
    meta:
        description = "Detects batch scripts triggering AMSI or ETW in-memory byte patch routines"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "CRITICAL"
        mitre_technique = "T1562.001"

    strings:
        $amsi = "AmsiScanBuffer" ascii
        $etw = "EtwEventWrite" ascii
        $patch = { C3 }

    condition:
        ($amsi or $etw)
}
