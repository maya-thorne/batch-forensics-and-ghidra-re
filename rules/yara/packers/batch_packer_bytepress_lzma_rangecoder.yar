rule Batch_Packer_Bytepress_LZMA_Stub {
    meta:
        description = "Detects Bytepress native PE container using LZMA RangeCoder stub"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "CRITICAL"
        mitre_technique = "T1027.002"

    strings:
        $mz = { 4D 5A }
        $bp = "Bytepress" ascii
        $lzma = { 5D 00 00 80 00 }
        $valloc = "VirtualAlloc" ascii

    condition:
        $mz at 0 and ($bp or ($lzma and $valloc))
}
