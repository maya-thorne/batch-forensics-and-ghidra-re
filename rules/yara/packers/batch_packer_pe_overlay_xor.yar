rule Batch_Packer_PE_Overlay_XOR_Batch {
    meta:
        description = "Detects PE executable with XOR-encrypted batch script appended to file overlay"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027"

    strings:
        $mz = { 4D 5A }
        $xor_stub = { 8A 04 0E 34 ?? 88 04 0E 41 }

    condition:
        $mz at 0 and $xor_stub
}
