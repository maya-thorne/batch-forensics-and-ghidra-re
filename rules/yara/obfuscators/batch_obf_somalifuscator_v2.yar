rule Batch_Obfuscator_Somalifuscator_V2 {
    meta:
        description = "Detects Somalifuscator V2 Caesar shift lookup table and anti-VM logic"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "CRITICAL"
        mitre_technique = "T1027"

    strings:
        $caesar = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" ascii
        $marker = "KDot227" nocase
        $vmcheck = "getmac" ascii
        $vm_ou1 = "00:05:69" ascii

    condition:
        ($caesar and $marker) or ($caesar and $vmcheck and $vm_ou1)
}
