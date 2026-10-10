rule Batch_Obfuscator_BEncoder_Base64 {
    meta:
        description = "Detects BEncoder certutil base64 decode and execute bootstrap script"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1140"

    strings:
        $be = "BEncoder" nocase
        $cert1 = "certutil -decode" nocase
        $cert2 = "certutil /decode" nocase
        $cert3 = "-----BEGIN CERTIFICATE-----" ascii

    condition:
        $be or ($cert3 and ($cert1 or $cert2))
}
