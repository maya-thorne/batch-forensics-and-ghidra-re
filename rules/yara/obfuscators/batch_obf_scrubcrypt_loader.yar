rule Batch_Obfuscator_ScrubCrypt_Loader {
    meta:
        description = "Detects ScrubCrypt multi-stage loader tags and polyglot extraction routines"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "CRITICAL"
        mitre_technique = "T1027"

    strings:
        $tag1 = "::ScrubCrypt::" ascii
        $tag2 = "::payload_start::" ascii
        $find = /findstr\s+\/v\s+\/r\s+"\^:"/ nocase
        $cert = /certutil\s+-decodehex/ nocase

    condition:
        1 of ($tag*) or ($find and $cert)
}
