rule Batch_Obfuscator_PandaCrypter {
    meta:
        description = "Detects PandaCrypter chainski batch encrypter markers and unescape loops"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027"

    strings:
        $panda = "PandaCrypter" nocase
        $chainski = "chainski" nocase
        $xor = /set\s+\/a\s+.*\^\s*0x[0-9a-f]+/ nocase

    condition:
        ($panda and $chainski) or ($panda and $xor)
}
