rule Batch_Obfuscator_BatCloak_BOM {
    meta:
        description = "Detects BatCloak UTF-16LE BOM header disguise with non-wide ASCII body lines"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "CRITICAL"
        mitre_technique = "T1027"

    strings:
        $bom = { FF FE }
        $cmd1 = "@echo off" ascii
        $cmd2 = "setlocal" ascii
        $cmd3 = "certutil" ascii

    condition:
        $bom at 0 and 1 of ($cmd*)
}
