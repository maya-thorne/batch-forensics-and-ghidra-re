rule Batch_Packer_Bat2Exe_DotNet_Resource {
    meta:
        description = "Detects .NET CLR assembly containing encrypted batch_cmd resource payload"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027.009"

    strings:
        $mz = { 4D 5A }
        $corexe = "_CorExeMain" ascii
        $mscoree = "mscoree.dll" nocase
        $res = "batch_cmd" ascii

    condition:
        $mz at 0 and $corexe and $mscoree and $res
}
