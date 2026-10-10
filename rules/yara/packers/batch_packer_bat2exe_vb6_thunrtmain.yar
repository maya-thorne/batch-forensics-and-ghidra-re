rule Batch_Packer_Bat2Exe_VB6_Container {
    meta:
        description = "Detects Visual Basic 6.0 VM compiled batch container (BEDeCode / ThunRTMain)"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027"

    strings:
        $mz = { 4D 5A }
        $thun = "ThunRTMain" ascii
        $vbvm = "MSVBVM60.DLL" nocase
        $chrmap = "CHRMAPSET" ascii

    condition:
        $mz at 0 and $thun and $vbvm and $chrmap
}
