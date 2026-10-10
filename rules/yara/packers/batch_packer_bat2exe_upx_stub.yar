rule Batch_Packer_Bat2Exe_UPX_Container {
    meta:
        description = "Detects native Win32 Bat2Exe container packed with UPX compression"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027.002"

    strings:
        $mz = { 4D 5A }
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $bat = /cmd(\.exe)?\s*\/c.*\.bat/ ascii

    condition:
        $mz at 0 and $upx0 and $upx1 and $bat
}
