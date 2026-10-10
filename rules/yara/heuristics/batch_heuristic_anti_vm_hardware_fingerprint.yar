rule Batch_Heuristic_Anti_VM_Hardware_Fingerprint {
    meta:
        description = "Detects batch queries for VM MAC, BIOS, or hard disk vendor identifiers"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1497.001"

    strings:
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "QEMU" nocase
        $wmic = "wmic" nocase
        $mac = "getmac" nocase

    condition:
        ($wmic or $mac) and 1 of ($vm*)
}
