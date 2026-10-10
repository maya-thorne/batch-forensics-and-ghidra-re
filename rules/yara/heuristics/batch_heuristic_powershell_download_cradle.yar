rule Batch_Heuristic_PowerShell_Download_Cradle {
    meta:
        description = "Detects batch launching PowerShell WebClient or Invoke-WebRequest cradle"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "CRITICAL"
        mitre_technique = "T1059.001"

    strings:
        $ps = "powershell" nocase
        $iwr = /iwr|invoke-webrequest|downloadstring|downloaddata/ nocase
        $http = /https?:\/\// nocase

    condition:
        $ps and $iwr and $http
}
