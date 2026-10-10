rule Batch_Obfuscator_Invoke_CradleCrafter {
    meta:
        description = "Detects Invoke-CradleCrafter batch-wrapped PowerShell download cradles"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "CRITICAL"
        mitre_technique = "T1059.001"

    strings:
        $cradle1 = "Invoke-CradleCrafter" nocase
        $net = "System.Net.WebClient" nocase
        $download = "DownloadString" nocase
        $iex = "IEX" nocase

    condition:
        $cradle1 or ($net and $download and $iex)
}
