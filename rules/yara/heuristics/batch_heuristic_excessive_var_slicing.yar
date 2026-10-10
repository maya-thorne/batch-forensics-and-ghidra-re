rule Batch_Heuristic_Excessive_Var_Slicing {
    meta:
        description = "Detects heavy concentration of environment variable substring slices"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "HIGH"
        mitre_technique = "T1027.010"

    strings:
        $slice = /%[a-zA-Z0-9_]+:~[0-9\-]+(,[0-9\-]+)?%/ ascii

    condition:
        #slice > 12
}
