rule Batch_Obfuscator_BatchAlchemy_Mutated {
    meta:
        description = "Detects BatchAlchemy tree-sitter mutated batch expressions"
        author = "Maya Thorne (Reverse Engineering & Forensics)"
        reference = "https://github.com/maya-thorne/batch-forensics-and-ghidra-re"
        date = "2026-10-11"
        severity = "MEDIUM"
        mitre_technique = "T1027"

    strings:
        $ba = "batchalchemy" nocase
        $arith = /set\s+\/a\s+[a-zA-Z0-9_]+=[0-9]+\s*\^\s*[0-9]+/ nocase
        $rem = /rem\s+[0-9a-f]{16,}/ nocase

    condition:
        $ba or (#arith > 8 and #rem > 8)
}
