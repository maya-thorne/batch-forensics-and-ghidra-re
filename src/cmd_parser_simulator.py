"""
@ai-role Windows cmd.exe 5-Stage Parser Simulator & Static Deobfuscation Engine
@ai-flow BOM/Encoding Normalization -> Caret State Machine -> Env Slicing/Substitution -> Telemetry Scoring
@ai-boundary Pure static analysis (Zero execution via subprocess/os.system)
@ai-invariant Deterministic AST/token normalization for defensive SOC/EDR inspection
"""

from __future__ import annotations
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


DEFAULT_WINDOWS_ENV: Dict[str, str] = {
    "PUBLIC": r"C:\Users\Public",
    "COMSPEC": r"C:\Windows\System32\cmd.exe",
    "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
    "SYSTEMROOT": r"C:\Windows",
    "WINDIR": r"C:\Windows",
    "PROGRAMDATA": r"C:\ProgramData",
    "APPDATA": r"C:\Users\Default\AppData\Roaming",
}


@dataclass
class DeobfuscationReport:
    encoding_anomaly: str
    normalized_lines: List[str]
    resolved_variables: Dict[str, str]
    shannon_entropy: float
    caret_density: float
    var_expansion_density: float
    mitre_techniques: List[str] = field(default_factory=list)


def detect_bom_and_decode(raw_bytes: bytes) -> Tuple[str, str]:
    """
    [SEC] Detects BatCloak / BEncoder style UTF-16 BOM header polyglot tricks.
    If a file starts with 0xFF 0xFE followed by non-null ASCII bytes on subsequent lines,
    cmd.exe processes the body as ANSI/ASCII while text editors misinterpret it as UTF-16LE CJK.
    """
    if raw_bytes.startswith(b"\xff\xfe"):
        body = raw_bytes[2:]
        null_ratio = body.count(0) / max(len(body), 1)
        if null_ratio < 0.25:
            first_newline = body.find(b"\n")
            usable = body[first_newline + 1 :] if first_newline != -1 else body
            return (
                usable.decode("utf-8", errors="replace"),
                "UTF16LE_BOM_POLYGLOT_DISGUISE (0xFF 0xFE with ASCII body)",
            )
        return raw_bytes.decode("utf-16-le", errors="replace"), "UTF-16LE"
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        return raw_bytes[3:].decode("utf-8", errors="replace"), "UTF-8-BOM"
    return raw_bytes.decode("utf-8", errors="replace"), "UTF-8/ASCII"


def strip_carets_state_machine(line: str) -> str:
    """
    [BIZ] Emulates cmd.exe Stage-2 Lexer caret (^) escaping outside double quotes.
    Inside double quotes, '^' is treated as a literal character by cmd.exe.
    """
    out: List[str] = []
    in_quotes = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == '"':
            in_quotes = not in_quotes
            out.append(ch)
            i += 1
        elif ch == "^" and not in_quotes:
            if i + 1 < n:
                out.append(line[i + 1])
                i += 2
            else:
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def evaluate_var_expr(expr: str, env: Dict[str, str]) -> str:
    """
    Resolves %VAR%, %VAR:~offset,len%, and %VAR:old=new% against current symbol table.
    """
    if ":" not in expr:
        key = expr.upper()
        return env.get(key, f"%{expr}%")

    var_name, modifier = expr.split(":", 1)
    key = var_name.upper()
    if key not in env:
        return f"%{expr}%"
    val = env[key]

    if modifier.startswith("~"):
        parts = modifier[1:].split(",")
        try:
            offset = int(parts[0].strip())
            length = int(parts[1].strip()) if len(parts) > 1 else None
            if offset < 0:
                start = max(len(val) + offset, 0)
            else:
                start = offset
            if length is None:
                return val[start:]
            if length < 0:
                end = max(len(val) + length, 0)
                return val[start:end]
            return val[start : start + length]
        except ValueError:
            return val

    if "=" in modifier:
        old_sub, new_sub = modifier.split("=", 1)
        if not old_sub:
            return val
        pattern = re.compile(re.escape(old_sub), re.IGNORECASE)
        return pattern.sub(new_sub, val)

    return val


def expand_variables_in_line(line: str, env: Dict[str, str]) -> str:
    """
    Iteratively expands both immediate (%VAR%) and delayed (!VAR!) expressions.
    """
    pct_pattern = re.compile(r"%([^%\r\n]+)%")
    bang_pattern = re.compile(r"!([^!\r\n]+)!")

    current = line
    for _ in range(8):
        prev = current
        current = pct_pattern.sub(lambda m: evaluate_var_expr(m.group(1), env), current)
        current = bang_pattern.sub(lambda m: evaluate_var_expr(m.group(1), env), current)
        if current == prev:
            break
    return current


def parse_set_assignment(line: str, env: Dict[str, str]) -> None:
    """
    Extracts variable definitions from `set VAR=VALUE` or `set "VAR=VALUE"` statements.
    """
    stripped = line.strip()
    m = re.match(r'^@?set\s+(?:/a\s+|/p\s+)?(?:"([^"=]+)=([^"]*)"|([^=\s]+)=(.*))$', stripped, re.IGNORECASE)
    if not m:
        return
    if m.group(1) is not None:
        k, v = m.group(1).strip(), m.group(2)
    else:
        k, v = m.group(3).strip(), m.group(4)
    env[k.upper()] = v


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 4)


def deobfuscate_batch_script(raw_bytes: bytes) -> DeobfuscationReport:
    decoded_text, encoding_anomaly = detect_bom_and_decode(raw_bytes)
    total_len = max(len(decoded_text), 1)
    caret_density = round(decoded_text.count("^") / total_len, 4)
    var_density = round((decoded_text.count("%") + decoded_text.count("!")) / total_len, 4)
    ent = shannon_entropy(decoded_text)

    env = dict(DEFAULT_WINDOWS_ENV)
    user_vars: Dict[str, str] = {}
    normalized_lines: List[str] = []

    raw_lines = decoded_text.splitlines()
    for raw_line in raw_lines:
        step1 = strip_carets_state_machine(raw_line)
        step2 = expand_variables_in_line(step1, env)
        before_keys = set(env.keys())
        parse_set_assignment(step2, env)
        for k in set(env.keys()) - before_keys:
            user_vars[k] = env[k]
        # Track updated custom vars
        for k in list(user_vars.keys()):
            user_vars[k] = env[k]
        normalized_lines.append(step2)

    mitre: List[str] = ["T1059.003 (Windows Command Shell)"]
    if "POLYGLOT" in encoding_anomaly or caret_density > 0.03 or var_density > 0.08:
        mitre.append("T1027.010 (Command Obfuscation)")
    if any("certutil" in ln.lower() for ln in normalized_lines):
        mitre.append("T1140 (Deobfuscate/Decode Files or Information)")

    return DeobfuscationReport(
        encoding_anomaly=encoding_anomaly,
        normalized_lines=normalized_lines,
        resolved_variables=user_vars,
        shannon_entropy=ent,
        caret_density=caret_density,
        var_expansion_density=var_density,
        mitre_techniques=mitre,
    )
