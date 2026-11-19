#!/usr/bin/env python3
"""
Model supply-chain assessment for the TensorTrust Labs challenge.

For every model in the models directory it:
  1. Verifies the ModelGuard signature (.sig.json) against the TensorTrust
     ECDSA P-256 public key (signature is over the hex SHA-256 digest string).
  2. Recomputes the file hash/size and compares them with the signed manifest.
  3. Statically disassembles every pickle inside the model (pickletools) and
     lists every imported global WITHOUT unpickling / torch.load()ing anything.
  4. Classifies risk and writes a Markdown report with the evidence.

Usage (from the challenge folder):
    python3 -I assess_models.py --models-dir models --pubkey signing_key.pub --out security_report.md

Requires only python3 and the openssl CLI (both present on Kali).
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import pickletools
import re
import subprocess
import tempfile
import zipfile

MODEL_EXTS = (".pth", ".pt", ".bin", ".ckpt", ".pkl", ".pickle")

# Globals a normal PyTorch state_dict / checkpoint needs.
SAFE_GLOBALS = {
    ("collections", "OrderedDict"),
    ("torch._utils", "_rebuild_tensor"),
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_parameter"),
    ("torch._utils", "_rebuild_parameter_with_state"),
    ("torch._tensor", "_rebuild_from_type_v2"),
    ("torch", "Size"),
    ("torch", "device"),
}
TORCH_DTYPES = {
    "float16", "float32", "float64", "bfloat16", "half", "float", "double",
    "int8", "int16", "int32", "int64", "uint8", "bool", "long", "int", "short",
    "complex64", "complex128",
}

# Modules that give code execution, I/O, network or are known pickle gadgets.
DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "builtins", "__builtin__", "sys",
    "socket", "shutil", "runpy", "importlib", "pty", "webbrowser", "requests",
    "urllib", "http", "ctypes", "pickle", "_pickle", "marshal", "types", "code",
    "codeop", "commands", "platform", "multiprocessing", "threading", "asyncio",
    "pathlib", "io", "tempfile", "telnetlib", "ftplib", "smtplib", "paramiko",
    "dill", "cloudpickle", "operator", "functools", "pdb", "timeit", "trace",
    "profile", "cProfile", "sqlite3", "glob", "torch.hub", "torch.jit",
    "torch.ops", "torch.serialization", "numpy.testing", "pip", "setuptools",
    "distutils", "base64", "zlib", "codecs", "signal", "ssl", "select",
}

SUSPICIOUS_STRING_RE = re.compile(
    r"(https?://|ftp://|/bin/|/usr/bin|/tmp/|/etc/|/dev/tcp|\bcurl\b|\bwget\b|"
    r"\bnc\b|\bncat\b|\bbash\b|\bsh\s+-c|\bpowershell|cmd\.exe|base64|"
    r"\beval\b|\bexec\b|__import__|\bsocket\b|reverse|\.onion|rm\s+-rf|"
    r"\bchmod\b|\bimport\s+\w+|subprocess|os\.system|\bpopen\b|"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)

STANDARD_ZIP_ENTRY_RE = re.compile(
    r"^[^/]+/(data\.pkl|constants\.pkl|version|\.format_version|"
    r"\.storage_alignment|byteorder|data/\d+|\.data/serialization_id|"
    r"\.data/version)$"
)

STR_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
}
CALL_OPS = ("REDUCE", "BUILD", "NEWOBJ", "NEWOBJ_EX", "INST", "OBJ")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, data=None):
    p = subprocess.run(cmd, input=data, capture_output=True)
    return p.returncode, (p.stdout + p.stderr).decode(errors="replace").strip()


def pubkey_info(pubkey):
    rc, der = 1, b""
    p = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", pubkey, "-outform", "DER"],
        capture_output=True,
    )
    if p.returncode == 0:
        der = p.stdout
    _, text = run(["openssl", "pkey", "-pubin", "-in", pubkey, "-noout", "-text"])
    curve = ""
    m = re.search(r"(NIST CURVE:\s*\S+|ASN1 OID:\s*\S+)", text)
    if m:
        curve = m.group(1)
    return {
        "der_sha256": hashlib.sha256(der).hexdigest() if der else "n/a",
        "key_id_der": hashlib.sha256(der).hexdigest()[:16] if der else "n/a",
        "key_id_pem": sha256_file(pubkey)[:16],
        "curve": curve or "unknown",
    }


def is_dangerous(module):
    if not module:
        return False
    return any(module == d or module.startswith(d + ".") for d in DANGEROUS_MODULES)


def is_safe(module, name):
    if (module, name) in SAFE_GLOBALS:
        return True
    if module == "torch" and (name.endswith("Storage") or name in TORCH_DTYPES):
        return True
    return False


def md(s):
    """Make a string safe inside a Markdown table cell / inline code."""
    return str(s).replace("|", "\\|").replace("`", "'").replace("\n", "\\n")


# --------------------------------------------------------------------------- #
# Signature verification (ModelGuard format)
# --------------------------------------------------------------------------- #
def verify_signature(model_path, pubkey, expected_key_ids):
    sig_path = model_path + ".sig.json"
    r = {
        "sig_file": os.path.basename(sig_path),
        "signed": os.path.isfile(sig_path),
        "actual_sha256": sha256_file(model_path),
        "actual_size": os.path.getsize(model_path),
    }
    if not r["signed"]:
        r.update(sig_valid=False, hash_ok=False, size_ok=False, key_id_ok=False,
                 claimed_sha256="-", claimed_size="-", key_id="-",
                 openssl="no signature file", manifest={})
        return r

    with open(sig_path) as f:
        man = json.load(f)
    r["manifest"] = man
    art = man.get("artifact", {})
    r["claimed_sha256"] = art.get("digest", {}).get("value", "")
    r["claimed_size"] = art.get("size", "")
    r["claimed_filename"] = art.get("filename", "")
    r["timestamp"] = man.get("timestamp", "")
    r["algorithm"] = man.get("signature", {}).get("algorithm", "")
    r["key_id"] = man.get("signer", {}).get("keyId", "")
    r["media_type"] = man.get("mediaType", "")

    r["hash_ok"] = r["actual_sha256"] == r["claimed_sha256"]
    r["size_ok"] = r["actual_size"] == r["claimed_size"]
    r["filename_ok"] = r["claimed_filename"] == os.path.basename(model_path)
    r["key_id_ok"] = r["key_id"] in expected_key_ids

    try:
        sig = base64.b64decode(man["signature"]["value"], validate=True)
    except Exception as e:  # malformed signature
        r["sig_valid"] = False
        r["openssl"] = "signature not valid base64: %s" % e
        return r

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(sig)
        sig_tmp = tf.name
    try:
        # ModelGuard signs the hex digest string (verified empirically).
        rc, out = run(
            ["openssl", "dgst", "-sha256", "-verify", pubkey, "-signature", sig_tmp],
            data=r["claimed_sha256"].encode(),
        )
    finally:
        os.unlink(sig_tmp)
    r["sig_valid"] = rc == 0
    r["openssl"] = out.splitlines()[0] if out else ("rc=%d" % rc)
    return r


# --------------------------------------------------------------------------- #
# Static pickle scan (no unpickling)
# --------------------------------------------------------------------------- #
BYTES_OPS = {"SHORT_BINBYTES", "BINBYTES", "BINBYTES8", "BYTEARRAY8"}
B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]{16,}$")


def try_nested_pickle(raw, depth):
    """Return a scan result if `raw` (bytes) is itself a pickle that imports
    something. Catches payloads hidden as an encoded pickle inside a string
    (e.g. _codecs.encode(..., 'latin1') + a custom loader that unpickles it)."""
    if depth >= 4 or len(raw) < 4:
        return None
    candidates = [raw]
    try:
        txt = raw.decode("ascii")
        if B64_RE.match(txt):
            candidates.append(base64.b64decode(txt))
    except Exception:
        pass
    for c in candidates:
        r = scan_pickle_stream(c, depth + 1)
        if not r["error"] and r["globals"]:
            return r
    return None


def scan_pickle_stream(src, depth=0):
    """src: bytes or a binary file object positioned at a pickle."""
    globals_, flagged, counts, nested = [], [], {}, []
    memo, stack = {}, []
    error = None
    proto = None
    try:
        for op, arg, pos in pickletools.genops(src):
            n = op.name
            counts[n] = counts.get(n, 0) + 1
            if n == "PROTO":
                proto = arg
            if n in STR_OPS or n in BYTES_OPS:
                if isinstance(arg, (bytes, bytearray)):
                    raw, s = bytes(arg), bytes(arg).decode("latin-1")
                else:
                    s = str(arg)
                    try:
                        raw = s.encode("latin-1")
                    except UnicodeEncodeError:
                        raw = s.encode("utf-8")
                stack.append(s)
                inner = try_nested_pickle(raw, depth)
                if inner:
                    nested.append((pos, inner))
                if SUSPICIOUS_STRING_RE.search(s):
                    flagged.append("".join(ch if 32 <= ord(ch) < 127 else "." for ch in s)[:300])
            elif n in ("PUT", "BINPUT", "LONG_BINPUT"):
                memo[arg] = stack[-1] if stack else None
            elif n == "MEMOIZE":
                memo[len(memo)] = stack[-1] if stack else None
            elif n in ("GET", "BINGET", "LONG_BINGET"):
                stack.append(memo.get(arg))
            elif n in ("GLOBAL", "INST"):
                mod, _, name = str(arg).partition(" ")
                globals_.append((mod, name, pos, n))
                stack.append(None)
            elif n == "STACK_GLOBAL":
                name = stack[-1] if stack else None
                mod = stack[-2] if len(stack) > 1 else None
                globals_.append((mod or "?", name or "?", pos, n))
                stack.append(None)
            else:
                stack.append(None)
    except Exception as e:
        error = "%s: %s" % (type(e).__name__, e)
    return {"globals": globals_, "flagged": flagged, "counts": counts,
            "error": error, "protocol": proto, "nested": nested}


def scan_model(path):
    res = {"format": None, "entries": [], "nonstandard_entries": [],
           "pickles": {}, "root_dir": None}
    if zipfile.is_zipfile(path):
        res["format"] = "PyTorch zip archive (torch.save >= 1.6)"
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            res["entries"] = [(i.filename, i.file_size) for i in infos]
            roots = {i.filename.split("/", 1)[0] for i in infos}
            res["root_dir"] = ", ".join(sorted(roots))
            res["nonstandard_entries"] = [
                i.filename for i in infos
                if not i.filename.endswith("/")
                and not STANDARD_ZIP_ENTRY_RE.match(i.filename)
            ]
            for i in infos:
                if i.filename.endswith(".pkl") or i.filename.endswith(".pickle"):
                    res["pickles"][i.filename] = scan_pickle_stream(z.read(i))
    else:
        res["format"] = "Raw / legacy pickle stream"
        with open(path, "rb") as f:
            data = f.read()
        buf = io.BytesIO(data)
        for idx in range(5):  # legacy torch format = up to 5 consecutive pickles
            if buf.tell() >= len(data):
                break
            r = scan_pickle_stream(buf)
            res["pickles"]["pickle[%d]@offset" % idx] = r
            if r["error"]:
                break
    return res


def summarise_scan(scan):
    dangerous, unknown, safe = {}, {}, {}
    flagged, errors, nested_found = [], [], []
    call_ops = {k: 0 for k in CALL_OPS}

    def walk(pname, p):
        for mod, name, pos, op in p["globals"]:
            key = "%s.%s" % (mod, name)
            bucket = dangerous if is_dangerous(mod) else (
                safe if is_safe(mod, name) else unknown)
            bucket.setdefault(key, []).append("%s @%s (%s)" % (pname, pos, op))
        flagged.extend("%s: %s" % (pname, s) for s in p["flagged"])
        if p["error"]:
            errors.append("%s: %s" % (pname, p["error"]))
        for k in CALL_OPS:
            call_ops[k] += p["counts"].get(k, 0)
        for pos, inner in p.get("nested", []):
            child = "%s -> nested pickle in string @%s" % (pname, pos)
            nested_found.append(child)
            walk(child, inner)

    for pname, p in scan["pickles"].items():
        walk(pname, p)
    return {"dangerous": dangerous, "unknown": unknown, "safe": safe,
            "flagged": flagged, "errors": errors, "call_ops": call_ops,
            "nested": nested_found}


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #
def classify(v, s, scan):
    reasons = []
    provenance_ok = v["signed"] and v["sig_valid"] and v["hash_ok"] and v["size_ok"]

    if not v["signed"]:
        reasons.append("No signature file - provenance cannot be established.")
    else:
        if not v["sig_valid"]:
            reasons.append("Signature does NOT verify with the TensorTrust Labs public key.")
        if not v["key_id_ok"]:
            reasons.append("Manifest keyId `%s` does not match the TensorTrust key ID." % v["key_id"])
        if not v["hash_ok"]:
            reasons.append("File SHA-256 differs from the signed digest (file modified after signing).")
        if not v["size_ok"]:
            reasons.append("File size differs from the signed size.")

    if s["nested"]:
        reasons.append("A second pickle is hidden inside a string constant and decoded "
                       "at load time (blocklist-evasion technique - generic scanners "
                       "such as modelscan only inspect the outer pickle).")
    if s["dangerous"]:
        reasons.append("Pickle imports dangerous callables: %s." %
                       ", ".join("`%s`" % k for k in s["dangerous"]))
    main_refs = [k for k in s["unknown"] if k.startswith("__main__.")]
    if main_refs:
        reasons.append("References code that is not part of any library (%s) - it only "
                       "resolves if the loading script defines it, typical of a trojan loader."
                       % ", ".join("`%s`" % k for k in main_refs))
    if s["unknown"]:
        reasons.append("Pickle imports non-allowlisted globals: %s." %
                       ", ".join("`%s`" % k for k in s["unknown"]))
    if s["flagged"]:
        reasons.append("Pickle contains %d suspicious string constant(s)." % len(s["flagged"]))
    if s["errors"]:
        reasons.append("Pickle stream could not be fully parsed (possible obfuscation).")
    if scan["nonstandard_entries"]:
        reasons.append("Archive contains non-standard entries: %s." %
                       ", ".join("`%s`" % e for e in scan["nonstandard_entries"]))

    if s["dangerous"]:
        risk, action = "Unsafe", "Do Not Deploy"
        payload = "MALICIOUS"
    elif s["unknown"] or s["flagged"] or s["errors"] or scan["nonstandard_entries"]:
        payload = "SUSPICIOUS"
        risk, action = "Suspicious", "Requires Further Review"
    else:
        payload = "CLEAN"
        risk, action = "Safe", "Deploy"

    if not provenance_ok and payload != "MALICIOUS":
        # Clean content but not provably from TensorTrust Labs.
        risk = "Suspicious"
        action = "Do Not Deploy"
        reasons.append("Payload scan is clean, but deployment policy requires a valid "
                       "TensorTrust Labs signature - re-obtain/re-sign the model from the "
                       "vendor before use.")

    if not reasons:
        reasons.append("Valid TensorTrust Labs signature, integrity confirmed, and only "
                       "standard PyTorch tensor-rebuild globals are referenced.")
    return risk, action, payload, reasons


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def yn(b, yes="Yes", no="No"):
    return yes if b else no


def build_report(results, pubkey, kinfo, models_dir):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    L = []
    L.append("# AI Model Supply-Chain Security Assessment")
    L.append("")
    L.append("| | |")
    L.append("|---|---|")
    L.append("| **Scope** | All model files in `%s/` |" % md(models_dir))
    L.append("| **Trusted signer** | TensorTrust Labs (`%s`) |" % md(os.path.basename(pubkey)))
    L.append("| **Key curve** | %s |" % md(kinfo["curve"]))
    L.append("| **Trusted keyId** (from manifests that verify with this key) | `%s` |" % kinfo["key_id_der"])
    L.append("| **Key fingerprint (SHA-256 DER)** | `%s` |" % kinfo["der_sha256"])
    L.append("| **Date** | %s |" % now)
    L.append("| **Method** | Static analysis only - no model was loaded or unpickled |")
    L.append("")

    # Summary
    L.append("## 1. Executive summary")
    L.append("")
    L.append("| Model | Signed | Signature | Integrity (hash/size) | Payload scan | Risk | Recommended action |")
    L.append("|---|---|---|---|---|---|---|")
    for r in results:
        v = r["verify"]
        L.append("| `%s` | %s | %s | %s | %s | **%s** | **%s** |" % (
            md(r["name"]),
            yn(v["signed"], "Signed", "Unsigned"),
            "-" if not v["signed"] else yn(v["sig_valid"], "Valid", "**Invalid**"),
            "-" if not v["signed"] else yn(v["hash_ok"] and v["size_ok"], "Match", "**Mismatch**"),
            r["payload"], r["risk"], r["action"]))
    L.append("")
    counts = {}
    for r in results:
        counts[r["risk"]] = counts.get(r["risk"], 0) + 1
    L.append("Totals: " + ", ".join("%d %s" % (c, k) for k, c in sorted(counts.items())) + ".")
    L.append("")

    # Methodology
    L.append("## 2. Methodology")
    L.append("")
    L.append("1. **Signature verification.** Each model ships with a ModelGuard manifest "
             "(`<model>.sig.json`, media type `application/vnd.modelguard.signature.v1+json`). "
             "The manifest's ECDSA-P256-SHA256 signature covers the *hex SHA-256 digest string* "
             "of the model. It was verified with `openssl dgst -sha256 -verify signing_key.pub` "
             "against the TensorTrust Labs public key.")
    L.append("2. **Integrity.** Because the signature covers only the claimed digest, the model "
             "file was re-hashed (`sha256sum`) and its size compared with the signed values. "
             "Both must match for the signature to apply to the file on disk.")
    L.append("3. **Signer identity.** The manifest `keyId` was compared with the key ID derived "
             "from the TensorTrust public key.")
    L.append("4. **Payload scan.** Every pickle inside each archive was disassembled with "
             "Python `pickletools` (no execution). All `GLOBAL`/`STACK_GLOBAL`/`INST` imports "
             "were extracted and compared against an allowlist of globals a normal PyTorch "
             "checkpoint needs (`torch._utils._rebuild_tensor_v2`, `collections.OrderedDict`, "
             "`torch.*Storage`, ...). Imports from code-execution / I/O / network modules "
             "(`os`, `posix`, `subprocess`, `builtins`, `socket`, `runpy`, ...) are classed as "
             "malicious. String constants were searched for commands, URLs and IPs.")
    L.append("5. **Classification.** *Unsafe* = malicious payload (Do Not Deploy). "
             "*Suspicious* = unexplained globals/strings (Requires Further Review), or clean "
             "content without valid TensorTrust provenance (Do Not Deploy). *Safe* = valid "
             "signature, matching hash, only standard globals (Deploy).")
    L.append("")

    # Per model
    L.append("## 3. Detailed findings")
    for r in results:
        v, s, scan = r["verify"], r["summary"], r["scan"]
        L.append("")
        L.append("### %s - %s / %s" % (r["name"], r["risk"], r["action"]))
        L.append("")
        L.append("**Assessment rationale**")
        L.append("")
        for reason in r["reasons"]:
            L.append("- " + reason)
        L.append("")
        L.append("**Signature & integrity evidence**")
        L.append("")
        L.append("| Check | Expected / signed | Observed | Result |")
        L.append("|---|---|---|---|")
        L.append("| Signature file | `%s` | %s | %s |" % (
            md(v["sig_file"]), yn(v["signed"], "present", "missing"), yn(v["signed"], "PASS", "FAIL")))
        if v["signed"]:
            L.append("| ECDSA signature (TensorTrust key) | Verified OK | %s | %s |" % (
                md(v["openssl"]), yn(v["sig_valid"], "PASS", "**FAIL**")))
            L.append("| Signer keyId | `%s` | `%s` | %s |" % (
                kinfo["key_id_der"], md(v["key_id"]), yn(v["key_id_ok"], "PASS", "**FAIL**")))
            L.append("| SHA-256 | `%s` | `%s` | %s |" % (
                md(v["claimed_sha256"]), v["actual_sha256"], yn(v["hash_ok"], "PASS", "**FAIL**")))
            L.append("| Size (bytes) | %s | %s | %s |" % (
                md(v["claimed_size"]), v["actual_size"], yn(v["size_ok"], "PASS", "**FAIL**")))
            L.append("| Filename in manifest | `%s` | `%s` | %s |" % (
                md(v.get("claimed_filename", "")), md(r["name"]),
                yn(v.get("filename_ok"), "PASS", "WARN")))
            L.append("| Signature algorithm | ECDSA-P256-SHA256 | %s | info |" % md(v.get("algorithm", "")))
            L.append("| Signed timestamp | - | %s | info |" % md(v.get("timestamp", "")))
        else:
            L.append("| SHA-256 (observed) | - | `%s` | info |" % v["actual_sha256"])
        L.append("")

        L.append("**Payload scan evidence**")
        L.append("")
        L.append("- Format: %s; archive root folder: `%s`; pickles scanned: %s" % (
            scan["format"], md(scan["root_dir"] or "-"),
            ", ".join("`%s`" % md(p) for p in scan["pickles"]) or "none"))
        L.append("- Object-construction opcodes: " + ", ".join(
            "%s=%d" % (k, c) for k, c in s["call_ops"].items() if c) )
        if scan["root_dir"] and r["name"].rsplit(".", 1)[0] != scan["root_dir"]:
            L.append("- Note: archive root folder `%s` differs from the file name "
                     "(the archive was created under a different name)." % md(scan["root_dir"]))
        L.append("")
        L.append("| Imported global | Classification | Occurrences (pickle @ byte offset) |")
        L.append("|---|---|---|")
        for label, bucket in (("**MALICIOUS**", s["dangerous"]),
                              ("**Not allowlisted**", s["unknown"]),
                              ("Standard PyTorch", s["safe"])):
            for g, occ in sorted(bucket.items()):
                shown = "; ".join(occ[:3]) + (" (+%d more)" % (len(occ) - 3) if len(occ) > 3 else "")
                L.append("| `%s` | %s | %s |" % (md(g), label, md(shown)))
        if not (s["dangerous"] or s["unknown"] or s["safe"]):
            L.append("| (none) | - | - |")
        L.append("")
        if s["flagged"]:
            L.append("Suspicious string constants found in the pickle:")
            L.append("")
            L.append("```")
            for f in s["flagged"][:20]:
                L.append(f)
            L.append("```")
            L.append("")
        if s["nested"]:
            L.append("Hidden (nested) pickles decoded from string constants:")
            L.append("")
            for nloc in s["nested"]:
                L.append("- `%s`" % md(nloc))
            L.append("")
        if s["errors"]:
            L.append("Parser errors: " + "; ".join("`%s`" % md(e) for e in s["errors"]))
            L.append("")
        if scan["nonstandard_entries"]:
            L.append("Non-standard archive entries: " + ", ".join(
                "`%s`" % md(e) for e in scan["nonstandard_entries"]))
            L.append("")

    # Recommendations
    L.append("## 4. Recommendations")
    L.append("")
    L.append("1. Deploy only models classed **Safe**; quarantine the rest and report "
             "**Unsafe** models to TensorTrust Labs as a supply-chain incident.")
    L.append("2. Never `torch.load()` untrusted checkpoints. Use `torch.load(..., weights_only=True)` "
             "(default since PyTorch 2.6) or convert models to `safetensors`, which cannot carry code.")
    L.append("3. A valid signature proves *who* published a file, not that it is *safe*: run the "
             "payload scan even on correctly signed models.")
    L.append("4. Fix the ModelGuard verifier design: sign the file contents (or a canonical manifest "
             "that is always re-hashed by the verifier), pin the trusted key by fingerprint rather "
             "than trusting the `keyId` in the manifest, and fail closed on any mismatch.")
    L.append("5. Add this check to the CI/CD gate so unsigned or tampered models are rejected "
             "automatically.")
    L.append("")
    L.append("## Appendix - reproduction commands")
    L.append("")
    L.append("```bash")
    L.append("# signature over the signed digest string")
    L.append("jq -j .artifact.digest.value models/<m>.sig.json | openssl dgst -sha256 -verify signing_key.pub \\")
    L.append("  -signature <(jq -r .signature.value models/<m>.sig.json | base64 -d)")
    L.append("# integrity")
    L.append("sha256sum models/<m>; stat -c %s models/<m>")
    L.append("# static pickle disassembly (never torch.load untrusted files)")
    L.append("unzip -p models/<m> '*/data.pkl' | python3 -I -m pickletools - | grep -E 'GLOBAL|REDUCE'")
    L.append("```")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models-dir", default="models")
    ap.add_argument("--pubkey", default="signing_key.pub")
    ap.add_argument("--out", default="security_report.md")
    a = ap.parse_args()

    kinfo = pubkey_info(a.pubkey)
    expected_ids = {kinfo["key_id_der"], kinfo["key_id_pem"]}

    models = sorted(
        os.path.join(a.models_dir, f) for f in os.listdir(a.models_dir)
        if f.lower().endswith(MODEL_EXTS) and not f.endswith(".sig.json")
    )
    verified = [(m, verify_signature(m, a.pubkey, expected_ids)) for m in models]
    # ModelGuard's keyId derivation is undocumented: learn the trusted keyId(s)
    # from manifests whose signature verifies with the pinned public key.
    learned = {v["key_id"] for _, v in verified if v.get("sig_valid") and v.get("key_id")}
    if learned:
        expected_ids |= learned
        kinfo["key_id_der"] = ", ".join(sorted(learned))
    for _, v in verified:
        if v["signed"]:
            v["key_id_ok"] = v["key_id"] in expected_ids

    results = []
    for m, v in verified:
        scan = scan_model(m)
        s = summarise_scan(scan)
        risk, action, payload, reasons = classify(v, s, scan)
        results.append({"name": os.path.basename(m), "verify": v, "scan": scan,
                        "summary": s, "risk": risk, "action": action,
                        "payload": payload, "reasons": reasons})
        print("%-22s signed=%-5s sig=%-5s hash=%-5s payload=%-10s -> %s / %s" % (
            os.path.basename(m), v["signed"], v.get("sig_valid"), v.get("hash_ok"),
            payload, risk, action))
        for g in s["dangerous"]:
            print("    MALICIOUS global: %s" % g)
        for g in s["unknown"]:
            print("    non-allowlisted : %s" % g)
        for f in s["flagged"][:5]:
            print("    string          : %s" % f[:120])

    with open(a.out, "w") as f:
        f.write(build_report(results, a.pubkey, kinfo, a.models_dir))
    print("\nReport written to %s" % a.out)
    print("TensorTrust key ID: %s" % kinfo["key_id_der"])


if __name__ == "__main__":
    main()
