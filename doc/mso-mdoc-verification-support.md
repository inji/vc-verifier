# mso_mdoc (mDL) verification

vc-verifier checks issuer-signed `mso_mdoc` credentials (ISO/IEC 18013-5) given as
base64url CBOR. Base45 (QR transport) is not accepted.

## Accepted shapes

| Shape | Structure |
|---|---|
| A | `{ issuerAuth, nameSpaces }` |
| B | `{ docType, issuerSigned: { issuerAuth, nameSpaces } }` |
| C | `{ documents: [ { docType, issuerSigned } ] }`, only `documents[0]` is used |

All checks run for every shape.

## Checks

**Validation (before the signature)**

| Check | Rule |
|---|---|
| MSO | Tag 24; `version` is `1.x`; `digestAlgorithm` is SHA-256, SHA-384 or SHA-512; `valueDigests`, `deviceKeyInfo`, `docType`, `validityInfo` present |
| Dates | `signed`, `validFrom`, `validUntil` are tag 0, `YYYY-MM-DDThh:mm:ssZ`, no fractional seconds |
| Validity | `signed` and `validFrom` not in the future; `validFrom` ≥ `signed`; `validUntil` > `validFrom` |
| Expiry | `validUntil` in the past gives the soft error `ERR_VC_EXPIRED`, reported after all other validation checks |

**Verification**

| Check | Rule |
|---|---|
| Algorithm | `alg` is ES256 in the protected header; DS key is EC P-256 |
| DS certificate | Valid now; `signed` falls inside its validity period |
| Signature | COSE signature verifies with the DS certificate key |
| Digests | Each received item is tag 24, has `digestID` < 2³¹ and `random` ≥ 16 bytes, and its bytes as received match the MSO digest. No duplicate `digestID` or `elementIdentifier` in a namespace. Items the holder did not share are fine |
| docType | Shapes B and C: the outer `docType` matches the MSO `docType` |

**mDL only** (`docType` = `org.iso.18013.5.1.mDL`)

| Check | Rule | Strict only |
|---|---|---|
| Mandatory elements | All 11 present, when the whole mDL namespace is shared | |
| `driving_privileges` | ISO structure | |
| Text elements | Latin-1, at most 150 characters | |
| Control characters | Not allowed in those text elements | Yes |
| Age claims | Agree with `birth_date`, with one day of slack | |
| `issue_date` | Not more than one day after the UTC date of `validFrom` | |
| Element types | ISO Table 5 | Yes |
| DS certificate profile | Critical KeyUsage `digitalSignature` and EKU `1.0.18013.5.1.2` | Yes |
| Issuer | `issuing_country` = certificate `C`; `issuing_jurisdiction` = `ST` when both exist | |

The one day of slack covers issuers that write their local date, which can differ from
the UTC date of the MSO timestamps.

## Result

| Case | `verificationStatus` | Code |
|---|---|---|
| All checks pass | `true` | none |
| Expired, everything else passes | `true` | `ERR_VC_EXPIRED` |
| Any other check fails | `false` | that check's code |

Treat `true` with `ERR_VC_EXPIRED` as expired, not valid. Error codes are listed in
[`vc-verifier/kotlin/README.md`](../vc-verifier/kotlin/README.md).

Time comparisons against "now" allow 3 seconds of clock difference.

## Strict mode

`CredentialsVerifier.verify(..., mdocStrictProfile = false)` turns off the three checks
marked "Strict only" above. Everything else always runs. The flag defaults to `true` and
is temporary, until Inji Certify issues conformant mDLs.

## Not checked

- IACA trust chain and CRL: the DS certificate is not validated against a trusted root
- ES384, ES512, EdDSA
- Device authentication (holder binding) for presentations
- Field rules for docTypes other than mDL
