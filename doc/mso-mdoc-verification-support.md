# mso_mdoc (mDL) validation and verification

vc-verifier checks `mso_mdoc` credentials (ISO/IEC 18013-5) sent as **base64url CBOR** with a
COSE_Sign1 `issuerAuth`. Base45 (QR transport) is not accepted.

Related: [vc-verifier#300](https://github.com/inji/vc-verifier/issues/300) (these checks),
[vc-verifier#302](https://github.com/inji/vc-verifier/issues/302) (ES384 / ES512 / EdDSA).

## Credential shapes

| Shape | Structure |
|---|---|
| A (OpenID4VCI 1.0) | `{ issuerAuth, nameSpaces }` |
| B (legacy) | `{ docType, issuerSigned: { issuerAuth, nameSpaces } }` |
| C (legacy) | `{ documents: [ { docType, issuerSigned } ] }` (only `documents[0]`) |

Every check below runs for all three shapes. The shape only decides where `issuerSigned` is found,
and for B and C the outer `docType` must match the MSO `docType`.

## How the checks are organised

| Step | Generic mdoc checks | mDL checks (`docType` = `org.iso.18013.5.1.mDL`) |
|---|---|---|
| Validation (before the signature) | `MsoMdocValidator` | `MdlValidator` |
| Verification (signature and after) | `MsoMdocVerifier` | `MdlVerifier` |

The docType checks are chosen by the MSO `docType` (`MdocDocTypes`). A docType with no entry gets only
the generic checks, so a new mdoc type (for example EU PID) adds its own validator and verifier.

## Sequence

### 1. Validation

1. Decode base64url and CBOR; find `issuerAuth` and `nameSpaces` for shape A, B or C.
2. The MSO payload is tag 24 (`#6.24(bstr .cbor MobileSecurityObject)`).
3. The MSO has `version` (`1.<minor>`), `digestAlgorithm` (SHA-256 / 384 / 512), `valueDigests`
   (ISO layout, digestIDs < 2³¹), `deviceKeyInfo`, `docType` and `validityInfo`.
4. `validityInfo`: `signed`, `validFrom` and `validUntil` are present, tag 0, `YYYY-MM-DDThh:mm:ssZ`;
   `signed` and `validFrom` are not in the future; `validFrom` ≥ `signed`; `validUntil` > `validFrom`.
5. **mDL only** (`MdlValidator`):
   - mandatory elements are present, when the whole mDL namespace is disclosed
   - `driving_privileges` structure
   - listed text elements are printable Latin-1, at most 150 characters
   - age claims agree with `birth_date`
   - `issue_date` is a full-date or tdate and not after `validFrom`
   - element types (ISO Table 5), **strict mode only**
6. If `validUntil` is in the past, return the soft error `ERR_VC_EXPIRED`. This comes last, so an
   expired credential still gets every check above.

### 2. Verification

1. The COSE protected header has `alg` = ES256, and the DS certificate key is EC P-256.
2. The DS certificate (from `x5chain`) is within `notBefore` / `notAfter`.
3. The MSO `signed` falls within the DS certificate validity.
4. The COSE signature verifies with the DS certificate key. (IACA trust is not checked yet.)
5. Value digests, for each received item: tag 24, `digestID` < 2³¹, `random` ≥ 16 bytes, no duplicate
   `digestID` or `elementIdentifier` in a namespace, and the digest of the item bytes exactly as received
   matches the MSO. A mismatch or an item the MSO does not know is `ERR_LIKELY_TAMPERED`. MSO digests with
   no received item are fine (selective disclosure).
6. Shapes B and C: the outer `docType` matches the MSO `docType`.
7. **mDL only** (`MdlVerifier`):
   - DS certificate KeyUsage `digitalSignature` and EKU `1.0.18013.5.1.2`, both critical (ISO Table B.3),
     **strict mode only**
   - a disclosed `issuing_country` matches the DS certificate `C`
   - `issuing_jurisdiction` matches `ST` when both are present

### Result through `CredentialsVerifier.verify`

- Validation fails (other than expiry) → `false` with that error code.
- Expired, and verification passes → `true` with `ERR_VC_EXPIRED`.
- Verification fails → `false` with that error code.

Error codes are listed in the **mso_mdoc Format VC Error Codes** table in
[`vc-verifier/kotlin/README.md`](../vc-verifier/kotlin/README.md).

## Clock

All comparisons against "now" use `MsoMdocVerificationOptions.currentTimeMillis` and a 3 second
tolerance in the credential's favour. `signed` against the DS certificate compares two issuer
timestamps, so it has no tolerance.

## Strict mode

`CredentialsVerifier.verify(..., mdocStrictProfile = false)` relaxes only two mDL checks: the DS
KeyUsage/EKU check and the element type checks. Everything else always runs; in relaxed mode a value
of the wrong type is skipped by the other mDL checks rather than reported. The flag defaults to `true`
and is temporary, until Inji Certify issues conformant mDLs
([inji-certify#1132](https://github.com/inji/inji-certify/issues/1132) DS EKU,
[inji-certify#1147](https://github.com/inji/inji-certify/issues/1147) element types).

## Known limits

- Mandatory elements are checked only when the whole mDL namespace is disclosed: the verifier cannot
  tell "hidden by the holder" from "never issued".
- Not checked: IACA trust chain / CRL, IACA ↔ DS country, ES384 / ES512 / EdDSA, DeviceResponse
  holder binding, other mdoc docTypes' field rules.

## Release notes

- mDL field checks now run during validation, before the signature and digests. A tampered element
  of the wrong type therefore reports `ERR_INVALID_MDL_ELEMENT` instead of `ERR_LIKELY_TAMPERED`
  (as for LDP), and an expired mDL with a field problem reports the field error, not `ERR_VC_EXPIRED`.
- The DS KeyUsage/EKU check now runs after the signature and digests, so a credential that fails both
  reports the signature or digest error first.
- A malformed COSE protected header returns the new code `ERR_INVALID_PROTECTED_HEADER` (was `ERR_MISSING_ALG`).
- The public `IssuerSignedNamespaces.extractFieldValue` extension was removed (unused).
- Tampering returns `ERR_LIKELY_TAMPERED` (`LikelyTamperedException(errorMessage, errorCode)`).
  Expired + tampered also returns `ERR_LIKELY_TAMPERED`.
- An mDL past `validUntil` that otherwise verifies returns `true` with `ERR_VC_EXPIRED` (was `false`
  with `ERR_INVALID_VALID_UNTIL_MSO`). Show it as "expired", not "valid".
- `signed` is mandatory, `validFrom` ≥ `signed`, MSO tag 24 and `validityInfo` tag 0 apply to every shape.
- Only ES256 with an EC P-256 DS key is accepted (`ERR_INVALID_ALG`).
- The non-ISO `valueDigests.nameSpaces` wrapper is rejected (`ERR_INVALID_MSO`).
- `MsoMdocVerificationOptions` gains `currentTimeMillis`; `Util.calculateDigest` was removed.

## Test data

- **Static samples** (`vcverifier/src/test/resources/mso_mdoc/mdl-*.b64url`) are used for passing
  cases; see the README in that folder.
- **`MdlEdgeCaseTestDataGenerator`** (tests only) builds signed credentials for failing and boundary
  cases: tampering, custom certificates, encoding and algorithm defects, exact validity limits.
