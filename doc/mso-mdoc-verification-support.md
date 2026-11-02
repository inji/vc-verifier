# Support for ISO/IEC 18013-5 mso_mdoc (mDL)

This document describes how **vc-verifier** validates and verifies `mso_mdoc` credentials
(Mobile Security Object / mobile Driving Licence) encoded as **base64url CBOR** with a
**COSE_Sign1** `issuerAuth`.

Related: [GitHub issue #300](https://github.com/inji/vc-verifier/issues/300),
[inji-certify#1123](https://github.com/inji/inji-certify/issues/1123) (ISO-conformant issuer fixtures).

---

## Input encoding

- Credential string must be **base64url** (no padding required) over CBOR.
- **Base45** (QR transport) is **not** accepted; callers must decode Base45 (/zlib) first if needed.

## Input shapes (`MsoMdocVerifiableCredential.parse`)

| Shape | Structure | `isLatest` |
|---|---|---|
| **A** (OpenID4VCI 1.0) | `{ issuerAuth, nameSpaces }` | `true` |
| **B** (legacy) | `{ docType, issuerSigned: { issuerAuth, nameSpaces } }` | `false` |
| **C** (legacy) | `{ documents: [ { docType, issuerSigned } ] }` (only `documents[0]`) | `false` |

Detection order: C → B → A.

---

## Validation (`MsoMdocValidator`)

- Mandatory MSO fields: `version`, `digestAlgorithm`, `valueDigests`, `deviceKeyInfo`, `docType`, `validityInfo`
- `version` major version must be `1` (for example, `"1.0"` or `"1.1"`)
- `digestAlgorithm` must be `SHA-256`, `SHA-384`, or `SHA-512`
- `validityInfo` dates (`validFrom`, `validUntil`, and `signed` when latest): no fractional seconds, must end in `Z`
- `validFrom` must not be in the future (3s skew via `DateUtils`)
- `validUntil` must be after `validFrom`
- Past `validUntil` → soft failure `ERR_VC_EXPIRED` (same pattern as other formats)
- For **shape A only**: `signed` required; `validFrom` must not be before `signed`; MSO payload must be tag-24

## Verification (`MsoMdocVerifier`)

Order of checks:

1. COSE protected header must contain `alg` and the value must be ES256 (`-7`), ES384 (`-35`), or ES512 (`-36`); other algs (incl. EdDSA) → `ERR_INVALID_ALG`
2. DS certificate from `x5chain`: within `notBefore` / `notAfter`
3. For `docType` `org.iso.18013.5.1.mDL` **when `mdocStrictProfile=true` (default)**:
   - KeyUsage includes `digitalSignature` and is critical
   - ExtendedKeyUsage includes `1.0.18013.5.1.2` and is critical
4. MSO `signed` falls within DS certificate validity **when `signed` is present**. For shapes B/C, `signed` is optional today (pending confirmation of issue #300 §2 #8); if absent, this check is skipped
5. COSE signature verifies with DS public key. This does **not** establish IACA trust (`verifyCertificateChain` is currently a no-op / out of scope)
6. Value digests: each received `nameSpaces` record is tag-24; hash the **exact on-the-wire** `IssuerSignedItemBytes`; `digestID` &lt; 2³¹; `random` ≥ 16 bytes; match MSO digests; reject duplicate `digestID`s; MSO digests without a received record are allowed (selective disclosure)
7. Credential `docType` matches MSO `docType` (legacy shapes). Shape C still uses only `documents[0]` (spike: multi-doc later)
8. For mDL: if `issuing_country` is disclosed it must match DS `C` (via BouncyCastle `X500Name`); `issuing_jurisdiction` matches `ST` when both present; `issue_date` (if disclosed) must be a valid full date and not after `validFrom`
9. For mDL **when `mdocStrictProfile=true`**: ISO Table 5 field types/structure, Latin-1 ≤150 for text fields, age consistency vs `birth_date` at `validFrom`, and **mandatory field presence only for a full issued credential** (every MSO digest for `org.iso.18013.5.1` is present in `nameSpaces`). Selective disclosure skips §3.4

Use `CredentialsVerifier.verify(..., mdocStrictProfile = false)` to temporarily relax EKU + §3 field checks for non-conformant Certify fixtures (issue #300).

## Out of scope

- IACA trust chain / CRL
- IACA ↔ DS `countryName` match
- EdDSA (ES384/ES512 are supported)
- DeviceResponse / holder `deviceKey` presentation binding

## Pending confirmation (issue #300 §2.7 and §2.8)

- Require MSO tag-24 for **all** shapes (currently shape A only)
- Require `validFrom` ≥ `signed` for **all** shapes (currently shape A only)

## Error codes

See `CredentialValidatorConstants` and the **mso_mdoc Format VC Error Codes** table in
[`vc-verifier/kotlin/README.md`](../vc-verifier/kotlin/README.md).

## Test fixtures

ISO-conformant pass-path fixtures (DS EKU `1.0.18013.5.1.2`, mandatory mDL claims including
`issuing_country`) are tracked on the Certify side. Until they land, success-path verifier tests
remain `@Disabled`. Fail-path and structural validator tests run without those fixtures.
