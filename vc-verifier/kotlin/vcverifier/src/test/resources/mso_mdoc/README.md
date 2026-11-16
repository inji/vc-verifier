# mso_mdoc test data

## Static mDL samples (passing cases)

Each `mdl-*.b64url` file holds one base64url string (no padding). All data is fictional.

| File | What it is | Expected result |
|---|---|---|
| `mdl-valid.b64url` | Shape A `{issuerAuth, nameSpaces}` with the 11 mandatory mDL elements | Passes |
| `mdl-shape-b.b64url` | Shape B `{docType, issuerSigned}`, same content | Passes |
| `mdl-shape-c.b64url` | Shape C `{documents: [ … ]}`, same content | Passes |
| `mdl-expired.b64url` | `validFrom` 2024-11-16, `validUntil` 2026-11-15 | `true` + `ERR_VC_EXPIRED` |
| `mdl-missing-ds-eku.b64url` | Real Certify mDL; DS certificate lacks the mDL EKU, mandatory elements missing | Fails |

Dates of the passing samples: `signed` = `validFrom` = 2026-11-15T00:00:00Z, `validUntil` =
2031-11-16T00:00:00Z, `issue_date` the day before `validFrom`. **Regenerate the set before 2031-11-16.**

All samples except `mdl-missing-ds-eku` are signed with the test key `test_ds_key_pkcs8.pem`. The DS
certificate is in `mdl-sample-ds-cert.pem`:

- Subject `C=IN, ST=KA, O=vc-verifier test, CN=vc-verifier TEST Document Signer - NOT FOR PRODUCTION`
- EC P-256, ES256, valid 2024-01-01 to 2036-01-01
- KeyUsage `digitalSignature` and EKU `1.0.18013.5.1.2`, both critical

### Regenerate

The samples are generated outside the tests and committed as static files; no generator script is
kept in the repo. Regenerate and re-sign them as a set (for example with a throwaway test that calls
`MdlEdgeCaseTestDataGenerator.create(...)` with a fixed clock, then deleted). Before committing, check
that `mdl-valid`, `mdl-shape-b` and `mdl-shape-c` pass and `mdl-expired` returns `ERR_VC_EXPIRED`
through `CredentialsVerifier.verify` in both strict and relaxed mode.

These samples follow the layout of the inji-verify `verify-core/src/test/resources/mdl-samples` set.
That set could not be used as-is: its `issue_date` is a day after `validFrom`, and the expired sample's
`signed` is before the DS certificate's `notBefore`, so both fail checks this library makes.

## Other files

- `test_ds_key_pkcs8.pem`, `test_ds_mdl.pem`, `test_ds_no_key_usage.pem`: test DS key and
  certificates used by `MdlEdgeCaseTestDataGenerator` for failing and edge cases.
