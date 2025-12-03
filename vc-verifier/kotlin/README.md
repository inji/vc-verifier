# VC Verifier (Kotlin)

## Table of Contents

1. [Overview](#1-overview)
2. [Supported Formats](#2-supported-formats)
    - 2.1 [Verifiable Credential (VC) Formats](#21-verifiable-credential-vc-formats)
    - 2.2 [Verifiable Presentation (VP) Format](#22-verifiable-presentation-vp-format)
3. [Validation Flow](#3-validation-flow)
    - 3.1 [LDP VC Validation](#31-ldp-vc-validation)
    - 3.2 [MSO MDOC Validation](#32-mso-mdoc-validation)
    - 3.3 [SD-JWT VC Validation](#33-sd-jwt-vc-validation)
4. [Verification Flow](#4-verification-flow)
    - 4.1 [Supported VC Formats and Signature Mechanisms](#41-supported-vc-formats-and-signature-mechanisms)
    - 4.2 [Verifiable Presentation (VP) Verification](#42-verifiable-presentation-vp-verification)
5. [Credential Status Check](#5-credential-status-check)
6. [API Overview](#6-api-overview)
    - 6.1 [Credential Verifier](#61-credential-verifier)
    - 6.2 [Presentation Verifier](#62-presentation-verifier)
7. [Public Key Extraction](#public-key-extraction)
8. [Error Codes](#error-codes)

---

## 1. Overview

The VC Verifier Kotlin Module is designed to validate, verify, and check the status of Verifiable
Credentials (VCs) and Verifiable Presentations (VPs) across multiple formats. It ensures conformance
to open standards (W3C, IETF, ISO) and provides granular error codes to help consuming systems
handle trust decisions reliably.

## 2. Supported Formats

### 2.1 Verifiable Credential (VC) Formats

The verifier supports multiple VC formats in alignment with global standards:

| Format                   | Description                                                                                                                                        |
|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| `ldp_vc`                 | W3C Linked Data Proof Verifiable Credentials [(v2.0)](https://www.w3.org/TR/vc-data-model-2.0/) ([v1.1](https://www.w3.org/TR/vc-data-model-1.1/)) |
| `mso_mdoc`               | ISO/IEC 18013-5 compliant mobile documents                                                                                                         |
| `vc+sd-jwt`, `dc+sd-jwt` | [IETF SD-JWT based Verifiable Credentials](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/10/)                                        |

🔸 Each format includes validation and cryptographic verification logic tailored to its respective
data model and proof structure.

### 2.2 Verifiable Presentation (VP) Format

Currently, only Verifiable Presentations containing `ldp_vc` credentials are supported.

* The verifier processes both the VP proof and each embedded VC.
* Support for presentations containing other VC formats (e.g., `vc+sd-jwt`) is planned for future
  versions.

## 3. Validation Flow

Validation is the first step in verifying a Verifiable Credential (VC). It is performed based on the
credential's format and ensures structural integrity, temporal correctness, and conformance to data
model specifications before signature verification begins.

Each format has a dedicated validator:

* `LdpValidator` for LDP VC
* `MsoMdocValidator` for MSO MDOC
* `SdJwtValidator` for SD-JWT VC/DC

⚠️ **Note:** The details below summarize major validation flows. These are not exhaustive. Please
refer to the implementation classes for complete rules.

### 3.1 LDP VC Validation

* **Context-based routing:** Uses `@context` to determine if the VC follows Data Model 1.1 or 2.0
* **Mandatory field checks:**
    * Common: `@context`, `type`, `credentialSubject`, `issuer`, `proof`
    * v1.1 specific: `issuanceDate`
    * v2.0 specific: `validUntil`, plus additional semantic fields like `name`, `description`
* **Nested field validations:**
    * Fields like `credentialStatus`, `credentialSchema`, `refreshService`, and `termsOfUse` are
      validated for structure and presence of `id`, `type`
* **Proof validation:** Structure and supported algorithms checked via
  `validationHelper.validateProof(...)`
* **Temporal checks:** Validates future `issuanceDate`, expired `expirationDate`, and `validFrom`/
  `validUntil` logic via `DateUtils`
* **Validation class:** `LdpValidator`

### 3.2 MSO MDOC Validation

* Parses CBOR MSO structure using `MsoMdocVerifiableCredential().parse(...)`
* **Validates the `validityInfo` block:**
    * `validFrom` should not be in future
    * `validUntil` should not be in past
    * `validUntil > validFrom` must hold
* Field access uses a CBOR helper operator `DataItem["validFrom"]`
* Exceptions thrown for any date inconsistencies
* **Validation class:** `MsoMdocValidator`

### 3.3 SD-JWT VC Validation

* Parses SD-JWT using `SDJWT.parse(...)`, extracting:
    * Credential JWT
    * Disclosures
    * Key Binding JWT (KB-JWT) if present
* **JWT Header validation:**
    * Validates `alg` (no "none", must be supported)
    * Validates `typ` as one of `vc+sd-jwt` or `dc+sd-jwt`
* **Payload validation:**
    * Required claims: `vct`, `iss`, `_sd_alg`
    * Temporal claims: `iat`, `nbf`, `exp`
    * URI fields: `aud`, `nonce`
    * Confirmation (`cnf`) must contain valid `jwk` or `kid` (but not both)
* **Disclosure validation:**
    * Validates structure and formats
    * Confirms hash of each disclosure matches `_sd` array
* **Key Binding JWT validation:**
    * Verifies header format (`alg`, `typ`)
    * Validates and matches `sd_hash`
    * Verifies signature using resolved key from `cnf`
* **Validation class:** `SdJwtValidator`

## 4. Verification Flow

Verification confirms that the credential or presentation was cryptographically signed by the issuer
or holder, ensuring data integrity and authenticity. The process varies for Verifiable Credentials (
VCs) and Verifiable Presentations (VPs).

### 4.1 Supported VC Formats and Signature Mechanisms

The VC Verifier supports multiple credential formats, each with its own signature mechanism,
cryptographic algorithm set, and proof suite. These formats align with major specifications
including [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/), ISO/IEC 18013-5,
and [IETF SD-JWT](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/).

#### Supported VC Formats and Their Signature Mechanisms

| VC format   | Issuer Signature Mechanism                                             | Verification Algorithms             | Signature Suites / Proof Types                                                            |
|-------------|------------------------------------------------------------------------|-------------------------------------|-------------------------------------------------------------------------------------------|
| `ldp_vc`    | Linked Data Proof                                                      | PS256, RS256, EdDSA (Ed25519)       | RsaSignature2018, Ed25519Signature2018, Ed25519Signature2020, EcdsaSecp256k1Signature2019 |
| `mso_mdoc`  | COSE (CBOR Object Signing and Encryption)                              | ES256                               | Uses COSE_Sign1                                                                           |
| `vc+sd-jwt` | X.509 Certificate (Currently, JWT VC Issuer Metadata is not supported) | PS256, RS256,ES256, EdDSA (Ed25519) |                                                                                           |
| `dc+sd-jwt` | X.509 Certificate (Currently, JWT VC Issuer Metadata is not supported) | PS256, RS256,ES256, EdDSA (Ed25519) |                                                                                           |

### 4.2 Verifiable Presentation (VP) Verification

Verifiable Presentations (VPs) are structured containers through which holders present one or more
Verifiable Credentials (VCs), optionally signed with their own DID-based proof of control.

This module supports VPs containing `ldp_vc` credentials, following
the [W3C Verifiable Credentials specification](https://www.w3.org/TR/vc-data-model-2.0/).

### Supported Features

| Feature                  | Support Status                                                       |
|--------------------------|----------------------------------------------------------------------|
| VP credential format     | `ldp_vc` only                                                        |
| VP proof types           | `Ed25519Signature2018` `Ed25519Signature2020` `JsonWebSignature2020` |
| Supported DID methods    | `did:web`, `did:key`, `did:jwk`                                      |
| Embedded VC verification | Full validation, credential status check and signature verification  |

### Verification Flow

1. **Top-level Proof Verification**

* The VP's `proof` is validated using the holder's DID verification method.
* Signature type and algorithm must be supported.

2. **Embedded VC Processing**

* Each credential inside the VP is processed using the VC validation + verification pipeline.
* Only `ldp_vc` credentials are currently supported inside VPs.

3. **Result Aggregation**

* Returns a combined result with:
    * VP-level proof verification status
    * Per-VC signature verification status results (`valid`, `invalid`, `expired`)
    * Status check results if applicable

📌 Refer to the Public API for method usage and detailed response schema.

⚠️ **Note:** Due to the removal of `presentation_submission` from OpenID4VP drafts, the verifier
returns the entire VC string in the response. Referencing VCs by ID is not currently feasible.

## 5. Credential Status Check

The VC Verifier library performs status verification on Verifiable Credentials (VCs) using
the [W3C StatusList2021 specification](https://www.w3.org/TR/vc-status-list/). It currently supports
BitstringStatusListEntry-based status entries, enabling decentralized revocation and suspension.

### ✅ Supported Status Format

* ✅ `type: BitstringStatusListEntry`
* ✅ `encodedList` in GZIP + Base64URL
* ✅ Multi-bit support (`statusSize` > 1)

### ⚙️ Status Check Flow

For each `credentialStatus` entry:

1. **Purpose Filtering**

* Only entries matching the requested `statusPurpose` are evaluated.

2. **Input Field Validation**

* Checks for presence and validity of:
    * `statusListCredential` (must be a valid URL)
    * `statusListIndex` (≥ 0)
    * `statusSize` (optional, defaults to 1)

3. **Status List Retrieval**

* Downloads and verifies the referenced `statusListCredential` VC:
    * Validates signature and VC structure
    * Ensures VC is within `validFrom` and `validUntil` range

4. **Bit Extraction**

* Decodes `encodedList` and extracts `statusSize` number of bits starting from `statusListIndex`
* Computes integer value:
    * `0` → ✅ Valid
    * `> 0` → ❌ Not valid for the given purpose

### Result Structure

The result is a map of status check summaries per purpose:

```kotlin
Map<String, CredentialStatusResult>
```

Where `CredentialStatusResult` is defined as:

```kotlin

data class CredentialStatusResult(
    val isValid: Boolean,
    val error: StatusCheckException?
)
```

| Purpose      | Use Case        | `isValid` | `error`                           | Meaning                                  |
|--------------|-----------------|-----------|-----------------------------------|------------------------------------------|
| `revocation` | ✅ Valid         | `true`    | `null`                            | Credential has not been revoked          |
| `revocation` | ❌ Invalid       | `false`   | `null`                            | Credential is revoked                    |
| `revocation` | ⚠️ Check Failed | `false`   | `StatusCheckException` or similar | Failed due to some error in status check |

## 6. API Overview

### 6.1 Credential Verifier

The `CredentialVerifier` class provides methods to verify Verifiable Credentials (VCs) across
multiple formats, including LDP VC, MSO MDOC, and SD-JWT. It supports signature verification, schema
validation, and credential status checks based on the StatusList2021 specification.

 **Verify and Obtain Credential status**

```kotlin
fun verifyAndGetCredentialStatus(
    credential: String,
    credentialFormat: CredentialFormat,
    statusPurposeList: List<String> = emptyList()
): CredentialVerificationSummary
```

* **Purpose:** Performs schema validation and signature verification for the input credential along
  with checks revocation/suspension status based on status purpose list (StatusList2021).
* **Parameters:**
    * `credential`: Verifiable Credential as a string (e.g., JWT, LDP JSON, or CBOR)
    * `credentialFormat`: Enum — one of `LDP_VC`,
      `VC_SD_JWT`,
      `DC_SD_JWT`,
      `MSO_MDOC`
    * `statusPurposeList`: List of purposes such as `"revocation"`, `"suspension"` (optional)

* **Returns:**
    * `CredentialVerificationSummary` — see [CredentialVerificationSummary Breakdown](#credentialverificationsummary-breakdown) below for structure.

---

**Verify Credential**

```kotlin
fun verify(
    credential: String,
    credentialFormat: CredentialFormat
): VerificationResult
```

* **Purpose:** Performs schema validation and signature verification for the input credential.

* **Parameters:**
    * `credential`: Verifiable Credential as a string (e.g., JWT, LDP JSON, or CBOR)
    * `credentialFormat`: Enum — one of `LDP_VC`,
      `VC_SD_JWT`,
      `DC_SD_JWT`,
      `MSO_MDOC`
* **Returns:** `VerificationResult` with:
    * `verificationStatus`: `true` if valid; otherwise `false`
    * `verificationMessage`: details of validation/syntax errors
    * `verificationErrorCode`: standardized error code (e.g., `VC_EXPIRED`, `SIGNATURE_INVALID`,
      etc.)

---

**Get Credential Status**

```kotlin
fun getCredentialStatus(
    credential: String,
    credentialFormat: CredentialFormat,
    statusPurposeList: List<String> = emptyList()
): Map<String, CredentialStatusResult>
```

* **Purpose:** Checks revocation/suspension status based on status purpose list (StatusList2021).
* **Parameters:**
    * `credential`: Verifiable Credential as a string (e.g., JWT, LDP JSON, or CBOR)
    * `credentialFormat`: Enum — one of `LDP_VC`,
      `VC_SD_JWT`,
      `DC_SD_JWT`,
      `MSO_MDOC`
    * `statusPurposeList`: List of purposes such as `"revocation"`, `"suspension"` (optional)
* **Returns:** A map of `CredentialStatusResult`, one per purpose, each containing:
    * `purpose`: status purpose (e.g., `"revocation"`)
    * `result`: `CredentialStatusResult`
        * `isValid = true`: credential is not revoked/suspended
        * `isValid = false`: credential is revoked/suspended
        * `error`: populated if status check failed

---

**Deprecated Verify Credentials Method**

```kotlin
@Deprecated
fun verifyCredentials(credentials: String?): Boolean
```

* **⚠️ Deprecated:** Only works for `LDP_VC` format.
* **Use Instead:** `verify(credential, credentialFormat)`

---

### CredentialVerificationSummary Breakdown

| Field                    | Type                                  | Description                                                            |
|--------------------------|---------------------------------------|------------------------------------------------------------------------|
| `verificationResult`     | `VerificationResult`                  | Overall result of VC verification (signature, expiry, structure, etc.) |
| `credentialStatus`       | `Map<String, CredentialStatusResult>` | Status check results for each purpose (e.g., revocation, suspension)   |
| `CredentialStatusResult` | `object`                              | Wrapper containing `isValid` and error (if any)                        |

---

#### `VerificationResult`

| Field                   | Type      | Description                                               |
|-------------------------|-----------|-----------------------------------------------------------|
| `verificationStatus`    | `Boolean` | `true` if credential is valid, `false` if invalid         |
| `verificationMessage`   | `String`  | Optional message (e.g., "VC is expired")                  |
| `verificationErrorCode` | `String`  | Error code (e.g., `ERROR_VC_EXPIRED`, `ERROR_VC_INVALID`) |

---

#### `CredentialStatusResult`

| Field     | Type     | Description                               |
|-----------|----------|-------------------------------------------|
| `isValid` | `Boolean` | `true` if status is valid for the purpose |
| `error`   | `StatusCheckException`      | Exception if check failed                 |

---

### Example JSON Response for CredentialVerificationSummary

```json
{
  "verificationResult": {
    "verificationStatus": true,
    "verificationMessage": "",
    "verificationErrorCode": ""
  },
  "credentialStatus": {
    "revocation": {
      "isValid": true,
      "error": null
    }
  }
}

```

The VC is valid and not revoked.

```json
{
  "verificationResult": {
    "verificationStatus": true,
    "verificationMessage": "VC is expired",
    "verificationErrorCode": ""
  },
  "credentialStatus": {
    "revocation": {
      "isValid": false,
      "error": null
    }
  }
}

```

The VC is expired and revoked.

```json
{
  "verificationResult": {
    "verificationStatus": true,
    "verificationMessage": "",
    "verificationErrorCode": ""
  },
  "credentialStatus": {
    "revocation": {
      "isValid": false,
      "error": {
        "message": "Failed to fetch status list",
        "code": "STATUS_RETRIEVAL_ERROR"
      }
    }
  }
}

```

The VC is valid but the status check failed due to a network error.

```json
{
  "verificationResult": {
    "verificationStatus": false,
    "verificationMessage": "Signature verification failed",
    "verificationErrorCode": "ERROR_SIGNATURE_INVALID"
  },
  "credentialStatus": {}
}
```

The VC signature is invalid; status check was not performed.

```json
{
  "verificationResult": {
    "verificationStatus": true,
    "verificationMessage": "",
    "verificationErrorCode": ""
  },
  "credentialStatus": {
    "revocation": {
      "isValid": false,
      "error": null
    }
  }
}

```

The VC is valid but revoked.

```json
 {
  "verificationResult": {
    "verificationStatus": true,
    "verificationMessage": "",
    "verificationErrorCode": ""
  },
  "credentialStatus": {
    "revocation": {
      "isValid": true,
      "error": null
    },
    "suspension": {
      "isValid": false,
      "error": null
    }
  }
}

```

The VC is valid, not revoked, but suspended.

### 6.2 Presentation Verifier

The `PresentationVerifier` class is responsible for verifying a Verifiable Presentation (VP) object.
It checks both the proof on the presentation and the integrity of all embedded Verifiable
Credentials (VCs).

**Verify Presentation**

```kotlin
fun verify(presentation: String): PresentationVerificationResult
```

* **Parameters:**
    * presentation: String — The Verifiable Presentation in JSON-LD string format.


- **Returns**:
  -`PresentationVerificationResult`, containing:
- `proofVerificationStatus`: `VALID` | `INVALID`
- `vcVerificationResults`: List of `VCResult` (each VC's raw string + individual
  verification status)

---

#### Output Structure – PresentationVerificationResult

| Field                     | Type                   | Description                                         |
|---------------------------|------------------------|-----------------------------------------------------|
| `proofVerificationStatus` | `VPVerificationStatus` | Signature validity of the presentation itself       |
| `vcVerificationResults`   | `List<VCResult>`       | Result of verifying all VCs inside the presentation |

Each `VCResult` contains:

- `vc`: String – the raw VC as it appeared in the input VP
- `verificationStatus`: Enum (`SUCCESS`, `INVALID`, `EXPIRED`) from internal VC verification

---

#### Purpose

- Validates the proof of the Verifiable Presentation (VP).
- Independently verifies each VC embedded inside the VP.
- Ensures conformance to supported proof types (Ed25519 2018, 2020, JsonWebProof 2020).
- Throws specific errors (e.g., `PresentationNotSupportedException`,
  `SignatureVerificationException`) for invalid inputs.

---

### Example JSON Response for PresentationVerificationResult

```json
{
  "proofVerificationStatus": "VALID",
  "vcResults": [
    {
      "vc": "{...full VC string...}",
      "status": "SUCCESS"
    },
    {
      "vc": "{...full VC string...}",
      "status": "SUCCESS"
    }
  ]
}
```
The VP proof is valid, and both embedded VCs are valid.

```json
{
  "proofVerificationStatus": "INVALID",
  "vcResults": [
    {
      "vc": "{...full VC string...}",
      "status": "SUCCESS"
    },
    {
      "vc": "{...full VC string...}",
      "status": "INVALID"
    }
  ]
}
```
The VP proof is invalid, the first VC is valid, and the second VC is invalid.

```json
{
  "proofVerificationStatus": "VALID",
  "vcResults": [
    {
      "vc": "{...full VC string...}",
      "status": "EXPIRED"
    },
    {
      "vc": "{...full VC string...}",
      "status": "EXPIRED"
    }
  ]
}
```
The VP proof is valid, the VCs are expired.

---

**Verify Presentation with Credential Status**

```kotlin
fun verifyAndGetCredentialStatus(
    presentation: String,
    statusPurposeList: List<String> = emptyList()
): PresentationResultWithCredentialStatus 
```

* **Purpose:** Verifies the VP proof and each embedded VC, along with status checks for each VC.
* **Parameters:**
    * `presentation`: Verifiable Presentation as a JSON-LD string
    * `statusPurposeList`: List of purposes such as `"revocation"`, `"suspension"` (optional)
* **Returns:** `PresentationResultWithCredentialStatus`, containing:
    * `proofVerificationStatus`: VP proof verification status
    * `vcResults`: List of `VCResultWithCredentialStatus`, each containing:
        * `vc`: raw VC string
        * `status`: VC signature verification status
            * `credentialStatus`: Map of status check results per purpose
---

### Output Structure – PresentationResultWithCredentialStatus

| Field                     | Type                                 | Description                                         |
|---------------------------|--------------------------------------|-----------------------------------------------------|
| `proofVerificationStatus` | `VPVerificationStatus`               | Signature validity of the presentation itself       |
| `vcResults`               | `List<VCResultWithCredentialStatus>` | Result of verifying all VCs inside the presentation |

Each `VCResultWithCredentialStatus` contains:

| Field              | Type                                  | Description                                                          |
|--------------------|---------------------------------------|----------------------------------------------------------------------|
| `vc`               | `String`                              | The raw VC as it appeared in the input VP                            |
| `status`           | `VCVerificationStatus`                | Verification status of the VC (`SUCCESS`, `INVALID`, `EXPIRED`)      |
| `credentialStatus` | `Map<String, CredentialStatusResult>` | Status check results for each purpose (e.g., revocation, suspension) |
---

### Example JSON Response for PresentationResultWithCredentialStatus

```json
{
  "proofVerificationStatus": "VALID",
  "vcResults": [
    {
      "vc": "{...full VC string...}",
      "status": "SUCCESS",
      "credentialStatus": {
        "revocation": {
          "isValid": true,
          "error": null
        }
      }
    },
    {
      "vc": "{...full VC string...}",
      "status": "EXPIRED",
      "credentialStatus": {
        "revocation": {
          "isValid": false,
          "error": null
        }
      }
    }
  ]
}
```
The VP proof is valid. The first VC is valid and not revoked; the second VC is expired and revoked.

```json
{
  "proofVerificationStatus": "INVALID",
  "vcResults": [
    {
      "vc": "{...full VC string...}",
      "status": "SUCCESS",
      "credentialStatus": {
        "revocation": {
          "isValid": true,
          "error": null
        }
      }
    },
    {
      "vc": "{...full VC string...}",
      "status": "INVALID",
      "credentialStatus": {
        "revocation": {
          "isValid": false,
          "error": {
            "message": "Failed to fetch status list",
            "code": "STATUS_RETRIEVAL_ERROR"
          }
        }
      }
    }
  ]
}
```
The VP proof is invalid. The first VC is valid and not revoked; the second VC is invalid and the status check failed due to a network error.

### Supported Features Summary

#### VC Format v/s features

| Format                    | Validation | Signature Verification | Status Check | VP Support |
|---------------------------|------------|------------------------|--------------|------------|
| `ldp_vc`                  | ✔️         | ✔️                     | ✔️           | ✔️         |
| `mso_mdoc`                | ✔️         | ✔️                     | ❌            | ❌          |
| `vc+sd-jwt` / `dc+sd-jwt` | ✔️         | ✔️                     | ❌            | ❌          |

#### API operations matrix

| API Method                                               | Validation | Signature Verification | Status Check |
|----------------------------------------------------------|------------|------------------------|--------------|
| `verify(credential, credentialFormat)`                   | ✔️         | ✔️                     | ❌            |
| `getCredentialStatus(...)`                               | ❌          | ❌                      | ✔️           |
| `verifyAndGetCredentialStatus(...)`                      | ✔️         | ✔️                     | ✔️           |
| `verifyCredentials(...)` (Deprecated)                    | ❌          | ✔️                     | ❌            |
| `PresentationVerifier.verify(presentation)`              | ✔️         | ✔️                     | ❌            |
| `PresentationVerifier.verifyAndGetCredentialStatus(...)` | ✔️         | ✔️                     | ✔️           |

## Public Key Extraction

The verifier extracts the public key differently based on the credential format.
For LDP-VCs and Verifiable Presentations, the key is resolved from the proof’s verificationMethod, which may point to a DID URL (did:web, did:key, did:jwk) or an HTTPS endpoint containing a JWK/PEM/Multibase/HEX key. The verifier dereferences this URL, loads the corresponding document, and extracts the public key using the appropriate encoding.
For SD-JWT and DC-SD-JWT credentials, the issuer’s public key is not resolved through verificationMethod; instead, it comes from the cnf (confirmation) claim inside the SD-JWT payload—either cnf.jwk or a cnf.kid mapping to a JWKS. This provides the public key required to verify the optional key-binding proof.

### Resolution Mechanisms

| Resolution Type             | Description                                                  | Supported Key Formats    |
|-----------------------------|--------------------------------------------------------------|--------------------------|
| DID (key, web)              | Uses DID Document resolution to extract verification method. | JWK, HEX, PEM, Multibase |
| HTTPS-based (JWK, key, web) | Uses HTTP endpoint to resolve  a public key document.        | JWK, HEX, PEM, Multibase |

| Source    | Variant | Where is the key?        | If document: key format | Supported Key Types           |
|-----------|---------|--------------------------|-------------------------|-------------------------------|
| DID/HTTPS | JWK     | **In-line with the URL** | —                       | ED25519, ECCR1, ECCK1, RSA256 |
| DID/HTTPS | KEY     | **In-line with the URL** | —                       | ED25519                       |
| DID/HTTPS | WEB     | **DID Document**         | **JWK**                 | ED25519, ECCR1, ECCK1, RSA256 |
|           |         |                          | **HEX**                 | ECCK1, ED25519                |
|           |         |                          | **PEM**                 | ED25519, RSA256               |
|           |         |                          | **Multi-base**          | ED25519, RSA256               |

## Error Codes

Consumer can use these Error codes to handle different error scenarios based on the requirements.
Error codes mapped to fields in VC are listed below:

**ldp_vc Error Codes**

| Field             | Error Code                         |
|-------------------|------------------------------------|
| credential        | ERR_EMPTY_VC                       |
| context           | ERR_MISSING_CONTEXT                |
|                   | ERR_INVALID_CONTEXT                |
| type              | ERR_MISSING_TYPE                   |
|                   | ERR_INVALID_TYPE                   |
| id                | ERR_INVALID_ID                     |
| credentialSubject | ERR_MISSING_CREDENTIALSUBJECT      |
|                   | ERR_INVALID_CREDENTIALSUBJECT      |
| issuer            | ERR_MISSING_ISSUER                 |
|                   | ERR_INVALID_ISSUER                 |
| proof             | ERR_MISSING_PROOF                  |
|                   | ERR_MISSING_PROOF_TYPE             |
|                   | ERR_INVALID_PROOF_TYPE             |
|                   | ERR_INVALID_ALGORITHM              |
| issuanceDate      | ERR_MISSING_ISSUANCEDATE           |
|                   | ERR_INVALID_ISSUANCEDATE           |
|                   | ERR_ISSUANCE_DATE_IS_FUTURE_DATE   |
| expirationDate    | ERR_INVALID_EXPIRATIONDATE         |
|                   | ERR_VC_EXPIRED                     |
| validFrom         | ERR_INVALID_VALIDFROM              |
|                   | ERR_CURRENT_DATE_BEFORE_VALID_FROM |
| validUntil        | ERR_INVALID_VALIDUNTIL             |
|                   | ERR_VC_EXPIRED                     |
| name              | ERR_INVALID_NAME                   |
| description       | ERR_INVALID_DESCRIPTION            |
| credentialStatus  | ERR_MISSING_CREDENTIALSTATUS       |
|                   | ERR_INVALID_CREDENTIALSTATUS       |
| evidence          | ERR_MISSING_EVIDENCE               |
|                   | ERR_INVALID_EVIDENCE               |
| termsOfUse        | ERR_MISSING_TERMSOFUSE_TYPE        |
| refreshService    | ERR_MISSING_REFRESHSERVICE_TYPE    |
|                   | ERR_MISSING_REFRESHSERVICE_ID      |
|                   | ERR_INVALID_REFRESHSERVICE_ID      |
| credentialSchema  | ERR_MISSING_CREDENTIALSCHEMA_TYPE  |
|                   | ERR_MISSING_CREDENTIALSCHEMA_ID    |
|                   | ERR_INVALID_CREDENTIALSCHEMA_ID    |

For other unknown exceptions, error code will be `ERR_GENERIC`

**mso_mdoc Format VC Error Codes**

| Field      | Error Code           |
|------------|----------------------|
| validFrom  | ERR_INVALID_DATE_MSO |
| validUntil | ERR_INVALID_DATE_MSO |

For other unknown exceptions, error code will be `ERR_GENERIC`

**vc+sd-jwt/dc+sd-jwt Format VC Error Codes**

| Field                     | Error Code                         |
|---------------------------|------------------------------------|
| credential empty          | ERR_EMPTY_VC                       |
| JWT                       | ERR_INVALID_JWT_FORMAT             |
| alg in header             | ERR_INVALID_ALG                    |
| typ in header             | ERR_INVALID_TYP                    |
| vct in payload            | ERR_INVALID_VCT                    |
| vct in payload            | ERR_INVALID_VCT_URI                |
| iss in payload            | ERR_INVALID_ISS                    |
| _sd_alg in payload        | ERR_INVALID_SD_ALG                 |
| iat in payload            | ERR_ISSUANCE_DATE_IS_FUTURE_DATE   |
| nbf in payload            | ERR_PROCESSING_DATE_IS_FUTURE_DATE |
| exp in payload            | ERR_VC_EXPIRED                     |
| aud in payload            | ERR_INVALID_AUD                    |
| cnf in payload            | ERR_INVALID_CNF                    |
| disclosure format         | ERR_INVALID_DISCLOSURE_FORMAT      |
| disclosure json length    | ERR_INVALID_DISCLOSURE_STRUCTURE   |
| disclosure claim          | ERR_INVALID_DISCLOSURE_CLAIM_NAME  |
| disclosure hash length    | ERR_INVALID_ALG                    |
| disclosure digest empty   | ERR_INVALID_DIGEST                 |
| KB JWT                    | ERR_INVALID_KB_JWT_FORMAT          |
| KB JWT header             | ERR_INVALID_KB_JWT_HEADER          |
| KB JWT header             | ERR_INVALID_KB_JWT_HEADER          |
| alg in KB JWT header      | ERR_MISSING_KB_JWT_ALG             |
| alg in KB JWT header      | ERR_INVALID_KB_JWT_ALG             |
| typ in KB JWT header      | ERR_INVALID_KB_JWT_TYP             |
| cnf in KB JWT header      | ERR_INVALID_CNF                    |
| cnf in KB JWT header      | ERR_INVALID_CNF_TYPE               |
| cnf in KB JWT header      | ERR_INVALID_KB_SIGNATURE           |
| aud in KB JWT payload     | ERR_MISSING_AUD                    |
| nonce in KB JWT payload   | ERR_MISSING_NONCE                  |
| sd_hash in KB JWT payload | ERR_MISSING_SD_HASH                |
| iat in KB JWT payload     | ERR_MISSING_IAT                    |
| aud in KB JWT payload     | ERR_INVALID_AUD                    |
| nonce in KB JWT payload   | ERR_INVALID_NONCE                  |
| iat in KB JWT payload     | ERR_INVALID_KB_JWT_IAT             |
| sd_hash in KB JWT payload | ERR_INVALID_SD_HASH                |

**Status Check Error Codes**

| Error Code                | Description                                   |
|---------------------------|-----------------------------------------------|
| RANGE_ERROR               | Bit position is out range                     |
| STATUS_VERIFICATION_ERROR | Error during status list VC verification      |
| STATUS_RETRIEVAL_ERROR    | Failed to retrieve the status list VC         |
| INVALID_PURPOSE           | Status purpose is invalid                     |
| INVALID_CREDENTIAL_STATUS | No valid credential status entry is found     |
| INVALID_INDEX             | Status list index is invalid or missing       |
| ENCODED_LIST_MISSING      | Encoded status list is missing                |
| BASE64_DECODE_FAILED      | Failed to decode Base64-encoded status list   |
| GZIP_DECOMPRESS_FAILED    | Failed to decompress GZIP-encoded status list |
| UNKNOWN_ERROR             | Unknown error occurred during status check    |

For other unknown exceptions, error code will be `ERR_INVALID_UNKNOWN`





