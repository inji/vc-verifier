# Support for IETF CWT Verifiable Credential (CWT-VC)

This document provides a comprehensive overview of validating and verifying **CWT-based Verifiable Credentials (cwt-vc)** encoded using **CBOR Web Token (CWT)** and **COSE_Sign1**, as defined by IETF standards.

---

## Public key resolution support

- **HTTP / HTTPS Issuer**
  - Retrieves issuer public key from `/.well-known/jwks.json` when `iss` is an HTTP(S) URL.

---

## Steps Involved

1. Add enum value `CWT_VC("cwt-vc")` in `CredentialFormat`.
2. Create a new class `CwtVerifiableCredential` that implements the `VerifiableCredential` interface.
   - `validate` method validates credential structure and claims.
   - `verify` method verifies cryptographic signature.
3. Create a class `CwtValidator` to validate credential structure and claims.
4. Create a class `CwtVerifier` to verify the credential signature.
5. Implement validation checks for COSE, headers, claims, and numeric dates.
6. Implement signature verification using issuer public key.
7. Register `CwtVerifiableCredential` in `CredentialVerifierFactory`.

---

## Sequence diagram – validate and verify `cwt-vc` credential

```mermaid
sequenceDiagram
   Wallet->>CredentialsVerifier: verify credential
   CredentialsVerifier->>CredentialVerifierFactory: Create verifier
   CredentialVerifierFactory->>CwtVerifiableCredential: Create instance
   CredentialsVerifier->>CwtVerifiableCredential: Validate
   CwtVerifiableCredential->>CwtValidator: Validate
   CwtValidator-->>CwtVerifiableCredential: Result
   CwtVerifiableCredential-->>CredentialsVerifier: Result
```

### Sequence diagram - validation process

```mermaid
sequenceDiagram

    CwtVerifiableCredential->>CwtValidator: Validate CWT Credential
    CwtValidator->>CwtValidator: Validate input is non-empty hex string
    CwtValidator->>CwtValidator: Decode hex to CBOR
    CwtValidator->>CwtValidator: Validate COSE_Sign1 structure
    Note over CwtValidator: COSE_Sign1 must be a CBOR array of size 4

    CwtValidator->>CwtValidator: Decode protected header
    CwtValidator->>CwtValidator: Validate protected header
    Note over CwtValidator: alg must be present and must be an integer

    CwtValidator->>CwtValidator: Decode CWT claims
    CwtValidator->>CwtValidator: Validate CWT claims structure
    Note over CwtValidator: CWT payload must be a CBOR map

    CwtValidator->>CwtValidator: Validate numeric date claims
    Note over CwtValidator: exp, nbf, iat are optional numeric dates

    alt exp present and expired
        CwtValidator-->>CwtVerifiableCredential: Return Validation Result as False (VC expired)
    else nbf present and in future
        CwtValidator-->>CwtVerifiableCredential: Return Validation Result as False (Not Before violation)
    else iat present and in future
        CwtValidator-->>CwtVerifiableCredential: Return Validation Result as False (Invalid iat)
    else Validation Success
        CwtValidator-->>CwtVerifiableCredential: Return Validation Result as True
    end
```

### Sequence diagram - verification process

```mermaid
sequenceDiagram

   CwtVerifiableCredential->>CwtVerifier: Verify CWT Credential
   CwtVerifier->>CwtVerifier: Decode hex to CBOR
   CwtVerifier->>CwtVerifier: Validate CBOR Tag 61 (CWT)
   alt Missing or invalid tag
      CwtVerifier-->>CwtVerifiableCredential: Return Verification Result as False
   else Valid CWT
      CwtVerifier->>CwtVerifier: Extract COSE_Sign1 object
      CwtVerifier->>CwtVerifier: Validate COSE_Sign1 structure
      CwtVerifier->>CwtVerifier: Extract CWT claims
      CwtVerifier->>CwtVerifier: Extract issuer (iss)
      CwtVerifier->>CwtVerifier: Extract kid from protected or unprotected header
      CwtVerifier->>PublicKeyResolverFactory: Resolve public key using issuer and kid
      CwtVerifier->>CwtVerifier: Verify COSE_Sign1 signature
      alt Signature Invalid
         CwtVerifier-->>CwtVerifiableCredential: Return Verification Result as False
      else Signature Valid
         CwtVerifier-->>CwtVerifiableCredential: Return Verification Result as True
      end
   end


```
---

## Key Validation Rules Summary

### COSE Structure
- Must be a CBOR array of exactly 4 elements.

### Protected Header
- `alg` MUST be present and an integer.

### CWT Claims
- Payload MUST be a CBOR map.
- `iss`, `exp`, `nbf`, `iat` validated as per spec.

### Cryptographic Verification
- CBOR tag `61` required.
- Signature verified using COSE_Sign1.

---
