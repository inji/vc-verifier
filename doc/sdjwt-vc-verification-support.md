## Support for IETF SD-JWT Verifiable Credential

This document provides a comprehensive overview of verifying `vc+sd-jwt` and `dc+sd-jwt` Verifiable Credentials (VCs).

### Public key resolution support
The mechanism is chosen by the credential, not the verifier, and an `x5c` header takes precedence:

- **X.509 Certificates** — retrieves the Issuer's public key from the `x5c` header parameter.
- **JWT VC Issuer Metadata** — when `iss` is an HTTPS URL, fetches the metadata at
  `/.well-known/jwt-vc-issuer` (inserted between host and path of `iss`), requires its `issuer` to
  match `iss` exactly, and selects a key from the inline `jwks` or the referenced `jwks_uri`.
  A `kid` header selects among published keys; without one, the key is chosen by what the JWS
  algorithm requires, and ambiguity is rejected rather than guessed at.
- **DID resolution** — when `iss` is a DID, resolves a relative fragment or absolute DID URL `kid`,
  but only when that `kid` is controlled by the DID in `iss`.

The first two are the Issuer Signature Mechanisms defined in draft-ietf-oauth-sd-jwt-vc-10 §3.5.
DID resolution is **not** part of that specification — it is an additional mechanism of the kind
§3.5 permits ecosystems to define, and is out of scope for the draft.

> **Note on network hardening:** the metadata location is derived from the `iss` claim, which is
> attacker supplied until the signature has been checked. All outbound requests therefore run through
> a single hardened client: connect/read/call timeouts, a response size cap, no redirects, and hosts
> resolving to non-public addresses refused. The last two are configurable via `NetworkPolicy` for
> deployments that serve issuers internally or behind a redirecting load balancer; both default to
> the safe setting.


### Steps Involved
1. Add enum value `VC_SD_JWT("vc+sd-jwt")` and `DC_SD_JWT("dc+sd-jwt")` in `CredentialFormat`
2. Create a new class `SdJwtVerifiableCredential` that implements `VerifiableCredential` interface. This class will be used to validate and verify the credential.
   - `validate` method will be used to validate the credential format and its claims.
   - `verify` method will be used to verify the credential signature and disclosures.
3. Create a class `SdJwtValidator` to validate the credential format and disclosures.
   -  method `validate` to validate the credential format, disclosures
4. Create a class `SdJwtVerifier` to verify the credential signature.
   - method `verify` to verify credential Cryptographic Signature
5. Implement the `validate` method in `SdJwtVerifiableCredential` class to perform the following checks:
   - Validate the credential format is `vc+sd-jwt` or `dc+sd-jwt`.
   - Validate the credential claims against the issuer metadata.
   - Ensure that the credential contains required claims as per the issuer's configuration.
   - Check if the credential is expired or not.
   - Disclosure Verification to confirm sd claims are not tampered (Cryptographic Hash Verification).
      - Use SHA-256 if `_sd_alg` is not specified, otherwise use the algorithm specified in `_sd_alg` claim
6. Implement the `verify` method in `SdJwtVerifiableCredential` class to perform the following checks:
   - Confirm the credential is not tampered (Cryptographic Signature Verification).
7. Implement the `CredentialVerifierFactory` to create an instance of `SdJwtVerifiableCredential` when the credential format is `vc+sd-jwt` or `dc+sd-jwt`.


> Note: All non-normative examples are referred for vc+sd-jwt format.

###  Sequence diagram - validate and verify `vc+sd-jwt` or `dc+sd-jwt` credential format VC

```mermaid
sequenceDiagram
   Wallet->>CredentialsVerifier: verify credential<br/>verify(credential: "jwt-string", credentialFormat: "vc+sd-jwt")
   CredentialsVerifier->>CredentialVerifierFactory: Create instance of VerifiableCredential based on format vc+sd-jwt
   CredentialVerifierFactory->>SdJwtVerifiableCredential: Create SdJwtVerifiableCredential instance
   CredentialsVerifier->>SdJwtVerifiableCredential: Validate sd-jwt Credential
   SdJwtVerifiableCredential->>SdJwtValidator: Validate sd-jwt Credential
   SdJwtValidator-->>SdJwtVerifiableCredential: Return validation result
   SdJwtVerifiableCredential-->>CredentialsVerifier: Return validation result
   
   alt Credential is Invalid
      CredentialsVerifier-->>Wallet: Return Verification Result as False with validation error
   else Credential is Valid
      CredentialsVerifier->>SdJwtVerifiableCredential: Verify sd-jwt Credential
      SdJwtVerifiableCredential->>SdJwtVerifier: Verify sd-jwt Credential
      SdJwtVerifier-->>SdJwtVerifiableCredential: Return Verification Result
      SdJwtVerifiableCredential-->>CredentialsVerifier: Return verification result
      
      alt Verification Failed
         CredentialsVerifier-->>Wallet: Return Verification Result as False with error
      else Verification Success
         CredentialsVerifier-->>Wallet: Return Verification Result as True
      end
   end
```

###  Sequence diagram - validation process

```mermaid
sequenceDiagram

    SdJwtVerifiableCredential->>SdJwtValidator: Validate sd-jwt Credential
    SdJwtValidator->>SdJwtValidator: Parse JWT
    SdJwtValidator->>SdJwtValidator: Validate Header
    Note over SdJwtValidator: typ header must be present and<br/>it's value must be `vc+sd-jwt` or `dc+sd-jwt`
    Note over SdJwtValidator: alg header must be present
    SdJwtValidator->>SdJwtValidator: Validate Payload/Claims
    Note over SdJwtValidator: vct must be present and<br/>value MUST be a case-sensitive StringOrURI
    Note over SdJwtValidator: iss is optional. If present, must be an issuer
    Note over SdJwtValidator: nbf is optional. If present, not before time cannot be in future
    Note over SdJwtValidator: exp is optional. If present, expired time cannot be in past
    Note over SdJwtValidator: cnf is optional. Must if cryptographic Key Binding is to be supported
    Note over SdJwtValidator: iat is optional. If present, issued at time cannot be in future
    Note over SdJwtValidator: _sd_alg is optional. If present, must be a valid algorithm(e.g., sha-256, sha-384, sha-512)
    Note over SdJwtValidator: if `_sd` present, value MUST be an array of digests
    Note over SdJwtValidator: digest length check based on hash algo  `sha-256` - 32, `sha-384` to 48, `sha-512` to 64
    alt if Disclosures present
        SdJwtValidator->>SdJwtValidator: Validate Disclosures
        loop For each disclosure
            SdJwtValidator->>SdJwtValidator: Create digest with sha-256 if `_sd_alg` is not specified and<br/>Base64URL Encode
        end
       SdJwtValidator->>SdJwtValidator: digest must match the hash available in `_sd` array inside payload <br/>or `_sd` available in claims
        alt If any digest does not match or missing
            SdJwtValidator-->>SdJwtVerifiableCredential: Return Validation Result as False with error
        else All digests match
            Note over SdJwtValidator: after base64 decoding, json object should be of size 2(salt and value if it's array) or 3(salt, key, value if object)
            Note over SdJwtValidator: disclosure claim name should exist once
            Note over SdJwtValidator: disclosure claim name should not conflict with claim name in payload
           alt If any validation fails
              SdJwtValidator-->>SdJwtVerifiableCredential: Return Validation Result as False with error
           else Validiation Success
              SdJwtValidator-->>SdJwtVerifiableCredential: Return Validation Result as True
           end
        end
    else If Disclosures not present
        alt If any validation fails
            SdJwtValidator-->>SdJwtVerifiableCredential: Return Validation Result as False with error
        else Validiation Success
           SdJwtValidator-->>SdJwtVerifiableCredential: Return Validation Result as True
        end
    end
```   

###  Sequence diagram - verification process

```mermaid
sequenceDiagram

   SdJwtVerifiableCredential->>SdJwtVerifier: Verify sd-jwt Credential
   SdJwtVerifier->>SdJwtVerifier: Separate JWT and disclosures
   SdJwtVerifier->>SdJwtVerifier: Validate JWT by checking if it is well-formed
   alt Invalid JWT
      SdJwtVerifier-->>SdJwtVerifiableCredential: Return Verification Result as False with error
   else Valid JWT
      SdJwtVerifier->>SdJwtVerifier: Parse JWT
      SdJwtVerifier->>SdJwtVerifier: Extract JWT Header
      SdJwtVerifier->>SdJwtVerifier: Extract x5c Certificate
      SdJwtVerifier->>SdJwtVerifier: Extract Algorithm
      SdJwtVerifier->>SdJwtVerifier: Extract Public Key
      SdJwtVerifier->>SdJwtVerifier: Verify Signature
      alt Signature Invalid
         SdJwtVerifier-->>SdJwtVerifiableCredential: Return Verification Result as False with error
      else Signature Valid
         SdJwtVerifier-->>SdJwtVerifiableCredential: Return Verification Result as True
      end
   end
```
