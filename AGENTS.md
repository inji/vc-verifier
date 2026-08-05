# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Project Overview

**vc-verifier** is a Kotlin/Android library (published as both AAR and JAR) for validating and verifying W3C Verifiable Credentials. It is part of the MOSIP/Inji ecosystem. The library source lives under `vc-verifier/kotlin/` with the main module at `vc-verifier/kotlin/vcverifier/`.

## Commands

All commands are run from `vc-verifier/kotlin/` (the Gradle root project, which includes the `:vcverifier` module) using the Gradle wrapper.

```bash
cd vc-verifier/kotlin

# Build
./gradlew :vcverifier:assembleDebug

# Run all unit tests
./gradlew :vcverifier:testDebugUnitTest

# Run a single test class
./gradlew :vcverifier:testDebugUnitTest --tests "io.mosip.vercred.vcverifier.CredentialsVerifierTest"

# Run a single test method
./gradlew :vcverifier:testDebugUnitTest --tests "io.mosip.vercred.vcverifier.CredentialsVerifierTest.should return true for valid credential validation success"

# Lint
./gradlew :vcverifier:lint

# Generate test coverage report (outputs to build/reports/jacoco/)
./gradlew :vcverifier:jacocoTestReport

# Build JAR for Maven consumers
./gradlew :vcverifier:jarRelease

# Generate POM files
./gradlew :vcverifier:generatePom
```

Java 17 is required. The project uses AGP 8.3.0 with `compileSdk = 33` and `minSdk = 23`.

## Architecture

### Request Flow

`CredentialsVerifier` (main public API) → `CredentialVerifierFactory` → format-specific `VerifiableCredential` implementation → separate `Validator` and `Verifier` classes → `PublicKeyResolverFactory` + `SignatureFactory`

### Key Abstractions

**`VerifiableCredential` interface** (`credentialverifier/VerifiableCredential.kt`) — every supported format implements `validate()`, `verify()`, and optionally `checkStatus()`. `CredentialVerifierFactory` maps `CredentialFormat` enum values to the correct implementation.

**Supported formats** (`CredentialFormat` enum):
- `LDP_VC` — JSON-LD with Linked Data Proofs → `LdpVerifiableCredential`
- `MSO_MDOC` — CBOR/COSE → `MsoMdocVerifiableCredential`
- `VC_SD_JWT` / `DC_SD_JWT` — SD-JWT → `SdJwtVerifiableCredential` (same impl for both)
- `CWT_VC` — CBOR Web Token → `CwtVerifiableCredential`
- `JWT_VC_JSON` — JWT → `JwtVerifiableCredential`

Each format has a matching validator (`credentialverifier/validator/`) and verifier (`credentialverifier/verifier/`) under the same package hierarchy.

**`PublicKeyResolverFactory`** (`keyResolver/PublicKeyResolverFactory.kt`) — routes key resolution by URI prefix:
- `did:` → `DidPublicKeyResolver` (delegates to `DidWebPublicKeyResolver`, `DidJwkPublicKeyResolver`, `DidKeyPublicKeyResolver`)
- `http*` ending in `jwks.json` → `JwksPublicKeyResolver`
- `http*` → `HttpsPublicKeyResolver`

**`SignatureFactory`** (`signature/SignatureFactory.kt`) — maps JWS algorithm strings to verifier implementations (PS256, RS256, EdDSA, ES256K, ES256). COSE signatures for `mso_mdoc` and `cwt_vc` use `CoseSignatureVerifierImpl` directly, not through this factory.

**`PresentationVerifier`** (`PresentationVerifier.kt`) — handles Verifiable Presentations (VP). Verifies the VP proof using the same LDP machinery, then performs holder binding checks for `did:key` and `did:jwk` holder DIDs. VCs inside the VP are verified as `LDP_VC` only.

### Public API Entry Points

- `CredentialsVerifier.verify(credential, format)` → `VerificationResult`
- `CredentialsVerifier.verifyAndGetCredentialStatus(credential, format, statusPurposeList)` → `CredentialVerificationSummary`
- `PresentationVerifier.verify(presentation)` → `PresentationVerificationResult` (V1, uses `VPVerificationStatus` enum)
- `PresentationVerifier.verifyV2(presentation)` → `PresentationVerificationResultV2` (V2, returns structured `VerificationResult`)
- V2 variants of VP methods also expose per-VC `VerificationResult` instead of the enum-based `VerificationStatus`

### Test Infrastructure

Tests use JUnit 5 + MockK. The `LocalDocumentLoader` object (`utils/LocalDocumentLoader.kt`) is used in tests instead of making live HTTP calls for JSON-LD context resolution — inject it via `Util.documentLoader = LocalDocumentLoader` in `@BeforeAll`. HTTP calls for DID resolution / public key fetching are mocked with `MockWebServer` via the helper in `testutils/TestUtils.kt`.

Test fixtures (VCs, VPs, public keys, CBOR hex files) live under `src/test/resources/` organized by format (`ldp_vc/`, `sd-jwt_vc/`, `cwt_vc/`, `vp/`, `jwt_vc/`).

### Dependency Notes

Two separate custom Maven repositories are required (configured in `settings.gradle.kts`):
- `https://repo.danubetech.com/repository/maven-public/` — for `ld-signatures-java` and `jsonld-common-java`
- `https://jitpack.io` — for `identity-credential`

When integrating as a Maven JAR consumer, three additional runtime dependencies must be added manually (they are not transitively resolved): `identity-credential`, `ld-signatures-java`, `jsonld-common-java`. See the root `README.md` for exact coordinates.

BouncyCastle conflicts are common when mixing with other Android libraries — the `build.gradle.kts` excludes the legacy `jdk15on` variants and forces `bcprov-jdk15to18`.
