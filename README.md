[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?branch=develop&project=mosip_vc-verifier&metric=alert_status)](https://sonarcloud.io/dashboard?branch=develop&id=mosip_vc-verifier)
# vc-verifier

**VC Verifier Library** is a comprehensive Java/Kotlin library designed to enable the validation and verification of **Verifiable Credentials (VCs)**, a crucial component in modern decentralized identity systems. This library provides a robust mechanism for verifying the authenticity and integrity of VCs, ensuring that the claims made within the credential are both valid and trustworthy.

## 🚨 Breaking Changes

### From Version `release-1.5.x` onward:

#### ❗ Required Update in Imports

Replace:

```kotlin
import io.mosip.vercred.vcverifier.publicKey.PublicKeyGetterFactory;
import io.mosip.vercred.vcverifier.publicKey.PublicKeyGetter;
import io.mosip.vercred.vcverifier.DidWebResolver;
import io.mosip.vercred.vcverifier.publicKey.impl.DidWebPublicKeyGetter;
import io.mosip.vercred.vcverifier.publicKey.impl.DidJwkPublicKeyGetter;
import io.mosip.vercred.vcverifier.publicKey.impl.DidKeyPublicKeyGetter;
import io.mosip.vercred.vcverifier.publicKey.impl.HttpsPublicKeyGetter;
```

With:

```kotlin
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory;
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolver;
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver;
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidWebPublicKeyResolver;
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidJwkPublicKeyResolver;
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidKeyPublicKeyResolver;
import io.mosip.vercred.vcverifier.keyResolver.types.http.HttpsPublicKeyResolver;
```


#### Key Features:

-   **VC Validation**: The library validates the structure, signatures, and expiration of Verifiable Credentials to ensure they conform to the W3C VC standards.
-   **Cryptographic Signature Verification**: Supports the verification of cryptographic signatures using public keys, including EdDSA, RSA, and other supported algorithms, ensuring the integrity of the credential.
-   **Status Check**: It includes mechanisms to check the current status of credentials, allowing applications to determine if a credential is still valid or has been invalidated.
-   **Compatibility with Various Data Models**: It supports multiple VC data models (e.g., VC 1.1, VC 2.0), ensuring compatibility across various decentralized identity systems.

#### Supported VC Formats and Their Signature Mechanisms

| VC format   | Issuer Signature Mechanism                                             | Verification Algorithms             | Signature Suites / Proof Types                                                            |
|-------------|------------------------------------------------------------------------|-------------------------------------|-------------------------------------------------------------------------------------------|
| `ldp_vc`    | Linked Data Proof                                                      | PS256, RS256, EdDSA (Ed25519)       | RsaSignature2018, Ed25519Signature2018, Ed25519Signature2020, EcdsaSecp256k1Signature2019 |
| `mso_mdoc`  | COSE (CBOR Object Signing and Encryption)                              | ES256                               | Uses COSE_Sign1                                                                           |
| `vc+sd-jwt` | X.509 Certificate (Currently, JWT VC Issuer Metadata is not supported) | PS256, RS256,ES256, EdDSA (Ed25519) | -                                                                                         |
| `dc+sd-jwt` | X.509 Certificate (Currently, JWT VC Issuer Metadata is not supported) | PS256, RS256,ES256, EdDSA (Ed25519) | -                                                                                         |

#### Project Structure

`io.mosip.vercred.vcverifier`
- **constants**
- **credentialverifier**
    - `types`
    - `validator`
    - `verifier`
    - `statusChecker`
- **data**
- **exception**
- **keyResolver**
- **signature**
    - `impl`
- **utils**
- **CredentialVerifier.kt**
- **PresentationVerifier.kt**

#### Package Description

- **constants** - All Validator and Verifier constants are declared in this package.
- **credentialverifier** - CredentialFactory for different credential formats are declared in this package. It also 
consists of classes for different credential formats.
- **data** - It has data classes for Validation Status and Verification Result.
- **exception** - Custom exceptions are defined in this package.
- **keyResolver** - PublicKeyResolverFactory for different type of verification method types are declared in this package.
It has support for DID(web, key, jwk) and HTTP verification methods.
- **signature** - Interface and Implementations for multiple Signature Verification are available in this package.
- **utils** - It helper classes and methods that provide reusable and general-purpose functionalities across the project.
- **CredentialVerifier.kt** - The `CredentialVerifier.kt` file serves as the main entry point to the VC Verifier Library. 
This class provides the primary interface for interacting with the library and encapsulates all the core functionalities 
related to validating and verifying Verifiable Credentials (VCs). It also performs a revocation check by calling the method isRevoked(credential).
- **PresentationVerifier.kt** - The `PresentationVerifier.kt` file is a dedicated class within the VC Verifier Library
that focuses on the verification of Verifiable Presentations (VPs). This class provides methods and functionalities 
specifically designed to handle the unique aspects of VPs, including their structure, proof mechanisms, and the embedded 
Verifiable Credentials they may contain.

#### Integrating jar to Maven Project


##### Add Vc-Verifier in `pom.xml`

        <dependency>
            <groupId>io.mosip</groupId>
            <artifactId>vcverifier-jar</artifactId>
            <version>{{version-number}}</version>
        </dependency>

To integrate **vc-verifier** library into a Maven project ,  include below additional dependencies that are not managed via the `pom.xml` file of vc-verifier library.

        <dependency>
            <groupId>com.android.identity</groupId>
            <artifactId>identity-credential</artifactId>
            <version>20231002</version>
        </dependency>
        <dependency>
            <groupId>info.weboftrust</groupId>
            <artifactId>ld-signatures-java</artifactId>
            <version>1.5.0</version>
        </dependency>
        <dependency>
            <groupId>decentralized-identity</groupId>
            <artifactId>jsonld-common-java</artifactId>
            <version>1.8.0</version>
        </dependency>


#### Integrating aar to Gradle Project

To integrate **vc-verifier** library into a Gradle project ,  add below line in module level `build.gradle`.

	dependencies {
		implementation("io.mosip:vc-verifier-aar:{{version-number}}")
	}

To avoid Duplicate classes error while building the application, include the below exclusion strategy in the build.gradle file.

    configurations.all {  
      resolutionStrategy {  
      exclude(module = "bcprov-jdk15to18")  
      exclude(module = "bcutil-jdk18on")  
      exclude(module = "bcprov-jdk15on")  
      exclude(module = "bcutil-jdk15on")  
      exclude(module = "titanium-json-ld")  
      }  
    }

**Note**: `version-number` should be replaced with the actual version of the library from Maven Central.



#### References:

- [Data Model 1.1](https://www.w3.org/TR/vc-data-model-1.1/)
- [Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [IETF SD-JWT DRAFT](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-10.html)
