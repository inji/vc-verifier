package io.mosip.vercred.vcverifier

import foundation.identity.jsonld.JsonLDObject
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.spyk
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_CODE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.data.PresentationResultWithCredentialStatus
import io.mosip.vercred.vcverifier.data.VPVerificationStatus
import io.mosip.vercred.vcverifier.data.VerificationStatus
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.exception.PresentationNotSupportedException
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.utils.LocalDocumentLoader
import io.mosip.vercred.vcverifier.utils.Util
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.assertThrows
import testutils.mockHttpResponse
import testutils.readClasspathFile
import java.util.concurrent.TimeUnit
import io.mosip.vercred.vcverifier.data.PresentationResultWithCredentialStatusV2
import org.junit.jupiter.api.Assertions.assertNotEquals
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.HOLDER_VERIFICATION_FAIL_ERROR
import io.mosip.vercred.vcverifier.exception.HolderBindingException
import org.junit.jupiter.api.Assertions.assertDoesNotThrow

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PresentationVerifierTest {

    private fun mockedVerifier(): PresentationVerifier {
        val verifier = spyk(PresentationVerifier(), recordPrivateCalls = true)

        every {
            verifier["verifyPresentationProof"](any<JsonLDObject>())
        } returns true

        return verifier
    }

    @BeforeAll
    fun setup() {
        mockkObject(NetworkManagerClient)
        Util.documentLoader = LocalDocumentLoader
    }

    @AfterAll
    fun teardownAll() {
        Util.documentLoader = null
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return true for valid presentation verification success Ed25519Signature2018`() {
        val vc = readClasspathFile("vp/Ed25519Signature2018SignedVP-didKey.json")

        val verificationResult = PresentationVerifier().verify(vc)

        assertEquals(VPVerificationStatus.VALID,verificationResult.proofVerificationStatus)
        //check when we have a supported vc
        //assertEquals(verificationResult.vcResults, emptyList<VCResult>())

    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return true for valid presentation verification success JsonWebSignature2020`() {
        mockHttpResponse("https://api.released.mosip.net/identity-service/02b073b8-aacd-472e-b63f-265bb7ccdd9f/did.json", readClasspathFile("vp/public_key/didIdentityServiceKey.json"))

        val vc = readClasspathFile("vp/JsonWebSignature2020SignedVP-didJws.json")
        val verificationResult = PresentationVerifier().verify(vc)
        assertEquals(VPVerificationStatus.VALID, verificationResult.proofVerificationStatus)
        assertNotEquals("", verificationResult.vcResults[0].vc)
        assertNotNull(verificationResult.vcResults[0].vc)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return false for invalid presentation verification`() {
        val vc = readClasspathFile("vp/InvalidEd25519Signature2018SignedVP-didKey.json")

        val verificationResult = PresentationVerifier().verify(vc)
        assertEquals(VPVerificationStatus.INVALID,verificationResult.proofVerificationStatus)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should throw error when public key not found false`() {
        val vc = readClasspathFile("vp/InvalidPublicKeyEd25519Signature2018SignedVP-didKey.json")

        assertThrows<UnsupportedDidUrl> { PresentationVerifier().verify(vc) }
    }

    @Test
    fun `should throw error when vc is not jsonld`() {
        assertThrows<PresentationNotSupportedException> { PresentationVerifier().verify("invalid") }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should throw error for invalid presentation verification of Ed25519Signature2020`() {
        val vc = readClasspathFile("vp/Ed25519Signature2020SignedVP-didKey.json")

        val verificationResult = PresentationVerifier().verify(vc)

        assertEquals(VPVerificationStatus.INVALID,verificationResult.proofVerificationStatus)

    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `should verify VC and return VC status as revoked`() {
        val mockStatusListJson = readClasspathFile("ldp_vc/mosipRevokedStatusList.json")
        val vp = readClasspathFile("vp/VPWithRevokedVC.json")
        mockHttpResponse("https://mosip.github.io/inji-config/qa-inji1/mock/did.json", readClasspathFile("vp/public_key/didMockKey.json"))

        val realUrl = "https://injicertify-mock.qa-inji1.mosip.net/v1/certify/credentials/status-list/56622ad1-c304-4d7a-baf0-08836d63c2bf"
        mockHttpResponse(realUrl,mockStatusListJson)

        val result: PresentationResultWithCredentialStatus =
            PresentationVerifier().verifyAndGetCredentialStatus(
                vp,
                listOf("revocation")
            )
        val credentialStatus = result.vcResults[0].credentialStatus
        val proofVerificationStatus = result.proofVerificationStatus

        assertEquals(VPVerificationStatus.INVALID,proofVerificationStatus)
        assertNotNull(result)
        assertEquals(VerificationStatus.SUCCESS, result.vcResults[0].status)
        assertEquals(1, credentialStatus.size)
        val credentialStatusEntry = credentialStatus.entries.first()
        assertEquals("revocation", credentialStatusEntry.key)
        assertNull(credentialStatusEntry.value.error)
        assertFalse(credentialStatusEntry.value.isValid)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `should verify VC and return VC status as unrevoked`() {
        val mockStatusListJson = readClasspathFile("ldp_vc/mosipUnrevokedStatusList.json")
        val vp = readClasspathFile("vp/VPWithUnrevokedVC.json")
        mockHttpResponse("https://mosip.github.io/inji-config/qa-inji1/mock/did.json", readClasspathFile("vp/public_key/didMockKey.json"))
        val realUrl = "https://injicertify-mock.qa-inji1.mosip.net/v1/certify/credentials/status-list/56622ad1-c304-4d7a-baf0-08836d63c2bf"
        mockHttpResponse(realUrl,mockStatusListJson)

        val result: PresentationResultWithCredentialStatus =
            PresentationVerifier().verifyAndGetCredentialStatus(
                vp,
                listOf("revocation")
            )
        val credentialStatus = result.vcResults[0].credentialStatus
        val proofVerificationStatus = result.proofVerificationStatus

        assertEquals(VPVerificationStatus.INVALID,proofVerificationStatus)
        assertNotNull(result)
        assertEquals(VerificationStatus.SUCCESS, result.vcResults[0].status)
        assertEquals(1, credentialStatus.size)
        val credentialStatusEntry = credentialStatus.entries.first()
        assertEquals("revocation", credentialStatusEntry.key)
        assertNull(credentialStatusEntry.value.error)
        assertEquals(credentialStatusEntry.value.isValid, true)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should return success for valid Ed25519Signature2018 VP`() {
        val vp = readClasspathFile("vp/Ed25519Signature2018SignedVP-didKey.json")

        val result = PresentationVerifier().verifyV2(vp)

        assertTrue(result.proofVerificationResult.verificationStatus)
        assertEquals("", result.proofVerificationResult.verificationErrorCode)
    }



    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should return success for valid jwk holder binding VP`() {
        val vp = readClasspathFile("vp/validJWKHolderBindingVP.json")
        val verifier = mockedVerifier()
        val result = verifier.verifyV2(vp)

        assertTrue(result.proofVerificationResult.verificationStatus)
        assertEquals("", result.proofVerificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should skip holder binding for unSupported did VP`() {
        val vp = readClasspathFile("vp/webHolderBindingVP.json")
        val verifier = mockedVerifier()
        val result = verifier.verifyV2(vp)

        assertTrue(result.proofVerificationResult.verificationStatus)
        assertEquals("", result.proofVerificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `verifyV2 should return success when VP holder did-key matches VC subject did-jwk`() {
        val vp = readClasspathFile("vp/crossMethodBindingVP.json")
        val verifier = mockedVerifier()
        val result = verifier.verifyV2(vp)

        assertTrue(result.proofVerificationResult.verificationStatus)
        assertEquals("", result.proofVerificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should return success for valid ES256AlgorithmVP`() {
        mockHttpResponse(
            "https://api.released.mosip.net/identity-service/02b073b8-aacd-472e-b63f-265bb7ccdd9f/did.json",
            readClasspathFile("vp/public_key/didIdentityServiceKey.json")
        )
        val vp = readClasspathFile("vp/ES256AlgorithmVP.json")

        val result = PresentationVerifier().verifyV2(vp)

        assertTrue(result.proofVerificationResult.verificationStatus)
        assertEquals("", result.proofVerificationResult.verificationErrorCode)
        assertTrue(result.vcResults[0].verificationResult.verificationStatus)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should return success for valid ES256KAlgorithmVP`() {
        mockHttpResponse(
            "https://api.released.mosip.net/identity-service/02b073b8-aacd-472e-b63f-265bb7ccdd9f/did.json",
            readClasspathFile("vp/public_key/didIdentityServiceKey.json")
        )
        val vp = readClasspathFile("vp/ES256KAlgorithmVP.json")

        val result = PresentationVerifier().verifyV2(vp)

        assertTrue(result.proofVerificationResult.verificationStatus)
        assertEquals("", result.proofVerificationResult.verificationErrorCode)
        assertTrue(result.vcResults[0].verificationResult.verificationStatus)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should return success for valid JsonWebSignature2020 VP`() {
        mockHttpResponse(
            "https://api.released.mosip.net/identity-service/02b073b8-aacd-472e-b63f-265bb7ccdd9f/did.json",
            readClasspathFile("vp/public_key/didIdentityServiceKey.json")
        )

        val vp = readClasspathFile("vp/JsonWebSignature2020SignedVP-didJws.json")

        val result = PresentationVerifier().verifyV2(vp)

        assertTrue(result.proofVerificationResult.verificationStatus)
        assertNotNull(result.vcResults[0].vc)
        assertNotEquals("", result.vcResults[0].vc)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should return failure for invalid VP signature`() {
        val vp = readClasspathFile("vp/InvalidEd25519Signature2018SignedVP-didKey.json")

        val result = PresentationVerifier().verifyV2(vp)

        assertFalse(result.proofVerificationResult.verificationStatus)
        assertEquals(ERROR_CODE_VERIFICATION_FAILED, result.proofVerificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should return unsupported DID error when public key not found`() {
        val vp = readClasspathFile("vp/InvalidPublicKeyEd25519Signature2018SignedVP-didKey.json")

        assertThrows<UnsupportedDidUrl> { PresentationVerifier().verifyV2(vp) }
    }
    
    @Test
    fun `V2 should throw error when VP is not JSON-LD`() {
        assertThrows<PresentationNotSupportedException> {
            PresentationVerifier().verifyV2("invalid")
        }
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should return failure for invalid Ed25519Signature2020 VP`() {
        val vp = readClasspathFile("vp/Ed25519Signature2020SignedVP-didKey.json")

        val result = PresentationVerifier().verifyV2(vp)

        assertFalse(result.proofVerificationResult.verificationStatus)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should verify VC and return revoked credential status`() {
        val mockStatusListJson = readClasspathFile("ldp_vc/mosipRevokedStatusList.json")
        val vp = readClasspathFile("vp/VPWithRevokedVC.json")

        mockHttpResponse(
            "https://mosip.github.io/inji-config/qa-inji1/mock/did.json",
            readClasspathFile("vp/public_key/didMockKey.json")
        )

        val realUrl =
            "https://injicertify-mock.qa-inji1.mosip.net/v1/certify/credentials/status-list/56622ad1-c304-4d7a-baf0-08836d63c2bf"
        mockHttpResponse(realUrl, mockStatusListJson)

        val result: PresentationResultWithCredentialStatusV2 =
            PresentationVerifier().verifyAndGetCredentialStatusV2(
                vp,
                listOf("revocation")
            )

        assertFalse(result.proofVerificationResult.verificationStatus)
        assertTrue(result.vcResults[0].verificationResult.verificationStatus)

        val credentialStatus = result.vcResults[0].credentialStatus
        val entry = credentialStatus.entries.first()

        assertEquals("revocation", entry.key)
        assertFalse(entry.value.isValid)
        assertNull(entry.value.error)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should verify VC and return unrevoked credential status`() {
        val mockStatusListJson = readClasspathFile("ldp_vc/mosipUnrevokedStatusList.json")
        val vp = readClasspathFile("vp/VPWithUnrevokedVC.json")

        mockHttpResponse(
            "https://mosip.github.io/inji-config/qa-inji1/mock/did.json",
            readClasspathFile("vp/public_key/didMockKey.json")
        )

        val realUrl =
            "https://injicertify-mock.qa-inji1.mosip.net/v1/certify/credentials/status-list/56622ad1-c304-4d7a-baf0-08836d63c2bf"
        mockHttpResponse(realUrl, mockStatusListJson)

        val result: PresentationResultWithCredentialStatusV2 =
            PresentationVerifier().verifyAndGetCredentialStatusV2(
                vp,
                listOf("revocation")
            )

        assertFalse(result.proofVerificationResult.verificationStatus)
        assertTrue(result.vcResults[0].verificationResult.verificationStatus)

        val credentialStatus = result.vcResults[0].credentialStatus
        val entry = credentialStatus.entries.first()

        assertEquals("revocation", entry.key)
        assertTrue(entry.value.isValid)
        assertNull(entry.value.error)
    }


    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should handle P256 key type in did-key extraction`() {
        val vp = readClasspathFile("vp/P256HolderBindingVP.json")
        val verifier = mockedVerifier()
        val result = verifier.verifyV2(vp)
        assertNotNull(result)
        assertTrue(result.proofVerificationResult.verificationStatus)
        assertEquals("", result.proofVerificationResult.verificationErrorCode)
    }

    //Below are testcase for Holder Binding Check

    @Test
    fun `V1 should return success for valid jwk holder binding VP`() {

        val vp = readClasspathFile("vp/validJWKHolderBindingVP.json")

        val verifier = mockedVerifier()

        val result = verifier.verify(vp)

        assertEquals(
            VPVerificationStatus.VALID,
            result.proofVerificationStatus
        )
    }

    @Test
    fun `V1 should verify credential status with valid holder proof`() {

        val vp = readClasspathFile("vp/validJWKHolderBindingVP.json")

        val verifier = mockedVerifier()

        val result =
            verifier.verifyAndGetCredentialStatus(
                vp,
                listOf("revocation")
            )

        assertEquals(
            VPVerificationStatus.VALID,
            result.proofVerificationStatus
        )

        assertEquals(1, result.vcResults.size)
    }

    @Test
    fun `V1 should return failure when holder is missing`() {

        val vp = readClasspathFile("vp/VPWithMissingHolder.json")

        val verifier = mockedVerifier()

        val result = verifier.verify(vp)

        assertEquals(
            VPVerificationStatus.INVALID,
            result.proofVerificationStatus
        )
    }

    @Test
    fun `V1 should return failure for invalid holder binding VP`() {

        val vp = readClasspathFile("vp/InvalidHolderBindingVP.json")

        val verifier = mockedVerifier()

        val result = verifier.verify(vp)

        assertEquals(
            VPVerificationStatus.INVALID,
            result.proofVerificationStatus
        )
    }

    @Test
    fun `V1 should fail for malformed did-jwk`() {

        val vp = readClasspathFile("vp/VPWithMalformedJwk.json")

        val verifier = mockedVerifier()

        val result = verifier.verify(vp)

        assertEquals(
            VPVerificationStatus.INVALID,
            result.proofVerificationStatus
        )
    }

    @Test
    fun `V1 should fail for invalid holder proof`() {

        val vp = readClasspathFile("vp/InvalidHolderBindingVP.json")

        val verifier = mockedVerifier()

        val result =
            verifier.verifyAndGetCredentialStatus(
                vp,
                emptyList()
            )

        assertEquals(
            VPVerificationStatus.INVALID,
            result.proofVerificationStatus
        )
    }

    @Test
    fun `V2 should return failure when verifiableCredential is missing`() {
        val vp = readClasspathFile("vp/vpWithMissingVerifiableCredential.json")

        val verifier = mockedVerifier()
        val result = verifier.verifyV2(vp)

        assertFalse(result.proofVerificationResult.verificationStatus)
        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            result.proofVerificationResult.verificationErrorCode
        )
    }

    @Test
    fun `V2 should return failure when holder is missing`() {
        val vp = readClasspathFile("vp/VPWithMissingHolder.json")

        val verifier = mockedVerifier()
        val result = verifier.verifyV2(vp)

        assertFalse(result.proofVerificationResult.verificationStatus)
        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            result.proofVerificationResult.verificationErrorCode
        )
    }

    @Test
    fun `V2 should return failure when credentialSubject is missing or empty`() {
        val vp = readClasspathFile("vp/VPWithEmptySubject.json")

        val verifier = mockedVerifier()
        val result = verifier.verifyV2(vp)

        assertFalse(result.proofVerificationResult.verificationStatus)
        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            result.proofVerificationResult.verificationErrorCode
        )
    }

    @Test
    fun `V2 should return failure when subject ID is missing`() {
        val vp = readClasspathFile("vp/VPWithSubjectMissingId.json")

        val verifier = mockedVerifier()
        val result = verifier.verifyV2(vp)

        assertFalse(result.proofVerificationResult.verificationStatus)
        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            result.proofVerificationResult.verificationErrorCode
        )
    }

    @Test
    fun `V2 should return failure when did-jwk is malformed`() {
        val vp = readClasspathFile("vp/VPWithMalformedJwk.json")

        val verifier = mockedVerifier()
        val result = verifier.verifyV2(vp)

        assertFalse(result.proofVerificationResult.verificationStatus)
        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            result.proofVerificationResult.verificationErrorCode
        )
        assertEquals(
            "Fail to decode input to extract public key",
            result.proofVerificationResult.verificationMessage
        )
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should return failed for invalid jwk holder binding VP`() {

        val vp = readClasspathFile("vp/InvalidJWKHolderBindingVP.json")

        val verifier = spyk(PresentationVerifier(), recordPrivateCalls = true)

        every {
            verifier["verifyPresentationProof"](any<JsonLDObject>())
        } returns true

        val result = verifier.verifyV2(vp)

        assertFalse(result.proofVerificationResult.verificationStatus)

        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            result.proofVerificationResult.verificationErrorCode
        )
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should return failed for invalid holder binding VP`() {
        val vp = readClasspathFile("vp/InvalidHolderBindingVP.json")

        val verifier = mockedVerifier()
        val result = verifier.verifyV2(vp)

        assertFalse(result.proofVerificationResult.verificationStatus)
        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            result.proofVerificationResult.verificationErrorCode
        )
    }

    @Test
    fun `V2 should return failure for unsupported multi-codec key type`() {
        val vp = readClasspathFile("vp/UnsupportedKeyTypeVP.json")

        val verifier = mockedVerifier()
        val result = verifier.verifyV2(vp)

        assertFalse(result.proofVerificationResult.verificationStatus)
        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            result.proofVerificationResult.verificationErrorCode
        )
    }

    @Test
    fun `comparePublicKeyJson should return false for unknown key types`() {
        val verifier = PresentationVerifier()
        val method = verifier.javaClass.getDeclaredMethod("comparePublicKeyJson", org.json.JSONObject::class.java, org.json.JSONObject::class.java)
        method.isAccessible = true

        val key1 = org.json.JSONObject().put("kty", "UNKNOWN")
        val key2 = org.json.JSONObject().put("kty", "UNKNOWN")

        val result = method.invoke(verifier, key1, key2) as Boolean
        assertFalse(result)
    }

    @Test
    fun `comparePublicKeyJson should validate RSA key components`() {
        val verifier = PresentationVerifier()
        val method = verifier.javaClass.getDeclaredMethod("comparePublicKeyJson", org.json.JSONObject::class.java, org.json.JSONObject::class.java)
        method.isAccessible = true

        val key1 = org.json.JSONObject().put("kty", "RSA").put("n", "n-val").put("e", "e-val")
        val key2 = org.json.JSONObject().put("kty", "RSA").put("n", "n-val").put("e", "e-val")
        val key3 = org.json.JSONObject().put("kty", "RSA").put("n", "n-val").put("e", "different-e-val")

        val resultTrue = method.invoke(verifier, key1, key2) as Boolean
        val resultFalse = method.invoke(verifier, key1, key3) as Boolean
        assertTrue(resultTrue)
        assertFalse(resultFalse)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `V2 should verify credential status with holder binding enabled`() {

        val vp = readClasspathFile("vp/validJWKHolderBindingVP.json")

        val verifier = spyk(PresentationVerifier(), recordPrivateCalls = true)

        every {
            verifier["verifyPresentationProof"](any<JsonLDObject>())
        } returns true

        val result =
            verifier.verifyAndGetCredentialStatusV2(
                vp,
                listOf("revocation")
            )

        assertTrue(result.proofVerificationResult.verificationStatus)

        assertEquals(
            "",
            result.proofVerificationResult.verificationErrorCode
        )

        assertEquals(1, result.vcResults.size)
    }

    @Test
    fun `V2 credential status should fail for invalid holder proof`() {

        val vp = readClasspathFile("vp/InvalidHolderBindingVP.json")

        val verifier = spyk(PresentationVerifier(), recordPrivateCalls = true)

        every {
            verifier["verifyPresentationProof"](any<JsonLDObject>())
        } returns true

        val result =
            verifier.verifyAndGetCredentialStatusV2(
                vp,
                emptyList()
            )
        assertFalse(result.proofVerificationResult.verificationStatus)

        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            result.proofVerificationResult.verificationErrorCode
        )
    }

    @Test
    fun `validateHolderProofOfPossession should fail when proof is missing`() {

        val verifier = PresentationVerifier()

        val vpJson = org.json.JSONObject(
            readClasspathFile("vp/validJWKHolderBindingVP.json")
        )

        vpJson.remove("proof")

        val jsonLdObject =
            JsonLDObject.fromJson(vpJson.toString())

        val holderKey = org.json.JSONObject()
            .put("kty", "OKP")
            .put("crv", "Ed25519")
            .put("x", "dummy")

        val method =
            verifier.javaClass.getDeclaredMethod(
                "validateHolderProofOfPossession",
                JsonLDObject::class.java,
                org.json.JSONObject::class.java
            )

        method.isAccessible = true

        assertThrows<java.lang.reflect.InvocationTargetException> {
            method.invoke(verifier, jsonLdObject, holderKey)
        }
    }

    @Test
    fun `validateHolderProofOfPossession should succeed for matching holder proof`() {

        val verifier = PresentationVerifier()

        val vp =
            readClasspathFile("vp/Ed25519Signature2018SignedVP-didKey.json")

        val jsonLdObject = JsonLDObject.fromJson(vp)

        val extractMethod =
            verifier.javaClass.getDeclaredMethod(
                "extractPublicKeyJson",
                String::class.java
            )

        extractMethod.isAccessible = true

        val holder =
            jsonLdObject.jsonObject["holder"] as String

        val holderKey =
            extractMethod.invoke(verifier, holder) as org.json.JSONObject

        val method =
            verifier.javaClass.getDeclaredMethod(
                "validateHolderProofOfPossession",
                JsonLDObject::class.java,
                org.json.JSONObject::class.java
            )

        method.isAccessible = true

        method.invoke(verifier, jsonLdObject, holderKey)
    }

    @Test
    fun `validateHolderProofOfPossession should fail for mismatched verificationMethod`() {

        val verifier = PresentationVerifier()

        val vp =
            readClasspathFile("vp/InvalidHolderBindingVP.json")

        val jsonLdObject = JsonLDObject.fromJson(vp)

        val extractMethod =
            verifier.javaClass.getDeclaredMethod(
                "extractPublicKeyJson",
                String::class.java
            )

        extractMethod.isAccessible = true

        val holder =
            jsonLdObject.jsonObject["holder"] as String

        val holderKey =
            extractMethod.invoke(verifier, holder) as org.json.JSONObject

        val method =
            verifier.javaClass.getDeclaredMethod(
                "validateHolderProofOfPossession",
                JsonLDObject::class.java,
                org.json.JSONObject::class.java
            )

        method.isAccessible = true

        val exception = assertThrows<java.lang.reflect.InvocationTargetException> {
            method.invoke(verifier, jsonLdObject, holderKey)
        }

        val cause = exception.cause as HolderBindingException

        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            cause.errorCode
        )
    }

    @Test
    fun `validateHolderProofOfPossession should fail when verificationMethod missing`() {

        val verifier = PresentationVerifier()

        val vpJson = org.json.JSONObject(
            readClasspathFile("vp/validJWKHolderBindingVP.json")
        )

        vpJson.getJSONObject("proof").remove("verificationMethod")

        val jsonLdObject =
            JsonLDObject.fromJson(vpJson.toString())

        val holderKey = org.json.JSONObject()
            .put("kty", "OKP")
            .put("crv", "Ed25519")
            .put("x", "dummy")

        val method =
            verifier.javaClass.getDeclaredMethod(
                "validateHolderProofOfPossession",
                JsonLDObject::class.java,
                org.json.JSONObject::class.java
            )

        method.isAccessible = true

        val exception = assertThrows<java.lang.reflect.InvocationTargetException> {
            method.invoke(verifier, jsonLdObject, holderKey)
        }

        val cause = exception.cause as HolderBindingException

        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            cause.errorCode
        )
    }

    @Test
    fun `validateHolderProofOfPossession should fail for malformed verificationMethod`() {

        val verifier = PresentationVerifier()

        val vpJson = org.json.JSONObject(
            readClasspathFile("vp/validJWKHolderBindingVP.json")
        )

        vpJson.getJSONObject("proof")
            .put("verificationMethod", "did:jwk:invalid")

        val jsonLdObject =
            JsonLDObject.fromJson(vpJson.toString())

        val holderKey = org.json.JSONObject()
            .put("kty", "OKP")
            .put("crv", "Ed25519")
            .put("x", "dummy")

        val method =
            verifier.javaClass.getDeclaredMethod(
                "validateHolderProofOfPossession",
                JsonLDObject::class.java,
                org.json.JSONObject::class.java
            )

        method.isAccessible = true

        val exception = assertThrows<java.lang.reflect.InvocationTargetException> {
            method.invoke(verifier, jsonLdObject, holderKey)
        }

        val cause = exception.cause as HolderBindingException

        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            cause.errorCode
        )
    }

    @Test
    fun `validateHolderProofOfPossession should skip unsupported DID method`() {

        val verifier = PresentationVerifier()

        val vpJson = org.json.JSONObject(
            readClasspathFile("vp/Ed25519Signature2018SignedVP-didKey.json")
        )

        vpJson.getJSONObject("proof")
            .put(
                "verificationMethod",
                "did:web:example.com#key-1"
            )

        val jsonLdObject =
            JsonLDObject.fromJson(vpJson.toString())

        val holderKey = org.json.JSONObject()
            .put("kty", "OKP")
            .put("crv", "Ed25519")
            .put("x", "dummy")

        val method =
            verifier.javaClass.getDeclaredMethod(
                "validateHolderProofOfPossession",
                JsonLDObject::class.java,
                org.json.JSONObject::class.java
            )

        method.isAccessible = true

        assertDoesNotThrow {
            method.invoke(verifier, jsonLdObject, holderKey)
        }
    }

    @Test
    fun `V2 should return failure when verifiableCredential array is empty`() {

        val vp = readClasspathFile("vp/EmptyVerifiableCredentialVP.json")

        val verifier = spyk(PresentationVerifier(), recordPrivateCalls = true)

        every {
            verifier["verifyPresentationProof"](any<JsonLDObject>())
        } returns true

        val result = verifier.verifyV2(vp)

        assertFalse(result.proofVerificationResult.verificationStatus)

        assertEquals(
            HOLDER_VERIFICATION_FAIL_ERROR,
            result.proofVerificationResult.verificationErrorCode
        )
    }

   
}