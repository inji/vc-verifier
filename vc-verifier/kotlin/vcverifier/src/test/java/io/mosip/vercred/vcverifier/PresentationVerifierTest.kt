package io.mosip.vercred.vcverifier

import io.mockk.mockkObject
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
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows
import testutils.mockHttpResponse
import testutils.readClasspathFile
import java.util.concurrent.TimeUnit

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PresentationVerifierTest {

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

        assertEquals(VPVerificationStatus.VALID,verificationResult.proofVerificationStatus)
        assertEquals(verificationResult.vcResults[0].status, VerificationStatus.SUCCESS)
        assertNotEquals(verificationResult.vcResults[0].vc, "")
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
}