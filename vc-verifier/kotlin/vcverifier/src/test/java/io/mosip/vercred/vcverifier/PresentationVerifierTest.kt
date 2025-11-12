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
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import java.util.logging.Logger

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PresentationVerifierTest {

    @BeforeAll
    fun setup() {
        Util.documentLoader = LocalDocumentLoader
    }

    @AfterAll
    fun teardownAll() {
        Util.documentLoader = null
    }

    private val logger = Logger.getLogger(PresentationVerifierTest::class.java.name)

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return true for valid presentation verification success Ed25519Signature2018`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/Ed25519Signature2018SignedVP-didKey.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = PresentationVerifier().verify(vc)

        assertEquals(VPVerificationStatus.VALID,verificationResult.proofVerificationStatus)
        //check when we have a supported vc
        //assertEquals(verificationResult.vcResults, emptyList<VCResult>())

    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return true for valid presentation verification success JsonWebSignature2020`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/JsonWebSignature2020SignedVP-didJws.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = PresentationVerifier().verify(vc)

        assertEquals(VPVerificationStatus.VALID,verificationResult.proofVerificationStatus)
        assertEquals(verificationResult.vcResults[0].status, VerificationStatus.SUCCESS)
        assertNotEquals(verificationResult.vcResults[0].vc, "")
        assertNotNull(verificationResult.vcResults[0].vc)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return false for invalid presentation verification`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/InvalidEd25519Signature2018SignedVP-didKey.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = PresentationVerifier().verify(vc)
        assertEquals(VPVerificationStatus.INVALID,verificationResult.proofVerificationStatus)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should throw error when public key not found false`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/InvalidPublicKeyEd25519Signature2018SignedVP-didKey.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        assertThrows<UnsupportedDidUrl> { PresentationVerifier().verify(vc) }
    }

    @Test
    fun `should throw error when vc is not jsonld`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/InvalidPublicKeyEd25519Signature2018SignedVP-didKey.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        assertThrows<PresentationNotSupportedException> { PresentationVerifier().verify("invalid") }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should throw error for invalid presentation verification of Ed25519Signature2020`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/Ed25519Signature2020SignedVP-didKey.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = PresentationVerifier().verify(vc)

        assertEquals(VPVerificationStatus.INVALID,verificationResult.proofVerificationStatus)

    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `should verify VC and return VC status as revoked`() {
        val mockStatusList = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/mosipRevokedStatusList.json")
        val mockStatusListJson = String(Files.readAllBytes(mockStatusList.toPath()))

        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/VPWithRevokedVC.json")
        val vp = String(Files.readAllBytes(file.toPath()))

        val realUrl = "https://injicertify-mock.qa-inji1.mosip.net/v1/certify/credentials/status-list/56622ad1-c304-4d7a-baf0-08836d63c2bf"

        mockkObject(NetworkManagerClient.Companion)

        io.mockk.every {
            NetworkManagerClient.sendHTTPRequest(realUrl, any())
        } answers {
            val mapper = com.fasterxml.jackson.module.kotlin.jacksonObjectMapper()
            mapper.readValue(mockStatusListJson, Map::class.java) as Map<String, Any>?
        }

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
        assertEquals("revocation", credentialStatus[0].purpose)
        assertEquals(1, credentialStatus[0].status)
        assertNull(credentialStatus[0].error)
        assertFalse(credentialStatus[0].valid)
    }

    @Test
    @Timeout(20, unit = TimeUnit.SECONDS)
    fun `should verify VC and return VC status as unrevoked`() {
        val mockStatusList = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/mosipUnrevokedStatusList.json")
        val mockStatusListJson = String(Files.readAllBytes(mockStatusList.toPath()))

        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/VPWithUnrevokedVC.json")
        val vp = String(Files.readAllBytes(file.toPath()))

        val realUrl = "https://injicertify-mock.qa-inji1.mosip.net/v1/certify/credentials/status-list/56622ad1-c304-4d7a-baf0-08836d63c2bf"

        mockkObject(NetworkManagerClient.Companion)

        io.mockk.every {
            NetworkManagerClient.sendHTTPRequest(realUrl, any())
        } answers {
            val mapper = com.fasterxml.jackson.module.kotlin.jacksonObjectMapper()
            mapper.readValue(mockStatusListJson, Map::class.java) as Map<String, Any>?
        }

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
        assertEquals("revocation", credentialStatus[0].purpose)
        assertEquals(0, credentialStatus[0].status)
        assertNull(credentialStatus[0].error)
        assert(credentialStatus[0].valid)
    }
}