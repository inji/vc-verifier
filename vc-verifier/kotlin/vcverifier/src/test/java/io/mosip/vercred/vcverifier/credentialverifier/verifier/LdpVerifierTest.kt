package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.utils.LocalDocumentLoader
import io.mosip.vercred.vcverifier.utils.Util
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows
import org.springframework.util.ResourceUtils
import testutils.mockHttpResponse
import testutils.readClasspathFile
import java.nio.file.Files
import java.util.concurrent.TimeUnit

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LdpVerifierTest {

    @BeforeAll
    fun setup() {
        Util.documentLoader = LocalDocumentLoader
        mockkObject(NetworkManagerClient)
        loadMockPublicKeys()
    }

    @AfterAll
    fun teardownAll() {
        Util.documentLoader = null
    }


    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return true for valid ps256 credential`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/PS256SignedMosipVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertTrue(LdpVerifier().verify(vc))
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return false for invalid credential`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/tamperedVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertFalse(LdpVerifier().verify(vc))
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should successfully verify valid sunbird credential`(){
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/Ed25519Signature2020SignedSunbirdVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertTrue(LdpVerifier().verify(vc))
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should throw error if did url is not valid while verify valid sunbird credential`(){
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/InvalidDidUrlSunbirdVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        val exception = assertThrows<UnsupportedDidUrl> {
            LdpVerifier().verify(vc)
        }
        assertEquals("Unsupported DID method: web1", exception.message)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should successfully verify valid ed25519Signature2018 signed credential with did verification method`(){
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/Ed25519Signature2018SignedVC-did.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertTrue(LdpVerifier().verify(vc))
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should successfully verify valid ed25519Signature2018 signed credential with https verification method`(){
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/Ed25519Signature2018SignedVC-https.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertTrue(LdpVerifier().verify(vc))
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should successfully verify valid rs256 credential`(){
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/RS256SignedMosipVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertTrue(LdpVerifier().verify(vc))
    }

    private fun loadMockPublicKeys() {
        mockHttpResponse("https://vharsh.github.io/DID/mock-public-key2.json", readClasspathFile("ldp_vc/public_key/httpsMockKey2.json"))
        mockHttpResponse("https://vharsh.github.io/DID/mock-public-key.json",readClasspathFile("ldp_vc/public_key/httpsMockKey.json"))
        mockHttpResponse("https://api.collab.mosip.net/.well-known/ida-public-key.json",readClasspathFile("ldp_vc/public_key/idaPublicKey.json"))
        mockHttpResponse("https://api.released.mosip.net/identity-service/02b073b8-aacd-472e-b63f-265bb7ccdd9f/did.json",readClasspathFile("ldp_vc/public_key/didMosipKey.json"))
        mockHttpResponse("https://vharsh.github.io/DID/local/did.json",readClasspathFile("ldp_vc/public_key/didEdPublicKey.json"))
    }
}