package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mockk.mockkObject
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import testutils.mockHttpResponse
import testutils.readClasspathFile
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import org.junit.jupiter.api.Assertions.assertFalse


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CwtVerifierTest {

    @BeforeAll
    fun setup() {
        mockkObject(NetworkManagerClient.Companion)
        loadMockPublicKeys()
    }

    @Test
    fun `should verify valid EC signed CWT`() {
        val coseHex = readClasspathFile("cwt_vc/valid-ec-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertTrue(CwtVerifier().verify(coseHex))
    }

    @Test
    fun `should fail when EC CWT is verified with wrong public key`() {


        val coseHex = readClasspathFile("cwt_vc/invalid-ec-cwt.hex")
            .replace("\\s".toRegex(), "")

    }


    private fun loadMockPublicKeys() {
        mockHttpResponse("https://221f38cc3ffc.ngrok-free.app/v1/certify/.well-known/jwks.json", readClasspathFile("cwt_vc/public_key/jwksECkey.json"))
        mockHttpResponse("https://9c65dc69fafc.ngrok-free.app/v1/certify/.well-known/jwks.json", readClasspathFile("cwt_vc/public_key/jwksinvalidECkey.json"))
    }
}