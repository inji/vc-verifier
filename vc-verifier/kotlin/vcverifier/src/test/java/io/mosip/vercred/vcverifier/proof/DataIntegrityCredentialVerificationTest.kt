package io.mosip.vercred.vcverifier.proof

import io.mosip.vercred.vcverifier.CredentialsVerifier
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.utils.LocalDocumentLoader
import io.mosip.vercred.vcverifier.utils.Util
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DataIntegrityCredentialVerificationTest {

    @BeforeAll
    fun setUp() {
        Util.documentLoader = LocalDocumentLoader
    }

    @AfterAll
    fun tearDown() {
        Util.documentLoader = null
    }

    private fun vector(name: String): String =
        javaClass.classLoader.getResourceAsStream("w3c/$name")!!
            .bufferedReader().use { it.readText() }

    private fun verify(credential: String) =
        CredentialsVerifier().verify(credential, CredentialFormat.LDP_VC)

    @Test
    fun `verifies an eddsa-rdfc-2022 credential through the credential verifier`() {
        val result = verify(vector("eddsa-rdfc-2022-signed.json"))

        assertTrue(result.verificationStatus, result.verificationMessage)
    }

    @Test
    fun `verifies an ecdsa-rdfc-2019 P-256 credential through the credential verifier`() {
        val result = verify(vector("ecdsa-rdfc-2019-p256-signed.json"))

        assertTrue(result.verificationStatus, result.verificationMessage)
    }

    @Test
    fun `rejects a credential whose subject was tampered with after signing`() {
        val tampered = JSONObject(vector("eddsa-rdfc-2022-signed.json")).apply {
            getJSONObject("credentialSubject").put("alumniOf", "Tampered University")
        }.toString()

        assertFalse(verify(tampered).verificationStatus)
    }

    @Test
    fun `rejects a credential whose proofValue was altered`() {
        val credential = JSONObject(vector("eddsa-rdfc-2022-signed.json"))
        val proof = credential.getJSONObject("proof")
        val proofValue = proof.getString("proofValue")
        // flip the final base58 character so the signature stays well-formed but invalid
        val flipped = proofValue.dropLast(1) + if (proofValue.last() == 'a') 'b' else 'a'
        proof.put("proofValue", flipped)

        assertFalse(verify(credential.toString()).verificationStatus)
    }

    @Test
    fun `rejects a credential proof asserted for the wrong purpose`() {
        val credential = JSONObject(vector("eddsa-rdfc-2022-signed.json")).apply {
            getJSONObject("proof").put("proofPurpose", "authentication")
        }.toString()

        assertFalse(verify(credential).verificationStatus)
    }
}
