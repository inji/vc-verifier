package io.mosip.vercred.vcverifier.proof

import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.utils.LocalDocumentLoader
import io.mosip.vercred.vcverifier.utils.Util
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.assertThrows
import testutils.readClasspathFile

/** Published W3C vectors from vc-di-eddsa and vc-di-ecdsa, TestVectors/. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DataIntegrityProofVerifierTest {
    @BeforeAll
    fun setUp() {
        Util.documentLoader = LocalDocumentLoader
    }

    @AfterAll
    fun tearDown() {
        Util.documentLoader = null
    }

    @Test
    fun `verifies official eddsa-rdfc-2022 vector and hash data`() {
        val document = readClasspathFile("w3c/eddsa-rdfc-2022-signed.json")
        val json = JSONObject(document)
        val hashData = DataIntegrityProofVerifier.createHashData(json, json.getJSONObject("proof"))

        assertEquals(
            "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b" +
                "0517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017",
            hashData.toHex()
        )
        assertTrue(DataIntegrityProofVerifier.verify(document, "assertionMethod"))
    }

    @Test
    fun `verifies official ecdsa-rdfc-2019 P-256 vector and hash data`() {
        val document = readClasspathFile("w3c/ecdsa-rdfc-2019-p256-signed.json")
        val json = JSONObject(document)
        val hashData = DataIntegrityProofVerifier.createHashData(json, json.getJSONObject("proof"))

        assertEquals(
            "3a8a522f689025727fb9d1f0fa99a618da023e8494ac74f51015d009d35abc2e" +
                "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017",
            hashData.toHex()
        )
        assertTrue(DataIntegrityProofVerifier.verify(document, "assertionMethod"))
    }

    @Test
    fun `rejects tampered official vector`() {
        val json = JSONObject(readClasspathFile("w3c/eddsa-rdfc-2022-signed.json"))
        json.put("name", "Tampered credential")

        assertFalse(DataIntegrityProofVerifier.verify(json.toString(), "assertionMethod"))
    }

    @Test
    fun `rejects mismatched challenge before signature verification`() {
        val document = readClasspathFile("w3c/eddsa-rdfc-2022-signed.json")
        assertThrows<SignatureVerificationException> {
            DataIntegrityProofVerifier.verify(document, "assertionMethod", expectedChallenge = "wrong")
        }
    }

    @Test
    fun `recognizes and rejects multiple data integrity proofs`() {
        val json = JSONObject(readClasspathFile("w3c/eddsa-rdfc-2022-signed.json"))
        val proof = json.getJSONObject("proof")
        json.put("proof", JSONArray().put(proof).put(JSONObject(proof.toString())))

        assertTrue(DataIntegrityProofVerifier.isDataIntegrityProof(json.toString()))
        val exception = assertThrows<SignatureNotSupportedException> {
            DataIntegrityProofVerifier.verify(json.toString(), "assertionMethod")
        }
        assertEquals("Multiple Data Integrity proofs are not supported", exception.message)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
