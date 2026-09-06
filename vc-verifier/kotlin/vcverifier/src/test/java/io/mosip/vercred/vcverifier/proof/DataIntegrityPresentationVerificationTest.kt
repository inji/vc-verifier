package io.mosip.vercred.vcverifier.proof

import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.utils.LocalDocumentLoader
import io.mosip.vercred.vcverifier.utils.Util
import org.json.JSONObject
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.assertThrows

/**
 * Presentations carrying a DataIntegrityProof, signed with an independent JSON-LD
 * implementation so the fixtures double as a cross-implementation check.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DataIntegrityPresentationVerificationTest {

    private val challenge = "n-0S6_WzA2Mj"
    private val domain = "https://verifier.example/openid4vp"

    @BeforeAll
    fun setUp() {
        Util.documentLoader = LocalDocumentLoader
    }

    @AfterAll
    fun tearDown() {
        Util.documentLoader = null
    }

    private fun presentation(name: String): String =
        javaClass.classLoader.getResourceAsStream("w3c/$name")!!
            .bufferedReader().use { it.readText() }

    private fun verify(
        vp: String,
        expectedChallenge: String? = challenge,
        expectedDomain: String? = domain,
    ) = DataIntegrityProofVerifier.verify(
        vp,
        expectedProofPurpose = "authentication",
        expectedChallenge = expectedChallenge,
        expectedDomain = expectedDomain,
    )

    @Test
    fun `verifies an eddsa-rdfc-2022 presentation bound to its challenge and domain`() {
        assertTrue(verify(presentation("eddsa-rdfc-2022-presentation.json")))
    }

    @Test
    fun `verifies an ecdsa-rdfc-2019 P-256 presentation`() {
        assertTrue(verify(presentation("ecdsa-rdfc-2019-p256-presentation.json")))
    }

    @Test
    fun `rejects a presentation replayed against a different nonce`() {
        assertThrows<SignatureVerificationException> {
            verify(presentation("eddsa-rdfc-2022-presentation.json"), expectedChallenge = "some-other-nonce")
        }
    }

    @Test
    fun `rejects a presentation addressed to a different verifier`() {
        assertThrows<SignatureVerificationException> {
            verify(presentation("eddsa-rdfc-2022-presentation.json"), expectedDomain = "https://attacker.example")
        }
    }

    @Test
    fun `rejects a presentation whose enclosed credential was swapped after signing`() {
        val vp = JSONObject(presentation("eddsa-rdfc-2022-presentation.json"))
        vp.getJSONArray("verifiableCredential").getJSONObject(0)
            .getJSONObject("credentialSubject").put("alumniOf", "Tampered University")

        assertFalse(verify(vp.toString()))
    }

    @Test
    fun `rejects a presentation whose holder was substituted`() {
        val vp = JSONObject(presentation("eddsa-rdfc-2022-presentation.json"))
        vp.put("holder", "did:example:someone-else")

        assertFalse(verify(vp.toString()))
    }
}
