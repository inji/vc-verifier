package io.mosip.vercred.vcverifier.credentialverifier.verifier

import COSE.*
import com.nimbusds.jose.jwk.*
import com.upokecenter.cbor.CBORObject
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.utils.Util
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.*


class CwtVerifierTest {

    @Test
    fun `should verify valid CWT`() {

        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(256)
        val keyPair = kpg.generateKeyPair()

        val publicKey = keyPair.public as ECPublicKey
        val privateKey = keyPair.private as ECPrivateKey

        val kid = "test-key-1"


        val jwk = ECKey.Builder(Curve.P_256, publicKey)
            .privateKey(privateKey)
            .keyID(kid)
            .build()

        val jwksJson = JWKSet(jwk.toPublicJWK()).toJSONObject().toString()

        val issuer = "https://issuer.example.com"

        val issuerMetadataJson = """
            {
              "jwks_uri": "$issuer/jwks"
            }
        """.trimIndent()


        val claims = CBORObject.NewMap().apply {
            Add(1, issuer)
            Add(4, Date().time / 1000 + 600)
        }


        val sign1 = Sign1Message()

        sign1.addAttribute(
            HeaderKeys.Algorithm,
            AlgorithmID.ECDSA_256.AsCBOR(),
            Attribute.PROTECTED
        )

        sign1.addAttribute(
            HeaderKeys.KID,
            CBORObject.FromObject(kid.toByteArray()),
            Attribute.PROTECTED
        )

        sign1.SetContent(claims.EncodeToBytes())

        val oneKey = OneKey(publicKey, privateKey)
        sign1.sign(oneKey)

        val coseHex = sign1.EncodeToBytes().joinToString("") {
            "%02x".format(it)
        }

        mockkObject(Util)

        every { Util.httpGet(any()) } answers {
            when (firstArg<String>()) {
                "$issuer/.well-known/openid-credential-issuer" -> issuerMetadataJson
                "$issuer/jwks" -> jwksJson
                else -> null
            }
        }

        assertTrue(CwtVerifer().verify(coseHex))
    }

}
