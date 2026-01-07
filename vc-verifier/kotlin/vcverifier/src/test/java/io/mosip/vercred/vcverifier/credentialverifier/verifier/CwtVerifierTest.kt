package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.nimbusds.jose.jwk.*
import com.upokecenter.cbor.CBORObject
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.utils.Util
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import se.digg.cose.COSEKey
import se.digg.cose.HeaderKeys
import se.digg.cose.Attribute
import se.digg.cose.Sign1COSEObject
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.*


class CwtVerifierTest {

    @Test
    fun `should verify valid CWT`() {
//
//        val kpg = KeyPairGenerator.getInstance("EC")
//        kpg.initialize(256)
//        val keyPair = kpg.generateKeyPair()
//
//        val publicKey = keyPair.public as ECPublicKey
//        val privateKey = keyPair.private as ECPrivateKey
//
//        val kid = "test-key-1"
//
//
//        val jwk = ECKey.Builder(Curve.P_256, publicKey)
//            .privateKey(privateKey)
//            .keyID(kid)
//            .build()
//
//        val jwksJson = JWKSet(jwk.toPublicJWK()).toJSONObject().toString()
//
//        val issuer = "https://issuer.example.com"
//
//        val issuerMetadataJson = """
//            {
//              "jwks_uri": "$issuer/jwks"
//            }
//        """.trimIndent()
//
//
//        val claims = CBORObject.NewMap().apply {
//            Add(1, issuer)
//            Add(4, Date().time / 1000 + 600)
//        }
//
//
//        val sign1 = Sign1COSEObject()
//
//        sign1.addAttribute(
//            HeaderKeys.Algorithm,
//            CBORObject.FromObject(-7),           // ES256
//            Attribute.PROTECTED
//        )
//
//        sign1.addAttribute(
//            HeaderKeys.KID,
//            CBORObject.FromObject(kid.toByteArray()),
//            Attribute.PROTECTED
//        )
//
//        sign1.SetContent(claims.EncodeToBytes())
//
//        val coseKey = COSEKey(publicKey, privateKey)
//        sign1.sign(coseKey)
//
//        val coseHex = sign1.EncodeToBytes().joinToString("") {
//            "%02x".format(it)
//        }
//
//        mockkObject(Util)
//
//        every { Util.httpGet(any()) } answers {
//            when (firstArg<String>()) {
//                "$issuer/.well-known/openid-credential-issuer" -> issuerMetadataJson
//                "$issuer/jwks" -> jwksJson
//                else -> null
//            }
//        }
//
        val coseHex = "d28443a10126a0590101a501782b6469643a7765623a706979757368373033342e6769746875622e696f3a4449443a7069797573682d6d6163041a6a4b4dc4051a695dffc4061a695dffc418a958bcac61316a3339313835393234333861320a61346c4a616e61726468616e20425361386a30342d31382d3139383461390162313078294e657720486f7573652c204e656172204d6574726f204c696e652c2042656e67616c7572752c204b41623131756a616e61726468616e406578616d706c652e636f6d6231326d2b39313938373635343332313062313362494e623632a361306435323439613100613200623635a3613064353234396131026132006568656c6c6f65776f726c64584078f7ac67ebcc1389d16c25c201115e9ee9779c9b5bda1bdfa3eabb017af3d86c29c8b236e224ce15f000489d250a89e8fd2d8a4de3321d72d1055130dc75b2d7"
        assertTrue(CwtVerifier().verify(coseHex))
    }

}
