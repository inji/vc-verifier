package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.danubetech.keyformats.jose.JWSAlgorithm
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
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.util.*
import java.security.KeyFactory


class CwtVerifierTest {

//    @Test
//    fun `should verify valid CWT`() {
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
//        val coseHex = "d284585da201260458576469643a7765623a706979757368373033342e6769746875622e696f3a4449443a7069797573682d6d6163236d5a355034654a7a7a6c65776c714e55374d6a4178614334456a6e374d64657168624b344e65307a676e59a058fda501782768747470733a2f2f696e6a69636572746966792e71612d696e6a69312e6d6f7369702e6e65742f041a6a4dc51a051a6960771a061a6960771a18a958bcac61316a3339313835393234333861320a61346c4a616e61726468616e20425361386a30342d31382d3139383461390162313078294e657720486f7573652c204e656172204d6574726f204c696e652c2042656e67616c7572752c204b41623131756a616e61726468616e406578616d706c652e636f6d6231326d2b39313938373635343332313062313362494e623632a361306435323439613100613200623635a3613064353234396131026132006568656c6c6f65776f726c6458408fde69832c10c9ebe20982b2971d2de6bb30f539605cc82a5f21c0412c710ed0be774ca00a9f6245948bbc3464bf3c51347a3f8e4c85a619b34c22b4a44d42ec"
//        assertTrue(CwtVerifier().verify(coseHex))
//    }

}
