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
////        val coseHex = "d83dd28443a10126a059015fa701782b6469643a7765623a706979757368373033342e6769746875622e696f3a4449443a7069797573682d6d6163041a6a4a2f79051a695ce179061a695ce1796d44617465204f662042697274686a32352d30352d313939306946756c6c204e616d65684a6f686e20446f656446616365a36b4461746120666f726d617465496d6167656f446174612073756220666f726d6174644a455047644461746178be646174613a696d6167652f706e673b6261736536342c6956424f5277304b47676f414141414e5355684555674141414277414141415143415941414141467a782f764141414151306c455156513479324e674741576a594c41445269435943574c382f2f382f48556c774a724969617371424c5077506c5752456b76795070704671636b7a30446c4957494a364652587757486a32306b4273466f3241514151445370535370396b6851704141414141424a52553545726b4a6767673d3d5840baafa376fee591618a03c10dc33b97e5d87053b52882640e3a317fbfa57b571c8c4c3d1bf2a67f68f7d62b4c547fc49a8a4aad89921de06bf85db518ada6b42f"
//        assertTrue(CwtVerifier().verify(coseHex))
//    }

}
