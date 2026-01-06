package io.mosip.vercred.vcverifier.credentialverifier.verifier

import android.net.Uri
import se.digg.cose.Sign1COSEObject
import se.digg.cose.COSEKey
import com.nimbusds.jose.jwk.JWKSet
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import com.nimbusds.jose.jwk.*
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.utils.Util.httpGet
import se.digg.cose.COSEObject
import java.net.URI
import java.net.URL
import java.security.PublicKey

class CwtVerifier {

    fun hexToBytes(hex: String): ByteArray {
        val cleanHex = hex.replace("\\s".toRegex(), "")
        require(cleanHex.length % 2 == 0) { "Invalid hex length" }

        return ByteArray(cleanHex.length / 2) { i ->
            cleanHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun decodeCose(cwtHex: String): CBORObject? {
        return try {
            val bytes = hexToBytes(cwtHex)
            CBORObject.DecodeFromBytes(bytes)
        } catch (e: Exception) {
            null
        }
    }

    private fun isValidCoseStructure(coseObj: CBORObject): Boolean {
        if (coseObj.type != CBORType.Array) return false
        if (coseObj.size() != 4) return false
        if (coseObj[0].type != CBORType.ByteString) return false
        if (coseObj[1].type != CBORType.Map) return false
        if (coseObj[2].type != CBORType.ByteString) return false
        if (coseObj[3].type != CBORType.ByteString) return false
        return true
    }

    private fun isValidCwtStructure(claims: CBORObject): Boolean {
        if (claims.type != CBORType.Map) return false

        for (key in claims.keys) {
            if (key.type != CBORType.Integer) return false
        }
        return true
    }

    private fun extractIssuerUri(claims: CBORObject): URI? {
        val ISS = CBORObject.FromObject(1)

        if (!claims.ContainsKey(ISS)) return null

        val iss = claims[ISS]
        if (iss.type != CBORType.TextString) return null

        return try {
            URI(iss.AsString())
        } catch (e: Exception) {
            null
        }
    }


    private fun resolveIssuerMetadata(issuer: String): String? {
        val metadataUrl = "$issuer/.well-known/openid-credential-issuer"
        return httpGet(metadataUrl)
    }

    private fun fetchPublicKey(
        coseObj: CBORObject,
        issuerMetadataJson: String
    ): PublicKey? {

        val metadata = org.json.JSONObject(issuerMetadataJson)
        val jwksUri = metadata.optString("jwks_uri", null) ?: return null

        val jwksJson = httpGet(jwksUri) ?: return null
        val jwkSet = JWKSet.parse(jwksJson)

        val kid = extractKid(coseObj) ?: return null

        val jwk = jwkSet.keys.firstOrNull { it.keyID == kid } ?: return null

        return when (jwk) {
            is RSAKey -> jwk.toRSAPublicKey()
            is ECKey -> jwk.toECPublicKey()
            is OctetKeyPair -> jwk.toPublicKey()
            else -> null
        }
    }

    private fun extractKid(coseObj: CBORObject): String? {
        val KID = CBORObject.FromObject(4)

        val protectedBytes = coseObj[0].GetByteString()
        if (protectedBytes.isNotEmpty()) {
            val protected = CBORObject.DecodeFromBytes(protectedBytes)
            if (protected.ContainsKey(KID)) {
                return String(protected[KID].GetByteString())
            }
        }

        val unprotected = coseObj[1]
        if (unprotected.ContainsKey(KID)) {
            return String(unprotected[KID].GetByteString())
        }

        return null
    }


    private fun verifySignature(
        coseObj: ByteArray,
        publicKey: PublicKey
    ): Boolean {
        return try {
            // Decode COSE_Sign1
            val coseObject = COSEObject.DecodeFromBytes(coseObj)

            val sign1 = coseObject as? Sign1COSEObject ?: return false

            val coseKey = COSEKey(publicKey, null)

            sign1.validate(coseKey)
        } catch (e: Exception) {
            false
        }
    }


    fun verify(credential: String): Boolean {
        val coseBytes = hexToBytes(credential)
        val coseObj = decodeCose(credential) ?: return false;
        if (!isValidCoseStructure(coseObj)) return false;

        val payloadBytes = coseObj[2].GetByteString()
        val claims = CBORObject.DecodeFromBytes(payloadBytes)
        if (!isValidCwtStructure(claims)) return false;

        val issuer = extractIssuerUri(claims) ?: return false;

        val publicKey = PublicKeyResolverFactory().get(issuer)

        return verifySignature(coseBytes, publicKey)
    }
}