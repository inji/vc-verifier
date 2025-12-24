package io.mosip.vercred.vcverifier.credentialverifier.verifier

import COSE.OneKey
import COSE.Sign1Message
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.nimbusds.jose.jwk.JWKSet
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import org.springframework.web.client.RestTemplate
import java.security.PublicKey

class CwtVerifer {

    val restTemplate = RestTemplate()

    fun httpGet(url: String): String? {
        return try {
            restTemplate.getForObject(url, String::class.java)
        } catch (e: Exception) {
            null
        }
    }

    private val cborMapper = ObjectMapper(CBORFactory())
        .registerKotlinModule()

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
            val cwtValue = CBORObject.DecodeFromBytes(bytes)
            null
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

    private fun extractIssuer(claims: CBORObject): String? {
        val ISS = CBORObject.FromObject(1)
        if (!claims.ContainsKey(ISS)) return null

        val iss = claims[ISS]
        return if (iss.type == CBORType.TextString) iss.AsString() else null
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
        return null;
    }

    private fun extractKid(coseObj: CBORObject): String? {
        val protectedHeaderBytes = coseObj[0].GetByteString()
        val protectedHeader = CBORObject.DecodeFromBytes(protectedHeaderBytes)

        val KID = CBORObject.FromObject(4)
        if (!protectedHeader.ContainsKey(KID)) return null

        return String(protectedHeader[KID].GetByteString())
    }

    private fun verifySignature(
        coseObj: CBORObject,
        publicKey: PublicKey
    ): Boolean {
        return try {
            val sign1 = Sign1Message.DecodeFromBytes(coseObj.EncodeToBytes()) as Sign1Message

            val oneKey = OneKey(publicKey, null)

            sign1.validate(oneKey)
        } catch (e: Exception) {
            false
        }
    }

    fun verify(credential: String): Boolean {
        val coseObj = decodeCose(credential) ?: return false;
        if (!isValidCoseStructure(coseObj)) return false;

        val payloadBytes = coseObj[2].GetByteString()
        val header1 = coseObj[0].GetByteString()
        val headerValue = CBORObject.DecodeFromBytes(header1)
        val claims = CBORObject.DecodeFromBytes(payloadBytes)
        if (!isValidCwtStructure(claims)) return false;

        val issuer = extractIssuer(claims) ?: return false;

        val issuerMetadata = resolveIssuerMetadata(issuer) ?: return false;

        val publicKey = fetchPublicKey(coseObj, issuerMetadata) ?: return false;

        verifySignature(coseObj, publicKey)

        return true;
    }
}