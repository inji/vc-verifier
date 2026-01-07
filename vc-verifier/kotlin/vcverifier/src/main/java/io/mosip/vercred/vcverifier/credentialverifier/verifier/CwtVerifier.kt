package io.mosip.vercred.vcverifier.credentialverifier.verifier

import se.digg.cose.Sign1COSEObject
import se.digg.cose.COSEKey
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import se.digg.cose.COSEObject
import java.net.URI
import java.security.PublicKey
import java.util.logging.Logger
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.utils.Util.hexToBytes

class CwtVerifier {

   private val logger = Logger.getLogger(CwtVerifier::class.java.name)

    private fun validateCoseStructure(coseObj: CBORObject) {
        if (coseObj.type != CBORType.Array || coseObj.size() != 4) {
            throw SignatureVerificationException("Invalid COSE_Sign1 structure")
        }
    }

    private fun extractIssuer(claims: CBORObject): URI {
        val ISS = CBORObject.FromObject(1)

        if (!claims.ContainsKey(ISS)) {
            throw SignatureVerificationException("Missing issuer (iss) claim")
        }

        val iss = claims[ISS]
        if (iss.type != CBORType.TextString) {
            throw SignatureVerificationException("Invalid issuer (iss) type")
        }

        val issURI = URI(iss.AsString())
        return when (issURI.scheme) {
            "did" -> issURI
            "http", "https" -> issURI.resolve("/.well-known/jwks.json")
            else -> throw UnsupportedDidUrl("Unsupported issuer scheme: ${issURI.scheme}")
        }
    }

//    private fun extractKid(coseObj: CBORObject): String? {
//        val KID = CBORObject.FromObject(4)
//
//        val protectedBytes = coseObj[0].GetByteString()
//        if (protectedBytes.isNotEmpty()) {
//            val protected = CBORObject.DecodeFromBytes(protectedBytes)
//            if (protected.ContainsKey(KID)) {
//                return String(protected[KID].GetByteString())
//            }
//        }
//
//        val unprotected = coseObj[1]
//        if (unprotected.ContainsKey(KID)) {
//            return String(unprotected[KID].GetByteString())
//        }
//
//        return null
//    }

    private fun extractClaims(coseObj: CBORObject): CBORObject {
        val payloadBytes = coseObj[2].GetByteString()
        val claims = CBORObject.DecodeFromBytes(payloadBytes)

        if (claims.type != CBORType.Map) {
            throw SignatureVerificationException("Invalid CWT claims structure")
        }

        return claims
    }

    private fun verifySignature(
        coseBytes: ByteArray,
        publicKey: PublicKey
    ): Boolean {
        val coseObject = COSEObject.DecodeFromBytes(coseBytes)
        val sign1 = coseObject as? Sign1COSEObject
            ?: throw SignatureVerificationException("Not a COSE_Sign1 object")

        val coseKey = COSEKey(publicKey, null)

        if (!sign1.validate(coseKey)) {
            throw SignatureVerificationException("CWT signature verification failed")
        }

        return true
    }

    fun verify(credential: String): Boolean {
        logger.info("Received CWT Verification - Start")

        return try {
            val coseBytes = hexToBytes(credential)
            val coseObj = CBORObject.DecodeFromBytes(coseBytes)
            validateCoseStructure(coseObj)

            val claims = extractClaims(coseObj)
            val issuer = extractIssuer(claims)

            /**
             * Resolves and returns a non-null PublicKey.
             * @throws PublicKeyNotFoundException if key cannot be resolved
             */
            val publicKey = PublicKeyResolverFactory().get(issuer)

            verifySignature(coseBytes, publicKey)
        } catch (exception: Exception) {
            when (exception) {
                is PublicKeyNotFoundException,
                is SignatureVerificationException -> throw exception

                else -> throw UnknownException(
                    "Error while verifying CWT credential: ${exception.message}"
                )
            }
        }
    }
}