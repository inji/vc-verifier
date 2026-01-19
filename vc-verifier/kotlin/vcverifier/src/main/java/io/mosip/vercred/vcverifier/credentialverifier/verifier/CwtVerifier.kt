package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.authlete.cbor.CBORDecoder
import com.authlete.cbor.CBORTaggedItem
import com.authlete.cose.COSESign1
import com.authlete.cose.COSEVerifier
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.utils.Util.hexToBytes
import io.mosip.vercred.vcverifier.utils.Util.toCoseBytes
import java.net.URI
import java.security.PublicKey
import java.util.logging.Logger

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
            "http", "https" -> {
                val base = issURI.toString().removeSuffix("/")
                URI("$base/.well-known/jwks.json")
            }
            else -> throw UnsupportedDidUrl("Unsupported issuer scheme: ${issURI.scheme}")
        }
    }

    private fun extractKid(coseObj: CBORObject): String? {
        val KID = CBORObject.FromObject(4)

        val protectedBytes = coseObj[0].GetByteString()
        if (protectedBytes.isNotEmpty()) {
            val protected = CBORObject.DecodeFromBytes(protectedBytes)
            val kid = protected[KID]
            if (kid != null && kid.type == CBORType.ByteString) {
                return String(kid.GetByteString(), Charsets.UTF_8)
            }
        }

        val unprotected = coseObj[1]
        val kid = unprotected[KID]
        if (kid != null && kid.type == CBORType.ByteString) {
            return String(kid.GetByteString(), Charsets.UTF_8)
        }

        return null
    }


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
        val sign1 = parseCoseSign1(coseBytes)

        val verifier = COSEVerifier(publicKey)

        return try {
            verifier.verify(sign1)
        } catch (exception: Exception){
            throw SignatureVerificationException("CWT signature verification failed: ${exception.message}")
        }
    }

    private fun requireAndUnwrapCwt(cbor: CBORObject): CBORObject {
        if (!cbor.isTagged || cbor.mostOuterTag.ToInt32Unchecked() != 61) {
            throw SignatureVerificationException(
                "Invalid CWT: missing required CBOR tag 61"
            )
        }
        return cbor.UntagOne()
    }


    private fun parseCoseSign1(coseBytes: ByteArray): COSESign1 {
        val item = CBORDecoder(coseBytes).next()
            ?: throw SignatureVerificationException("Empty CBOR input")

        val tagged = item as? CBORTaggedItem
            ?: throw SignatureVerificationException("COSE_Sign1 must be tagged")

        return tagged.tagContent as? COSESign1
            ?: throw SignatureVerificationException("Invalid COSE_Sign1 structure")
    }

    fun verify(credential: String): Boolean {
        logger.info("Received CWT Verification - Start")

        return try {
            val inputBytes = hexToBytes(credential)
            val decoded = CBORObject.DecodeFromBytes(inputBytes)
            val coseObj = requireAndUnwrapCwt(decoded)
            val coseBytes = toCoseBytes(coseObj)

            validateCoseStructure(coseObj)
            val claims = extractClaims(coseObj)
            val kid = extractKid(coseObj)

            var issuer = extractIssuer(claims)
            val publicKey = PublicKeyResolverFactory().get(issuer,kid)

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