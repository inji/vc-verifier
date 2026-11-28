package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.authlete.cbor.CBORDecoder
import com.authlete.cbor.CBORTaggedItem
import com.authlete.cose.COSESign1
import com.authlete.cose.COSEVerifier
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.keyResolver.types.x509.X5tHash
import io.mosip.vercred.vcverifier.keyResolver.types.x509.X5uPublicKeyResolver
import io.mosip.vercred.vcverifier.utils.Util.hexToBytes
import io.mosip.vercred.vcverifier.utils.Util.parseFullyQualifiedIssuer
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

        return try {
            parseFullyQualifiedIssuer(iss.AsString())
        } catch (exception: IllegalArgumentException) {
            throw SignatureVerificationException(exception.message ?: "Invalid issuer (iss)")
        }
    }
    private fun protectedHeader(coseObj: CBORObject): CBORObject? {
        val protectedBytes = coseObj[0].GetByteString()
        return if (protectedBytes.isEmpty()) null else CBORObject.DecodeFromBytes(protectedBytes)
    }

    // COSE header label 34 (x5t) - RFC 9360: [hashAlg, hashValue]. Protected header only, since it is the signed anchor.
    // A malformed x5t fails verification instead of being ignored.
    private fun extractX5t(coseObj: CBORObject): X5tHash? {
        val X5T = CBORObject.FromObject(34)

        val x5t = protectedHeader(coseObj)?.get(X5T) ?: return null
        if (x5t.type != CBORType.Array || x5t.size() != 2 || x5t[1].type != CBORType.ByteString) {
            throw SignatureVerificationException("Invalid x5t header")
        }
        val algorithm: Any = when (x5t[0].type) {
            CBORType.Integer -> x5t[0].AsInt64Value()
            CBORType.TextString -> x5t[0].AsString()
            else -> throw SignatureVerificationException("Invalid x5t hash algorithm")
        }
        return X5tHash(algorithm, x5t[1].GetByteString())
    }

    // COSE header label 35 (x5u) - RFC 9360. Protected x5u is always read. An unprotected x5u is read only when a
    // protected x5t is present, because the signed thumbprint then binds the downloaded certificate.
    // A malformed x5u fails verification instead of falling back to the issuer JWKS.
    private fun extractX5u(coseObj: CBORObject, x5t: X5tHash?): String? {
        val X5U = CBORObject.FromObject(35)

        val x5uFromProtectedHeader = protectedHeader(coseObj)?.get(X5U)
        val x5uFromUnprotectedHeader = coseObj[1]?.get(X5U)
        val x5u = x5uFromProtectedHeader ?: x5t?.let { x5uFromUnprotectedHeader }
        if (x5u == null) return null
        if (x5u.type != CBORType.TextString) {
            throw SignatureVerificationException("Invalid x5u header")
        }
        return x5u.AsString()
    }

    private fun resolvePublicKey(coseObj: CBORObject, issuer: URI, kid: String?): PublicKey {
        val x5t = extractX5t(coseObj)
        val x5u = extractX5u(coseObj, x5t)
        if (x5u != null) {
            return X5uPublicKeyResolver().resolve(x5u, issuer, x5t)
        }

        val verificationMethod = when (issuer.scheme) {
            "http", "https" -> URI("${issuer.toString().removeSuffix("/")}/.well-known/jwks.json")
            else -> issuer
        }
        return PublicKeyResolverFactory().get(verificationMethod, kid)
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

        val isValid = try {
            verifier.verify(sign1)
        } catch (exception: Exception){
            throw SignatureVerificationException("CWT signature verification failed: ${exception.message}")
        }

        if (!isValid) {
            throw SignatureVerificationException("CWT signature verification failed")
        }
        return isValid
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
            val publicKey = resolvePublicKey(coseObj, issuer, kid)

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