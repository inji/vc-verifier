package io.mosip.vercred.vcverifier.credentialverifier.statusChecker.mdoc

import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.COSE_HEADER_ALG
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.COSE_HEADER_TYP
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.COSE_HEADER_X5CHAIN
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.COSE_SIGN1_TAG
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.CWT_CLAIM_EXP
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.CWT_CLAIM_IAT
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.CWT_CLAIM_NBF
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.CWT_CLAIM_STATUS_LIST
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.CWT_CLAIM_SUB
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.CWT_CLAIM_TTL
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.IETF_BITS_1
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.IETF_BITS_2
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_BITS_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_INVALID_SIGNATURE
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_LST_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_MALFORMED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_TYP
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_UNTRUSTED_ISSUER
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_URI_MISMATCH
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_EXPIRED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_NOT_ACTIVE
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_PROFILE_UNSUPPORTED
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.signature.impl.CoseSignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils.getOrNull
import io.mosip.vercred.vcverifier.utils.Util
import java.security.cert.X509Certificate

data class ValidatedStatusListCwt(
    val bits: Int,
    val compressedLst: ByteArray,
    val ttlSeconds: Long?
)

/**
 * Validates a Token Status List CWT (tagged COSE_Sign1).
 *
 * Certificates in the CWT `x5chain` are untrusted input (RFC 9360). The signer is
 * authorized only against the verified mDoc issuer certificate, then the COSE
 * signature is checked with that already-authorized key.
 */
class MdocStatusListCwtValidator(
    private val signatureVerifier: SignatureVerifier = CoseSignatureVerifierImpl(),
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / 1000 }
) {

    fun validate(
        cwtBytes: ByteArray,
        expectedUri: String,
        issuerCertificate: X509Certificate
    ): ValidatedStatusListCwt {
        val decodedCwt = decodeCoseSign1(cwtBytes)
        val protectedHeader = decodeProtectedHeader(decodedCwt)
        requireTyp(protectedHeader)
        requireAlg(protectedHeader)
        val claims = decodeClaims(decodedCwt)
        val sub = requireTextClaim(claims, CWT_CLAIM_SUB, "sub")
        if (sub != expectedUri) {
            throw MdocStatusCheckException(
                STATUS_LIST_URI_MISMATCH,
                "Status list CWT sub '$sub' does not match MSO uri '$expectedUri'"
            )
        }
        requireUnsignedClaim(claims, CWT_CLAIM_IAT, "iat")
        val now = nowSeconds()
        val nbf = claims.getByUnsignedKey(CWT_CLAIM_NBF)?.let { readUnsigned(it, "nbf") }
        if (nbf != null && now < nbf) {
            throw MdocStatusCheckException(
                STATUS_LIST_NOT_ACTIVE,
                "Status list CWT is not yet active"
            )
        }
        val exp = claims.getByUnsignedKey(CWT_CLAIM_EXP)?.let { readUnsigned(it, "exp") }
        if (exp != null && now >= exp) {
            throw MdocStatusCheckException(
                STATUS_LIST_EXPIRED,
                "Status list CWT has expired"
            )
        }
        val ttlSeconds = claims.getByUnsignedKey(CWT_CLAIM_TTL)?.let { readUnsigned(it, "ttl") }
        if (ttlSeconds != null && ttlSeconds <= 0L) {
            throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "Status list CWT ttl must be a positive integer"
            )
        }
        val statusList = claims.getByUnsignedKey(CWT_CLAIM_STATUS_LIST)
            ?: throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list CWT is missing claim 65533")
        if (statusList !is Map) {
            throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list CWT claim 65533 is not a map")
        }
        val bitsItem = statusList.getOrNull(STATUS_LIST_BITS_KEY)
            ?: throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list is missing bits")
        val lstItem = statusList.getOrNull(STATUS_LIST_LST_KEY)
            ?: throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list is missing lst")
        val bits = requireSupportedBits(readUnsigned(bitsItem, "bits"))
        if (lstItem !is ByteString) {
            throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list lst must be a byte string")
        }
        val certificateChain = extractCertificateChain(protectedHeader, decodedCwt.dataItems[1])
        val certificate = certificateChain.firstOrNull()
            ?: throw MdocStatusCheckException(
                STATUS_LIST_UNTRUSTED_ISSUER,
                "Status list CWT x5chain (33) is missing or unusable"
            )
        requireAuthorizedSigner(certificate, certificateChain, issuerCertificate)
        verifySignature(cwtBytes, certificate)
        return ValidatedStatusListCwt(bits, lstItem.bytes, ttlSeconds)
    }

    private fun decodeCoseSign1(cwtBytes: ByteArray): Array {
        val decoded = decodeCborItem(cwtBytes, "Status list CWT is not valid CBOR")
        if (!decoded.hasTag() || decoded.tag.value != COSE_SIGN1_TAG) {
            throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "Status list CWT is not a COSE_Sign1 tag 18"
            )
        }
        if (decoded !is Array || decoded.dataItems.size != 4) {
            throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "Status list CWT is not a COSE_Sign1 array of 4 items"
            )
        }
        return decoded
    }

    private fun decodeProtectedHeader(coseSign1: Array): Map {
        val protectedItem = coseSign1.dataItems[0]
        if (protectedItem !is ByteString) {
            throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "COSE_Sign1 protected header must be a bstr")
        }
        val header = decodeCborItem(protectedItem.bytes, "COSE_Sign1 protected header is not valid CBOR")
        if (header !is Map) {
            throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "COSE_Sign1 protected header must be a map")
        }
        return header
    }

    private fun requireTyp(protectedHeader: Map) {
        val typ = protectedHeader.getByUnsignedKey(COSE_HEADER_TYP)
            ?: throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list CWT is missing typ (16)")
        if (typ !is UnicodeString || typ.string != STATUS_LIST_TYP) {
            throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "Status list CWT typ must be $STATUS_LIST_TYP"
            )
        }
    }

    private fun requireAlg(protectedHeader: Map) {
        if (protectedHeader.getByUnsignedKey(COSE_HEADER_ALG) == null) {
            throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list CWT is missing alg (1)")
        }
    }

    private fun decodeClaims(coseSign1: Array): Map {
        val payloadItem = coseSign1.dataItems[2]
        if (payloadItem !is ByteString) {
            throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "COSE_Sign1 payload must be a bstr")
        }
        val claims = decodeCborItem(payloadItem.bytes, "Status list CWT claims are not valid CBOR")
        if (claims !is Map) {
            throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list CWT claims must be a map")
        }
        return claims
    }

    private fun requireTextClaim(claims: Map, key: Long, name: String): String {
        val item = claims.getByUnsignedKey(key)
            ?: throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list CWT is missing $name ($key)")
        if (item !is UnicodeString || item.string.isNullOrBlank()) {
            throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list CWT $name must be a text string")
        }
        return item.string
    }

    private fun requireUnsignedClaim(claims: Map, key: Long, name: String): Long {
        val item = claims.getByUnsignedKey(key)
            ?: throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list CWT is missing $name ($key)")
        return readUnsigned(item, name)
    }

    private fun readUnsigned(item: DataItem, name: String): Long {
        if (item !is UnsignedInteger) {
            throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list CWT $name must be an unsigned integer")
        }
        return item.value.toLong()
    }

    private fun requireSupportedBits(bits: Long): Int {
        if (bits != IETF_BITS_1.toLong() && bits != IETF_BITS_2.toLong()) {
            throw MdocStatusCheckException(
                STATUS_PROFILE_UNSUPPORTED,
                "Status list bits=$bits is not supported; IETF profile allows 1 or 2"
            )
        }
        return bits.toInt()
    }

    private fun extractCertificateChain(
        protectedHeader: Map?,
        unprotectedHeader: DataItem?
    ): List<X509Certificate> {
        val fromProtected = certificatesFromX5Chain(protectedHeader?.getByUnsignedKey(COSE_HEADER_X5CHAIN))
        if (fromProtected.isNotEmpty()) {
            return fromProtected
        }
        val unprotected = unprotectedHeader as? Map ?: return emptyList()
        return certificatesFromX5Chain(unprotected.getByUnsignedKey(COSE_HEADER_X5CHAIN))
    }

    private fun certificatesFromX5Chain(x5Chain: DataItem?): List<X509Certificate> {
        if (x5Chain == null) {
            return emptyList()
        }
        val certificateItems: List<DataItem> = when (x5Chain.majorType) {
            MajorType.BYTE_STRING -> listOf(x5Chain)
            MajorType.ARRAY -> (x5Chain as Array).dataItems
            else -> return emptyList()
        }
        return certificateItems.mapNotNull { item ->
            if (item !is ByteString) {
                null
            } else {
                try {
                    Util.toX509Certificate(item.bytes)
                } catch (_: Exception) {
                    null
                }
            }
        }
    }

    private fun requireAuthorizedSigner(
        cwtSigner: X509Certificate,
        cwtChain: List<X509Certificate>,
        issuerCertificate: X509Certificate
    ) {
        if (isIssuerBound(cwtSigner, cwtChain, issuerCertificate)) {
            return
        }
        throw MdocStatusCheckException(
            STATUS_LIST_UNTRUSTED_ISSUER,
            "Status list CWT signer is not bound to the mDoc issuer"
        )
    }

    private fun isIssuerBound(
        cwtSigner: X509Certificate,
        cwtChain: List<X509Certificate>,
        issuerCertificate: X509Certificate
    ): Boolean {
        if (isSameSigner(cwtSigner, issuerCertificate) || isSignedBy(cwtSigner, issuerCertificate)) {
            return true
        }
        var current = cwtSigner
        for (chainCertificate in cwtChain.drop(1)) {
            if (!isSignedBy(current, chainCertificate)) {
                return false
            }
            if (isSameSigner(chainCertificate, issuerCertificate) || isSignedBy(chainCertificate, issuerCertificate)) {
                return true
            }
            current = chainCertificate
        }
        return false
    }

    private fun isSameSigner(
        statusListCertificate: X509Certificate,
        issuerCertificate: X509Certificate
    ): Boolean {
        return statusListCertificate == issuerCertificate ||
            statusListCertificate.publicKey.encoded.contentEquals(issuerCertificate.publicKey.encoded)
    }

    private fun isSignedBy(
        signedCertificate: X509Certificate,
        signingCertificate: X509Certificate
    ): Boolean {
        return try {
            signedCertificate.verify(signingCertificate.publicKey)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun verifySignature(cwtBytes: ByteArray, certificate: X509Certificate) {
        try {
            val verified = signatureVerifier.verify(certificate.publicKey, cwtBytes, null)
            if (!verified) {
                throw MdocStatusCheckException(
                    STATUS_LIST_INVALID_SIGNATURE,
                    "Status list CWT COSE_Sign1 signature verification failed"
                )
            }
        } catch (exception: MdocStatusCheckException) {
            throw exception
        } catch (exception: SignatureVerificationException) {
            throw MdocStatusCheckException(
                STATUS_LIST_INVALID_SIGNATURE,
                "Status list CWT COSE_Sign1 signature verification failed"
            )
        } catch (overflow: StackOverflowError) {
            throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "Status list CWT is not valid CBOR: nested structure too deep"
            )
        } catch (exception: Exception) {
            throw MdocStatusCheckException(
                STATUS_LIST_INVALID_SIGNATURE,
                "Status list CWT COSE_Sign1 signature verification failed: ${exception.message}"
            )
        }
    }

    private fun decodeCborItem(bytes: ByteArray, malformedMessage: String): DataItem {
        return try {
            CborDataItemUtils.fromByteArray(bytes)
        } catch (overflow: StackOverflowError) {
            throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "$malformedMessage: nested structure too deep"
            )
        } catch (exception: Exception) {
            throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "$malformedMessage: ${exception.message}"
            )
        }
    }
}

internal fun Map.getByUnsignedKey(key: Long): DataItem? {
    keys.forEach { mapKey ->
        if (mapKey is UnsignedInteger && mapKey.value.toLong() == key) {
            return get(mapKey)
        }
    }
    return get(UnsignedInteger(key))
}
