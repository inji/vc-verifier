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
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.CWT_CLAIM_STATUS_LIST
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.CWT_CLAIM_SUB
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.CWT_CLAIM_TTL
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_BITS_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_INVALID_SIGNATURE
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_LST_KEY
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_MALFORMED
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_TYP
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_UNTRUSTED_ISSUER
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_URI_MISMATCH
import io.mosip.vercred.vcverifier.constants.MdocStatusConstants.STATUS_LIST_EXPIRED
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
 * Phase 1 accepts any x5chain that can verify the signature; no IACA trust-store.
 */
class MdocStatusListCwtValidator(
    private val signatureVerifier: SignatureVerifier = CoseSignatureVerifierImpl(),
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / 1000 }
) {

    fun validate(cwtBytes: ByteArray, expectedUri: String): ValidatedStatusListCwt {
        val coseSign1 = decodeCoseSign1(cwtBytes)
        val protectedHeader = decodeProtectedHeader(coseSign1)
        requireTyp(protectedHeader)
        requireAlg(protectedHeader)
        val claims = decodeClaims(coseSign1)
        val sub = requireTextClaim(claims, CWT_CLAIM_SUB, "sub")
        if (sub != expectedUri) {
            throw MdocStatusCheckException(
                STATUS_LIST_URI_MISMATCH,
                "Status list CWT sub '$sub' does not match MSO uri '$expectedUri'"
            )
        }
        requireUnsignedClaim(claims, CWT_CLAIM_IAT, "iat")
        val exp = requireUnsignedClaim(claims, CWT_CLAIM_EXP, "exp")
        if (nowSeconds() > exp) {
            throw MdocStatusCheckException(
                STATUS_LIST_EXPIRED,
                "Status list CWT has expired"
            )
        }
        val ttlSeconds = claims.getByUnsignedKey(CWT_CLAIM_TTL)?.let { readUnsigned(it, "ttl") }
        val statusList = claims.getByUnsignedKey(CWT_CLAIM_STATUS_LIST)
            ?: throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list CWT is missing claim 65533")
        if (statusList !is Map) {
            throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list CWT claim 65533 is not a map")
        }
        val bitsItem = statusList.getOrNull(STATUS_LIST_BITS_KEY)
            ?: throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list is missing bits")
        val lstItem = statusList.getOrNull(STATUS_LIST_LST_KEY)
            ?: throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list is missing lst")
        val bits = readUnsigned(bitsItem, "bits").toInt()
        if (lstItem !is ByteString) {
            throw MdocStatusCheckException(STATUS_LIST_MALFORMED, "Status list lst must be a byte string")
        }
        val certificate = extractCertificate(coseSign1)
            ?: throw MdocStatusCheckException(
                STATUS_LIST_UNTRUSTED_ISSUER,
                "Status list CWT x5chain (33) is missing or unusable"
            )
        verifySignature(cwtBytes, certificate)
        return ValidatedStatusListCwt(bits, lstItem.bytes, ttlSeconds)
    }

    private fun decodeCoseSign1(cwtBytes: ByteArray): Array {
        val decoded = try {
            CborDataItemUtils.fromByteArray(cwtBytes)
        } catch (exception: Exception) {
            throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "Status list CWT is not valid CBOR: ${exception.message}"
            )
        }
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
        val header = try {
            CborDataItemUtils.fromByteArray(protectedItem.bytes)
        } catch (exception: Exception) {
            throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "COSE_Sign1 protected header is not valid CBOR: ${exception.message}"
            )
        }
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
        val claims = try {
            CborDataItemUtils.fromByteArray(payloadItem.bytes)
        } catch (exception: Exception) {
            throw MdocStatusCheckException(
                STATUS_LIST_MALFORMED,
                "Status list CWT claims are not valid CBOR: ${exception.message}"
            )
        }
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

    private fun extractCertificate(coseSign1: Array): X509Certificate? {
        val unprotected = coseSign1.dataItems[1]
        if (unprotected !is Map) {
            return null
        }
        val x5Chain = unprotected.getByUnsignedKey(COSE_HEADER_X5CHAIN) ?: return null
        val certificateItem: DataItem? = when (x5Chain.majorType) {
            MajorType.BYTE_STRING -> x5Chain
            MajorType.ARRAY -> (x5Chain as Array).dataItems.firstOrNull()
            else -> null
        }
        if (certificateItem !is ByteString) {
            return null
        }
        return try {
            Util.toX509Certificate(certificateItem.bytes)
        } catch (_: Exception) {
            null
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
        } catch (exception: Exception) {
            throw MdocStatusCheckException(
                STATUS_LIST_INVALID_SIGNATURE,
                "Status list CWT COSE_Sign1 signature verification failed: ${exception.message}"
            )
        }
    }
}

internal fun Map.getByUnsignedKey(key: Long): DataItem? {
    keys.forEach { candidate ->
        if (candidate is UnsignedInteger && candidate.value.toLong() == key) {
            return get(candidate)
        }
    }
    return get(UnsignedInteger(key))
}
