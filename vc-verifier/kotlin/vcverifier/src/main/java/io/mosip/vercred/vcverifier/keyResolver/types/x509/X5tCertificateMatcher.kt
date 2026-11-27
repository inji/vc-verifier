package io.mosip.vercred.vcverifier.keyResolver.types.x509

import java.security.MessageDigest
import java.security.cert.Certificate

// COSE x5t (RFC 9360, label 34) is [hashAlg, hashValue]; hashAlg is -16 or "sha-256" for SHA-256.
class X5tHash(val algorithm: Any?, val hash: ByteArray)

object X5tCertificateMatcher {

    private const val COSE_SHA_256 = -16L

    // An algorithm we don't implement is a failure, not a skip, so a header
    // can't turn the check off by naming something unknown.
    fun matches(cert: Certificate, x5t: X5tHash): Boolean {
        if (!isSha256(x5t.algorithm)) return false
        val actual = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
        return MessageDigest.isEqual(actual, x5t.hash)
    }

    private fun isSha256(alg: Any?): Boolean = when (alg) {
        is Number -> alg.toLong() == COSE_SHA_256
        is String -> alg.equals("sha-256", ignoreCase = true)
        else -> false
    }
}
