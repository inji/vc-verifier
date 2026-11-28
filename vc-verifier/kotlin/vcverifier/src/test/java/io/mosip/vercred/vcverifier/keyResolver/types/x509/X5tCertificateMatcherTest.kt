package io.mosip.vercred.vcverifier.keyResolver.types.x509

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.util.ResourceUtils
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateFactory

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class X5tCertificateMatcherTest {

    private lateinit var cert: Certificate
    private lateinit var sha256: ByteArray

    @BeforeAll
    fun setup() {
        val der = Files.readAllBytes(
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "cwt_vc/x5u-leaf-cert.der").toPath()
        )
        cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der))
        sha256 = MessageDigest.getInstance("SHA-256").digest(der)
    }

    @Test
    fun `matches numeric and text sha-256 identifiers`() {
        assertTrue(X5tCertificateMatcher.matches(cert, X5tHash(-16L, sha256)))
        assertTrue(X5tCertificateMatcher.matches(cert, X5tHash("SHA-256", sha256)))
    }

    @Test
    fun `rejects unknown text algorithm`() {
        assertFalse(X5tCertificateMatcher.matches(cert, X5tHash("sha-512", sha256)))
    }

    @Test
    fun `rejects algorithm that is neither number nor text`() {
        assertFalse(X5tCertificateMatcher.matches(cert, X5tHash(null, sha256)))
    }
}
