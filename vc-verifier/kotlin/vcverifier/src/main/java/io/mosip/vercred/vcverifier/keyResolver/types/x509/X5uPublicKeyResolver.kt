package io.mosip.vercred.vcverifier.keyResolver.types.x509

import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.networkManager.HttpMethod
import java.io.ByteArrayInputStream
import java.net.URI
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.logging.Logger

class X5uPublicKeyResolver {

    private val logger = Logger.getLogger(X5uPublicKeyResolver::class.java.name)

    // Until trust anchor checks exist, x5u must live on the same host as iss, so a token cannot point at an arbitrary certificate.
    private fun requireSameHostAsIssuer(x5u: String, issuer: URI) {
        val x5uHost = try {
            URI(x5u).host
        } catch (e: Exception) {
            null
        }
        if (x5uHost.isNullOrBlank() || issuer.host.isNullOrBlank() || !x5uHost.equals(issuer.host, ignoreCase = true)) {
            throw PublicKeyNotFoundException("x5u host must match the issuer (iss) host")
        }
    }

    // A plain-http x5u lets anyone on the path swap the certificate, so only https is accepted.
    private fun requireHttps(x5u: String) {
        val scheme = try {
            URI(x5u).scheme
        } catch (e: Exception) {
            null
        }
        if (!"https".equals(scheme, ignoreCase = true)) {
            throw PublicKeyNotFoundException("x5u must be an https URL")
        }
    }
    fun resolve(uri: String, issuer: URI, x5t: X5tHash? = null): PublicKey {
        requireHttps(uri)
        requireSameHostAsIssuer(uri, issuer)
        val cert = try {
            val certBytes = NetworkManagerClient.sendHTTPRequestForBytes(uri, HttpMethod.GET)
            val parsed = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
            parsed.checkValidity()
            parsed
        } catch (exception: Exception) {
            logger.severe("Error while resolving public key from x5u certificate: ${exception.message}")
            throw PublicKeyNotFoundException(
                "Unable to extract public key from x5u certificate: ${exception.message}"
            )
        }
        if (x5t != null && !X5tCertificateMatcher.matches(cert, x5t)) {
            throw PublicKeyNotFoundException("x5u certificate does not match the x5t thumbprint")
        }
        return cert.publicKey
    }
}