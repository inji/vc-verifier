package io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.mdl

import co.nstant.`in`.cbor.model.Map
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DS_CERT_EKU
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DS_CERT_KEY_USAGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DS_CERT_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUING_COUNTRY
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUING_JURISDICTION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DS_CERT_EKU
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DS_CERT_KEY_USAGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DS_CERT_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUING_COUNTRY
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUING_JURISDICTION
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DecodedIssuerSignedItem
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.EXTENDED_KEY_USAGE_OID
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.KEY_USAGE_DIGITAL_SIGNATURE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.KEY_USAGE_OID
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MdocDocTypeVerifier
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerificationOptions
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.elementText
import io.mosip.vercred.vcverifier.exception.ValidationException
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1String
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.util.logging.Logger
import javax.security.auth.x500.X500Principal

/**
 * mDL checks that run during verification, after the COSE signature and the value digests:
 * - DS certificate KeyUsage digitalSignature and the mDL EKU, both critical (ISO 18013-5 Table B.3;
 *   strict mDL profile only)
 * - issuing_country vs the DS certificate C, issuing_jurisdiction vs the DS certificate ST
 *
 * Runs only for docType org.iso.18013.5.1.mDL (chosen by MdocDocTypes).
 */
internal object MdlVerifier : MdocDocTypeVerifier {

    private val logger = Logger.getLogger(MdlVerifier::class.java.name)

    override fun verify(
        items: List<DecodedIssuerSignedItem>,
        mso: Map,
        dsCertificate: X509Certificate,
        options: MsoMdocVerificationOptions,
    ) {
        // TODO: always run this check (ISO 18013-5 Table B.3) once issuers' DS certificates
        //  include KeyUsage/EKU.
        if (options.strictMdlProfile) {
            verifyDsCertificateProfile(dsCertificate)
        }
        verifyIssuingCountry(dsCertificate, items)
        verifyIssuingJurisdiction(dsCertificate, items)
    }

    private fun verifyDsCertificateProfile(dsCertificate: X509Certificate) {
        val criticalOids = dsCertificate.criticalExtensionOIDs ?: emptySet()

        val keyUsage = dsCertificate.keyUsage
        if (keyUsage == null ||
            keyUsage.size <= KEY_USAGE_DIGITAL_SIGNATURE ||
            !keyUsage[KEY_USAGE_DIGITAL_SIGNATURE] ||
            !criticalOids.contains(KEY_USAGE_OID)
        ) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_DS_CERT_KEY_USAGE,
                ERROR_CODE_INVALID_DS_CERT_KEY_USAGE
            )
        }

        val extendedKeyUsage = try {
            dsCertificate.extendedKeyUsage
        } catch (exception: CertificateParsingException) {
            logger.severe("Unable to parse DS certificate extended key usage: ${exception.message}")
            null
        }
        if (extendedKeyUsage == null ||
            !extendedKeyUsage.contains(MDL_DS_EKU) ||
            !criticalOids.contains(EXTENDED_KEY_USAGE_OID)
        ) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_DS_CERT_EKU,
                ERROR_CODE_INVALID_DS_CERT_EKU
            )
        }
    }

    private fun verifyIssuingCountry(
        dsCertificate: X509Certificate,
        items: List<DecodedIssuerSignedItem>,
    ) {
        // Only an undisclosed element is skipped; a disclosed "" must still match the cert.
        val issuingCountry = items.elementText(ISSUING_COUNTRY, MDL_NAMESPACE) ?: return
        val countryName = extractDnAttribute(dsCertificate.subjectX500Principal, BCStyle.C)
            ?: throw ValidationException(
                ERROR_MESSAGE_INVALID_ISSUING_COUNTRY,
                ERROR_CODE_INVALID_ISSUING_COUNTRY
            )
        if (issuingCountry != countryName) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_ISSUING_COUNTRY,
                ERROR_CODE_INVALID_ISSUING_COUNTRY
            )
        }
    }

    private fun verifyIssuingJurisdiction(
        dsCertificate: X509Certificate,
        items: List<DecodedIssuerSignedItem>,
    ) {
        val stateOrProvinceName = extractDnAttribute(dsCertificate.subjectX500Principal, BCStyle.ST)
            ?: return
        val issuingJurisdiction = items.elementText(ISSUING_JURISDICTION, MDL_NAMESPACE) ?: return

        if (issuingJurisdiction != stateOrProvinceName) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_ISSUING_JURISDICTION,
                ERROR_CODE_INVALID_ISSUING_JURISDICTION
            )
        }
    }

    /**
     * Returns the raw (unescaped) value of the first [oid] RDN in [principal], or null when the
     * attribute is absent. An unparseable subject is a certificate error, not "absent".
     */
    private fun extractDnAttribute(
        principal: X500Principal,
        oid: ASN1ObjectIdentifier,
    ): String? {
        val subject = try {
            X500Name.getInstance(principal.encoded)
        } catch (exception: Exception) {
            logger.severe("Unable to parse DS certificate subject: ${exception.message}")
            throw ValidationException(
                ERROR_MESSAGE_INVALID_DS_CERT_SUBJECT,
                ERROR_CODE_INVALID_DS_CERT_SUBJECT
            )
        }
        val rdns = subject.getRDNs(oid)
        if (rdns.isEmpty()) {
            return null
        }
        return (rdns[0].first?.value as? ASN1String)?.string
            ?: throw ValidationException(
                ERROR_MESSAGE_INVALID_DS_CERT_SUBJECT,
                ERROR_CODE_INVALID_DS_CERT_SUBJECT
            )
    }
}
