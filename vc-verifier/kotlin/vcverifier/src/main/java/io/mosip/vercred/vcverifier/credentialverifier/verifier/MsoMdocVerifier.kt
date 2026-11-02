package io.mosip.vercred.vcverifier.credentialverifier.verifier

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ALG
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DIGEST_ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DS_CERT_EKU
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DS_CERT_KEY_USAGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DS_CERT_VALIDITY
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUING_COUNTRY
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUING_JURISDICTION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_SIGNED_OUTSIDE_DS_CERT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALUE_DIGESTS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING_ALG
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DIGEST_ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DS_CERT_EKU
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DS_CERT_KEY_USAGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DS_CERT_VALIDITY
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUE_DATE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUER_SIGNED_ITEM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUING_COUNTRY
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUING_JURISDICTION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MSO_ALG
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_SIGNED_OUTSIDE_DS_CERT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALUE_DIGESTS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_ALG
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DIGEST_SALT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_DIGEST_ID_OUT_OF_RANGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DIGEST_SALT
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.COSE_ALG_HEADER_LABEL
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DIGEST_ALGORITHM
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DIGEST_ID
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DIGEST_ID_MAX_EXCLUSIVE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MIN_DIGEST_SALT_BYTES
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocDataElementValidator
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerificationOptions
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.RANDOM
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.SUPPORTED_COSE_ALGS
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DOCUMENTS
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DOC_TYPE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.EXTENDED_KEY_USAGE_OID
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.ISSUE_DATE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.ISSUING_COUNTRY
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.ISSUING_JURISDICTION
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.IssuerSignedNamespaces
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.KEY_USAGE_OID
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MDL_DOCTYPE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MDL_DS_EKU
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MDL_NAMESPACE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.NAME_SPACES
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.VALUE_DIGESTS
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.X5C
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.extractFieldValue
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.get
import io.mosip.vercred.vcverifier.exception.InvalidPropertyException
import io.mosip.vercred.vcverifier.exception.LikelyTamperedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.signature.impl.CoseSignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils.getOrNull
import io.mosip.vercred.vcverifier.utils.DateUtils
import io.mosip.vercred.vcverifier.utils.Util
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.util.Date
import java.util.logging.Logger
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils

internal class MsoMdocVerifier(
    private val options: MsoMdocVerificationOptions = MsoMdocVerificationOptions(),
) {

    private val logger = Logger.getLogger(MsoMdocVerifier::class.java.name)

    fun verify(base64EncodedMdoc: String): Boolean {
        try {

            val (decodedCredential, credentialData, isLatest) = MsoMdocVerifiableCredential(options).parse(
                base64EncodedMdoc
            )
            val issuerSigned = credentialData.issuerSigned
            val mobileSecurityObject = credentialData.mso
            val issuerAuth = issuerSigned.issuerAuth
                ?: throw SignatureVerificationException("issuerAuth is not available")
            /**
             * a) The DS certificate is authenticated.
             * b) The digital signature verifies with the public key provided in the DS certificate.
             * c) The calculated message digests are the same as the message digests stored in the MSO.
             * d) The DocType in the MSO matches the relevant DocType in the “Documents” structure.
             */

            verifyCertificateChain(issuerAuth)
            verifyProtectedHeaderAlg(issuerAuth)
            val dsCertificate = verifyDsCertificate(issuerAuth, mobileSecurityObject)
            if (!verificationOfCoseSignature(issuerAuth, dsCertificate)) {
                throw SignatureVerificationException("COSE signature verification failed")
            }
            verifyValueDigests(
                issuerSigned.namespaces,
                issuerSigned.encodedNameSpaceItems,
                mobileSecurityObject,
            )
            verifyDocType(decodedCredential, mobileSecurityObject, isLatest)
            verifyMdlDataElements(mobileSecurityObject, issuerSigned.namespaces, dsCertificate)
            return true
        } catch (exception: Exception) {
            when (exception) {
                is SignatureVerificationException,
                is LikelyTamperedException,
                is InvalidPropertyException,
                is ValidationException
                    -> throw exception

                else -> {
                    throw UnknownException("Error while doing verification of credential - ${exception.message}")
                }
            }
        }
    }


    private fun verifyCertificateChain(issuerAuth: Array): Boolean {
        //TODO: Validate the certificate chain by getting the trusted root IACA certificate of the Issuing Authority
        return true
    }

    private fun verifyProtectedHeaderAlg(issuerAuth: Array) {
        val protectedHeaderItem = issuerAuth[0]
        if (protectedHeaderItem !is ByteString || protectedHeaderItem.bytes.isEmpty()) {
            throw ValidationException(ERROR_MESSAGE_MISSING_ALG, ERROR_CODE_MISSING_ALG)
        }
        val protectedHeader = try {
            CborDecoder(ByteArrayInputStream(protectedHeaderItem.bytes)).decode()[0] as Map
        } catch (exception: Exception) {
            throw ValidationException(ERROR_MESSAGE_MISSING_ALG, ERROR_CODE_MISSING_ALG)
        }
        if (!protectedHeader.keys.contains(UnsignedInteger(COSE_ALG_HEADER_LABEL))) {
            throw ValidationException(ERROR_MESSAGE_MISSING_ALG, ERROR_CODE_MISSING_ALG)
        }
        // ES256/ES384/ES512 supported; EdDSA remains out of scope (#300).
        // Compare the full BigInteger so unsigned wrap values (e.g. 2^64-7) are not narrowed.
        val protectedAlg =
            (protectedHeader[UnsignedInteger(COSE_ALG_HEADER_LABEL)]
                as? co.nstant.`in`.cbor.model.Number)
                ?.value
        if (protectedAlg == null || protectedAlg !in SUPPORTED_COSE_ALGS) {
            throw ValidationException(ERROR_MESSAGE_INVALID_MSO_ALG, ERROR_CODE_INVALID_ALG)
        }
    }

    private fun verifyDsCertificate(issuerAuth: Array, mso: Map): X509Certificate {
        val issuerCertificate = extractCertificate(issuerAuth)
            ?: throw SignatureVerificationException(
                "Error while doing COSE signature verification - certificate chain is empty"
            )

        try {
            issuerCertificate.checkValidity(Date(System.currentTimeMillis()))
        } catch (_: CertificateExpiredException) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_DS_CERT_VALIDITY,
                ERROR_CODE_INVALID_DS_CERT_VALIDITY
            )
        } catch (_: CertificateNotYetValidException) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_DS_CERT_VALIDITY,
                ERROR_CODE_INVALID_DS_CERT_VALIDITY
            )
        }

        val docType = (mso.getOrNull(DOC_TYPE) as? UnicodeString)?.string
        if (docType == MDL_DOCTYPE && options.strictMdlProfile) {
            verifyMdlDsCertificateProfile(issuerCertificate)
        }

        val signed = (mso.getOrNull("validityInfo") as? Map)?.getOrNull("signed")
        if (signed != null) {
            val signedDate = DateUtils.parseDate(signed.toString())
                ?: throw ValidationException(
                    ERROR_MESSAGE_INVALID_SIGNED_OUTSIDE_DS_CERT,
                    ERROR_CODE_INVALID_SIGNED_OUTSIDE_DS_CERT
                )
            if (signedDate.before(issuerCertificate.notBefore) || signedDate.after(issuerCertificate.notAfter)) {
                throw ValidationException(
                    ERROR_MESSAGE_INVALID_SIGNED_OUTSIDE_DS_CERT,
                    ERROR_CODE_INVALID_SIGNED_OUTSIDE_DS_CERT
                )
            }
        }

        return issuerCertificate
    }

    private fun verifyMdlDsCertificateProfile(issuerCertificate: X509Certificate) {
        val criticalOids = issuerCertificate.criticalExtensionOIDs ?: emptySet()

        val keyUsage = issuerCertificate.keyUsage
        if (keyUsage == null || !keyUsage[0] || !criticalOids.contains(KEY_USAGE_OID)) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_DS_CERT_KEY_USAGE,
                ERROR_CODE_INVALID_DS_CERT_KEY_USAGE
            )
        }

        val extendedKeyUsage = try {
            issuerCertificate.extendedKeyUsage
        } catch (_: Exception) {
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

    private fun verifyMdlDataElements(
        mso: Map,
        issuerSignedNamespaces: IssuerSignedNamespaces,
        dsCertificate: X509Certificate,
    ) {
        val docType = (mso.getOrNull(DOC_TYPE) as? UnicodeString)?.string
        if (docType != MDL_DOCTYPE) {
            return
        }

        verifyCountryName(dsCertificate, issuerSignedNamespaces)
        verifyIssuingJurisdiction(dsCertificate, issuerSignedNamespaces)
        verifyIssueDate(mso, issuerSignedNamespaces)
        // §3.4 mandatory presence is gated inside the validator to full issued credentials only.
        MsoMdocDataElementValidator.validate(
            namespaces = issuerSignedNamespaces,
            mso = mso,
            checkTypesAndStructure = options.strictMdlProfile,
            checkMandatoryPresence = options.strictMdlProfile,
        )
    }

    private fun verifyCountryName(
        issuerCertificate: X509Certificate,
        issuerSignedNamespaces: IssuerSignedNamespaces,
    ) {
        val issuingCountry = issuerSignedNamespaces.extractFieldValue(
            ISSUING_COUNTRY,
            MDL_NAMESPACE
        )
        if (issuingCountry.isNullOrEmpty()) {
            return
        }
        val countryName = extractDnAttribute(issuerCertificate.subjectX500Principal, BCStyle.C)
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
        issuerCertificate: X509Certificate,
        issuerSignedNamespaces: IssuerSignedNamespaces,
    ) {
        val stateOrProvinceName = extractDnAttribute(issuerCertificate.subjectX500Principal, BCStyle.ST)
            ?: return
        val issuingJurisdiction = issuerSignedNamespaces.extractFieldValue(
            ISSUING_JURISDICTION,
            MDL_NAMESPACE
        ) ?: return

        if (issuingJurisdiction != stateOrProvinceName) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_ISSUING_JURISDICTION,
                ERROR_CODE_INVALID_ISSUING_JURISDICTION
            )
        }
    }

    private fun verifyIssueDate(mso: Map, issuerSignedNamespaces: IssuerSignedNamespaces) {
        val issueDate = issuerSignedNamespaces.extractFieldValue(ISSUE_DATE, MDL_NAMESPACE)
            ?: return
        if (!DateUtils.isIsoFullDate(issueDate)) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_ISSUE_DATE_FORMAT,
                ERROR_CODE_INVALID_ISSUE_DATE
            )
        }

        val issueLocalDate = try {
            org.threeten.bp.LocalDate.parse(issueDate)
        } catch (_: org.threeten.bp.format.DateTimeParseException) {
            // Regex-only shape check can still admit impossible calendar dates (e.g. 2024-13-45).
            throw ValidationException(
                ERROR_MESSAGE_INVALID_ISSUE_DATE_FORMAT,
                ERROR_CODE_INVALID_ISSUE_DATE
            )
        }

        val validFrom = (mso.getOrNull("validityInfo") as? Map)?.getOrNull("validFrom")
            ?: return
        val validFromDate = DateUtils.parseDate(validFrom.toString()) ?: return
        val validFromUtcDate = org.threeten.bp.Instant.ofEpochMilli(validFromDate.time)
            .atZone(org.threeten.bp.ZoneOffset.UTC)
            .toLocalDate()
        if (issueLocalDate.isAfter(validFromUtcDate)) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_ISSUE_DATE,
                ERROR_CODE_INVALID_ISSUE_DATE
            )
        }
    }

    private fun extractDnAttribute(
        principal: X500Principal,
        oid: org.bouncycastle.asn1.ASN1ObjectIdentifier,
    ): String? {
        return try {
            val subject = X500Name.getInstance(principal.encoded)
            val rdns = subject.getRDNs(oid)
            if (rdns.isEmpty()) null
            else IETFUtils.valueToString(rdns[0].first.value)
        } catch (_: Exception) {
            null
        }
    }

    private fun verifyDocType(decodedCredential: Map, mso: Map, isLatest: Boolean): Boolean {
        if (isLatest) {
            return true
        }
        val docTypeInMso = mso[DOC_TYPE]
        val docTypeInDocument = decodedCredential.getOrNull(DOC_TYPE)
            ?: decodedCredential.getOrNull(DOCUMENTS)
                ?.let { documents -> ((documents as Array)[0] as Map).getOrNull(DOC_TYPE) }
            ?: throw InvalidPropertyException("Property docType not found in the credential")
        if (docTypeInMso == docTypeInDocument) {
            return true
        }
        logger.severe("Error while doing docType property verification - Property mismatch with docType in the credential")
        throw InvalidPropertyException("Property mismatch with docType in the credential")
    }

    private fun verificationOfCoseSignature(
        issuerAuth: DataItem,
        issuerCertificate: X509Certificate,
    ): Boolean {
        val signatureVerifier: SignatureVerifier = CoseSignatureVerifierImpl()
        return signatureVerifier.verify(
            issuerCertificate.publicKey,
            CborDataItemUtils.toByteArray(issuerAuth),
            null,
        )
    }

    private fun extractCertificate(coseSignature: DataItem): X509Certificate? {

        val unprotectedHeader = (coseSignature as Array)[1] as Map
        val x5Chain: DataItem = unprotectedHeader.get(UnsignedInteger(X5C)) ?: return null
        // The x5Chain (header parameter 33) in COSE is either:
        //A single DER-encoded X.509 certificate (byte string), or
        //An array of DER-encoded X.509 certificates (CBOR array of byte strings).
        val issuerCertificateString: DataItem? = when (x5Chain.majorType) {
            MajorType.BYTE_STRING -> {
                x5Chain
            }

            MajorType.ARRAY -> {
                (x5Chain as Array)[0]
            }

            else -> {
                null
            }
        }
        if (issuerCertificateString !is ByteString) {
            return null
        }
        val issuerCertificateBytes = issuerCertificateString.bytes
        return Util.toX509Certificate(issuerCertificateBytes)
    }


    private fun verifyValueDigests(
        issuerSignedNamespaces: Map,
        encodedNameSpaceItems: kotlin.collections.Map<String, List<ByteArray>>,
        mso: Map,
    ): Boolean {
        val digestAlgorithm = mso[DIGEST_ALGORITHM].toString()

        issuerSignedNamespaces.keys.forEach { namespaceKey ->
            val namespace = (namespaceKey as? UnicodeString)?.string
                ?: throw ValidationException(
                    ERROR_MESSAGE_INVALID_VALUE_DIGESTS,
                    ERROR_CODE_INVALID_VALUE_DIGESTS
                )
            val namespaceData: List<DataItem> =
                ((issuerSignedNamespaces[namespaceKey]) as Array).dataItems
            val encodedItems = encodedNameSpaceItems[namespace]
            if (encodedItems == null || encodedItems.size != namespaceData.size) {
                throw ValidationException(
                    "$ERROR_MESSAGE_INVALID_VALUE_DIGESTS (as-received nameSpaces bytes unavailable)",
                    ERROR_CODE_INVALID_VALUE_DIGESTS
                )
            }
            val calculatedDigests = mutableMapOf<Number, ByteArray>()

            val digestsByNamespace: Map = (mso[VALUE_DIGESTS] as Map).let { root ->
                if (root.keys.contains(UnicodeString(NAME_SPACES))) root[NAME_SPACES] as Map else root
            }
            val valueDigests: Map = digestsByNamespace[namespaceKey] as? Map
                ?: throw ValidationException(
                    "$ERROR_MESSAGE_INVALID_VALUE_DIGESTS (no digests for namespace in MSO)",
                    ERROR_CODE_INVALID_VALUE_DIGESTS
                )

            namespaceData.forEachIndexed { index, issuerSignedItem ->
                if (issuerSignedItem !is ByteString || issuerSignedItem.tag?.value != 24L) {
                    throw ValidationException(
                        ERROR_MESSAGE_INVALID_ISSUER_SIGNED_ITEM,
                        ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
                    )
                }

                // Hash IssuerSignedItemBytes exactly as received (full tag-24 wrapper bytes).
                val issuerSignedItemBytes = encodedItems[index]
                val digest = MessageDigest.getInstance(digestAlgorithm).digest(issuerSignedItemBytes)
                val decodedIssuerSignedItem =
                    CborDecoder(ByteArrayInputStream(issuerSignedItem.bytes)).decode()[0]
                val decodedMap = decodedIssuerSignedItem as Map
                val digestIdValue = (decodedMap[DIGEST_ID] as? UnsignedInteger)?.value
                    ?: throw ValidationException(
                        ERROR_MESSAGE_DIGEST_ID_OUT_OF_RANGE,
                        ERROR_CODE_INVALID_DIGEST_ID
                    )
                if (digestIdValue.signum() < 0 || digestIdValue >= DIGEST_ID_MAX_EXCLUSIVE) {
                    throw ValidationException(
                        ERROR_MESSAGE_DIGEST_ID_OUT_OF_RANGE,
                        ERROR_CODE_INVALID_DIGEST_ID
                    )
                }
                val digestId: Number = digestIdValue

                val salt = decodedMap[RANDOM] as? ByteString
                if (salt == null || salt.bytes.size < MIN_DIGEST_SALT_BYTES) {
                    throw ValidationException(
                        ERROR_MESSAGE_INVALID_DIGEST_SALT,
                        ERROR_CODE_INVALID_DIGEST_SALT
                    )
                }

                if (calculatedDigests.containsKey(digestId)) {
                    throw ValidationException(
                        ERROR_MESSAGE_INVALID_DIGEST_ID,
                        ERROR_CODE_INVALID_DIGEST_ID
                    )
                }
                calculatedDigests[digestId] = digest
            }

            for ((calculatedDigestId, calculatedDigest) in calculatedDigests) {
                val msoDigestItem = valueDigests.keys
                    .map { it as UnsignedInteger }
                    .firstOrNull { it.value == calculatedDigestId }
                    ?.let { valueDigests[it] as? ByteString }
                    ?: throw ValidationException(
                        "$ERROR_MESSAGE_INVALID_VALUE_DIGESTS (digestID $calculatedDigestId)",
                        ERROR_CODE_INVALID_VALUE_DIGESTS
                    )

                if (!calculatedDigest.contentEquals(msoDigestItem.bytes)) {
                    logger.severe("Error while doing valueDigests verification - mismatch in digests found")
                    throw ValidationException(
                        "$ERROR_MESSAGE_INVALID_VALUE_DIGESTS (digestID $calculatedDigestId)",
                        ERROR_CODE_INVALID_VALUE_DIGESTS
                    )
                }
            }
        }

        return true
    }
}
