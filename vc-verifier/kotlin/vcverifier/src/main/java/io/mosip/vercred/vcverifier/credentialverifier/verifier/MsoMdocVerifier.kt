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
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DIGEST_SALT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DOC_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_X5C_CERT_VALIDITY
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_PROTECTED_HEADER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_SIGNED_OUTSIDE_DS_CERT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALIDITY_INFO_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALUE_DIGESTS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING_ALG
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_DIGEST_ID_OUT_OF_RANGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_DOC_TYPE_MISMATCH
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_DUPLICATE_ELEMENT_IDENTIFIER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DIGEST_ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DIGEST_SALT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DS_CERT_KEY_FOR_ALG
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DS_CERT_VALIDITY
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MSO_ALG
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_SIGNED_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_SIGNED_OUTSIDE_DS_CERT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALUE_DIGESTS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VALUE_DIGESTS_STRUCTURE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MALFORMED_PROTECTED_HEADER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_ALG
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_DOC_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_SIGNED_MSO
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.COSE_ALG_HEADER_LABEL
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DIGEST_ID_MAX_EXCLUSIVE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DOCUMENTS
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DOC_TYPE
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MIN_DIGEST_SALT_BYTES
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MdocClock
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MdocDocTypes
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.decodeIssuerSignedItems
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.DecodedIssuerSignedItem
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerificationOptions
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.SIGNED
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.SUPPORTED_COSE_ALGS
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.VALIDITY_INFO
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.VALUE_DIGESTS
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.X5C
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.get
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.requireSupportedDigestAlgorithm
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
import org.bouncycastle.asn1.nist.NISTNamedCurves
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.util.logging.Logger

private val P256_ORDER: BigInteger = NISTNamedCurves.getByName("P-256").n
private const val P256_FIELD_SIZE = 256

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

            // isLatest only decides where IssuerSigned was found (and the outer docType match);
            // every other check runs the same way for shapes A, B and C.
            verifyCertificateChain(issuerAuth)
            verifyProtectedHeaderAlg(issuerAuth)
            val dsCertificate = verifyDsCertificate(issuerAuth)
            verifyDsCertificateKeyMatchesAlg(dsCertificate)
            verifySignedWithinDsCertificateValidity(mobileSecurityObject, dsCertificate)
            if (!verificationOfCoseSignature(issuerAuth, dsCertificate)) {
                throw SignatureVerificationException("COSE signature verification failed")
            }
            val decodedItems = verifyValueDigests(
                issuerSigned.namespaces,
                issuerSigned.encodedNameSpaceItems,
                mobileSecurityObject,
            )
            verifyDocType(decodedCredential, mobileSecurityObject, isLatest)
            // docType-specific checks (e.g. mDL), after the signature and digests.
            MdocDocTypes.verifierFor(mobileSecurityObject)
                ?.verify(decodedItems, mobileSecurityObject, dsCertificate, options)
            return true
        } catch (exception: Exception) {
            when (exception) {
                is SignatureVerificationException,
                is LikelyTamperedException,
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
        val protectedHeaderItem = issuerAuth[0] as? ByteString
            ?: throw ValidationException(ERROR_MESSAGE_MALFORMED_PROTECTED_HEADER, ERROR_CODE_INVALID_PROTECTED_HEADER)
        // A zero-length protected header is an empty header map (RFC 9052), so alg is missing.
        if (protectedHeaderItem.bytes.isEmpty()) {
            throw ValidationException(ERROR_MESSAGE_MISSING_ALG, ERROR_CODE_MISSING_ALG)
        }
        val protectedHeader = try {
            CborDecoder(ByteArrayInputStream(protectedHeaderItem.bytes)).decode()[0] as? Map
        } catch (exception: Exception) {
            null
        } ?: throw ValidationException(ERROR_MESSAGE_MALFORMED_PROTECTED_HEADER, ERROR_CODE_INVALID_PROTECTED_HEADER)
        if (!protectedHeader.keys.contains(UnsignedInteger(COSE_ALG_HEADER_LABEL))) {
            throw ValidationException(ERROR_MESSAGE_MISSING_ALG, ERROR_CODE_MISSING_ALG)
        }
        // ES256 only.
        // Compare the full BigInteger so unsigned wrap values (e.g. 2^64-7) are not narrowed.
        val protectedAlg =
            (protectedHeader[UnsignedInteger(COSE_ALG_HEADER_LABEL)]
                as? co.nstant.`in`.cbor.model.Number)
                ?.value
        if (protectedAlg == null || protectedAlg !in SUPPORTED_COSE_ALGS) {
            throw ValidationException(ERROR_MESSAGE_INVALID_MSO_ALG, ERROR_CODE_INVALID_ALG)
        }
    }

    /** ES256 requires an EC P-256 DS key; any other key cannot produce a valid ES256 signature. */
    private fun verifyDsCertificateKeyMatchesAlg(dsCertificate: X509Certificate) {
        val publicKey = dsCertificate.publicKey as? ECPublicKey
        val isP256 = publicKey != null &&
            publicKey.params.order == P256_ORDER &&
            publicKey.params.curve.field.fieldSize == P256_FIELD_SIZE
        if (!isP256) {
            throw ValidationException(ERROR_MESSAGE_INVALID_DS_CERT_KEY_FOR_ALG, ERROR_CODE_INVALID_ALG)
        }
    }

    private fun verifyDsCertificate(issuerAuth: Array): X509Certificate {
        val issuerCertificate = extractCertificate(issuerAuth)
            ?: throw SignatureVerificationException(
                "Error while doing COSE signature verification - certificate chain is empty"
            )

        verifyDsCertificateValidity(issuerCertificate)
        return issuerCertificate
    }

    /**
     * An expired or not-yet-valid DS certificate is a hard failure: the signature cannot be
     * trusted once the key is outside its validity. Compared leniently with the shared mdoc
     * clock-skew tolerance.
     */
    private fun verifyDsCertificateValidity(issuerCertificate: X509Certificate) {
        val now = options.currentTimeMillis()
        if (MdocClock.isAfterNow(issuerCertificate.notBefore.time, now) ||
            MdocClock.isBeforeNow(issuerCertificate.notAfter.time, now)
        ) {
            logger.severe(
                "DS certificate is outside its validity period " +
                    "(notBefore=${issuerCertificate.notBefore}, notAfter=${issuerCertificate.notAfter})"
            )
            throw ValidationException(
                ERROR_MESSAGE_INVALID_DS_CERT_VALIDITY,
                ERROR_CODE_INVALID_X5C_CERT_VALIDITY
            )
        }
    }

    /**
     * MSO `signed` must fall within the DS certificate validity. Both are issuer timestamps,
     * so no clock-skew tolerance is applied.
     */
    private fun verifySignedWithinDsCertificateValidity(mso: Map, dsCertificate: X509Certificate) {
        val signed = (mso.getOrNull(VALIDITY_INFO) as? Map)?.getOrNull(SIGNED)
            ?: throw ValidationException(
                ERROR_MESSAGE_MISSING_SIGNED_MSO,
                ERROR_CODE_INVALID_VALIDITY_INFO_MSO
            )
        val signedDate = DateUtils.parseDate(signed.toString())
            ?: throw ValidationException(
                ERROR_MESSAGE_INVALID_SIGNED_MSO,
                ERROR_CODE_INVALID_VALIDITY_INFO_MSO
            )
        if (signedDate.before(dsCertificate.notBefore) || signedDate.after(dsCertificate.notAfter)) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_SIGNED_OUTSIDE_DS_CERT,
                ERROR_CODE_INVALID_SIGNED_OUTSIDE_DS_CERT
            )
        }
    }

    private fun verifyDocType(decodedCredential: Map, mso: Map, isLatest: Boolean): Boolean {
        if (isLatest) {
            return true
        }
        val docTypeInMso = mso[DOC_TYPE]
        // Read from the same place IssuerSigned was taken (see MsoMdocVerifiableCredential.parse):
        // documents[0] when "documents" is present, otherwise the top level.
        val docTypeInDocument = if (decodedCredential.keys.contains(UnicodeString(DOCUMENTS))) {
            ((decodedCredential[DOCUMENTS] as Array)[0] as Map).getOrNull(DOC_TYPE)
        } else {
            decodedCredential.getOrNull(DOC_TYPE)
        } ?: throw ValidationException(ERROR_MESSAGE_MISSING_DOC_TYPE, ERROR_CODE_INVALID_DOC_TYPE)
        if (docTypeInMso == docTypeInDocument) {
            return true
        }
        logger.severe("Error while doing docType property verification - Property mismatch with docType in the credential")
        throw ValidationException(ERROR_MESSAGE_DOC_TYPE_MISMATCH, ERROR_CODE_INVALID_DOC_TYPE)
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


    /**
     * Digest check per received IssuerSignedItem (ISO 18013-5 §9.3.1 c).
     *
     * Data that does not match what the issuer signed (namespace / digestID absent from the MSO,
     * digest mismatch, parser disagreement on the item bytes) is [LikelyTamperedException];
     * structural problems stay [ValidationException]. Details (namespace, digestID) are logged
     * only, never returned to the caller.
     */
    private fun verifyValueDigests(
        issuerSignedNamespaces: Map,
        encodedNameSpaceItems: kotlin.collections.Map<String, List<ByteArray>>,
        mso: Map,
    ): List<DecodedIssuerSignedItem> {
        val digestAlgorithm = requireSupportedDigestAlgorithm(mso)
        val digestsByNamespace = mso.getOrNull(VALUE_DIGESTS) as? Map
            ?: throw ValidationException(
                ERROR_MESSAGE_INVALID_VALUE_DIGESTS_STRUCTURE,
                ERROR_CODE_INVALID_MSO
            )
        val decodedItems = decodeIssuerSignedItems(issuerSignedNamespaces)

        val itemsByNamespace = decodedItems.groupBy { it.namespace }

        // Every received namespace, including an empty one, must have digests in the MSO.
        issuerSignedNamespaces.keys.forEach { namespaceKey ->
            // decodeIssuerSignedItems has already rejected non-text namespace keys.
            val namespace = (namespaceKey as UnicodeString).string
            val namespaceItems = itemsByNamespace[namespace].orEmpty()
            val encodedItems = encodedNameSpaceItems[namespace]
            if (encodedItems == null || encodedItems.size != namespaceItems.size) {
                logger.severe("As-received nameSpaces bytes unavailable for namespace '$namespace'")
                throw ValidationException(
                    ERROR_MESSAGE_INVALID_VALUE_DIGESTS,
                    ERROR_CODE_INVALID_VALUE_DIGESTS
                )
            }

            val valueDigests: Map = when (val digests = digestsByNamespace[UnicodeString(namespace)]) {
                null -> {
                    logger.severe("Received namespace '$namespace' has no digests in the MSO")
                    throw LikelyTamperedException()
                }
                is Map -> digests
                else -> throw ValidationException(
                    ERROR_MESSAGE_INVALID_VALUE_DIGESTS_STRUCTURE,
                    ERROR_CODE_INVALID_MSO
                )
            }

            val calculatedDigests = linkedMapOf<BigInteger, ByteArray>()
            val elementIdentifiers = mutableSetOf<String>()

            namespaceItems.forEach { item ->
                // Hash IssuerSignedItemBytes exactly as received (full tag-24 wrapper bytes).
                val issuerSignedItemBytes = encodedItems[item.index]
                requireSameItemAsParsed(namespace, item.index, issuerSignedItemBytes, item.encoded!!)
                val digest = MessageDigest.getInstance(digestAlgorithm).digest(issuerSignedItemBytes)

                // UnsignedInteger.value is never negative, so only the upper bound is checked.
                if (item.digestId >= DIGEST_ID_MAX_EXCLUSIVE) {
                    throw ValidationException(
                        ERROR_MESSAGE_DIGEST_ID_OUT_OF_RANGE,
                        ERROR_CODE_INVALID_DIGEST_ID
                    )
                }

                val salt = item.random as? ByteString
                if (salt == null || salt.bytes.size < MIN_DIGEST_SALT_BYTES) {
                    throw ValidationException(
                        ERROR_MESSAGE_INVALID_DIGEST_SALT,
                        ERROR_CODE_INVALID_DIGEST_SALT
                    )
                }

                // Element lookups (e.g. issuing_country) must not depend on which duplicate wins.
                if (!elementIdentifiers.add(item.elementIdentifier)) {
                    throw ValidationException(
                        ERROR_MESSAGE_DUPLICATE_ELEMENT_IDENTIFIER,
                        ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
                    )
                }

                if (calculatedDigests.containsKey(item.digestId)) {
                    throw ValidationException(
                        ERROR_MESSAGE_INVALID_DIGEST_ID,
                        ERROR_CODE_INVALID_DIGEST_ID
                    )
                }
                calculatedDigests[item.digestId] = digest
            }

            for ((digestId, calculatedDigest) in calculatedDigests) {
                val msoDigest = valueDigests[UnsignedInteger(digestId)] as? ByteString
                if (msoDigest == null) {
                    logger.severe("valueDigests verification failed - digestID $digestId in namespace '$namespace' has no digest in the MSO")
                    throw LikelyTamperedException()
                }
                if (!calculatedDigest.contentEquals(msoDigest.bytes)) {
                    logger.severe("valueDigests verification failed - digest mismatch for digestID $digestId in namespace '$namespace'")
                    throw LikelyTamperedException()
                }
            }
        }

        return decodedItems
    }

    /**
     * The digest is computed over bytes from [MsoMdocNameSpacesRawBytes] while values come from
     * cbor-java, matched by position. Guard that both parsers saw the same item: the raw slice
     * must decode to a tag-24 bstr whose content equals the parsed item's content.
     */
    private fun requireSameItemAsParsed(
        namespace: String,
        index: Int,
        rawItemBytes: ByteArray,
        parsedItem: ByteString,
    ) {
        val decodedRaw = try {
            CborDecoder(ByteArrayInputStream(rawItemBytes)).decode().singleOrNull()
        } catch (exception: Exception) {
            null
        }
        if (decodedRaw !is ByteString ||
            decodedRaw.tag?.value != 24L ||
            !decodedRaw.bytes.contentEquals(parsedItem.bytes)
        ) {
            logger.severe("As-received bytes of item $index in namespace '$namespace' do not match the parsed item")
            throw LikelyTamperedException()
        }
    }
}
