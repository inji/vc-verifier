package io.mosip.vercred.vcverifier

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.HOLDER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ID
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_CODE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_MESSAGE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.HOLDER_MISMATCH_MSG
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.HOLDER_MISSING_MSG
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.HOLDER_VERIFICATION_FAIL_ERROR
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_PROOF_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256_PROOF_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.FAILED_TO_DECODE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JSON_WEB_PROOF_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.SUBJECT_ID_MISSING_MSG
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.UNSUPPORTED_KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.VERIFIABLE_CREDENTIAL_MISSING_MSG
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.HOLDER_PROOF_MISSING_MSG
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.INVALID_HOLDER_PROOF_MSG
import io.mosip.vercred.vcverifier.constants.Shared.KEY_VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.data.PresentationVerificationResult
import io.mosip.vercred.vcverifier.data.PresentationResultWithCredentialStatus
import io.mosip.vercred.vcverifier.data.PresentationResultWithCredentialStatusV2
import io.mosip.vercred.vcverifier.data.PresentationVerificationResultV2
import io.mosip.vercred.vcverifier.data.VCResult
import io.mosip.vercred.vcverifier.data.VCResultV2
import io.mosip.vercred.vcverifier.data.VCResultWithCredentialStatus
import io.mosip.vercred.vcverifier.data.VCResultWithCredentialStatusV2
import io.mosip.vercred.vcverifier.data.VPVerificationStatus
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.data.VerificationStatus
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.exception.HolderBindingException
import io.mosip.vercred.vcverifier.exception.PresentationNotSupportedException
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolverFactory
import io.mosip.vercred.vcverifier.keyResolver.decompressP256Key
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import io.mosip.vercred.vcverifier.signature.impl.ES256KSignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.ES256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.Util
import io.mosip.vercred.vcverifier.utils.asIterable
import org.json.JSONArray
import org.json.JSONObject
import java.security.spec.InvalidKeySpecException
import java.util.logging.Logger

private const val MULTIBASE_KEY_SIZE = 34
private const val ED_KEY_PREFIX = 0xed.toByte()
private const val MULTICODEC_TRAILING_BYTE = 0x01.toByte()
private const val P256_KEY_PREFIX_FIRST = 0x80.toByte()
private const val P256_KEY_PREFIX_SECOND = 0x24.toByte()

class PresentationVerifier {
    private val logger = Logger.getLogger(PresentationVerifier::class.java.name)

    private val credentialsVerifier: CredentialsVerifier = CredentialsVerifier()

    fun verify(presentation: String): PresentationVerificationResult {

        val presentationVerificationStatus: VPVerificationStatus = getPresentationVerificationStatus(presentation)

        val verifiableCredentials =
            JSONObject(presentation).optJSONArray(KEY_VERIFIABLE_CREDENTIAL)
                ?: JSONArray()
        val vcVerificationResults: List<VCResult> = getVCVerificationResults(verifiableCredentials)

        return PresentationVerificationResult(presentationVerificationStatus, vcVerificationResults)
    }

    fun verifyV2(presentation: String): PresentationVerificationResultV2 {

        val presentationVerificationResult: VerificationResult = getPresentationVerificationResult(presentation)

        val verifiableCredentials =
            JSONObject(presentation).optJSONArray(KEY_VERIFIABLE_CREDENTIAL)
                ?: JSONArray()
        val vcVerificationResults: List<VCResultV2> = getVCVerificationResultsV2(verifiableCredentials)

        return PresentationVerificationResultV2(presentationVerificationResult, vcVerificationResults)
    }

    private fun getPresentationVerificationStatus(presentation: String): VPVerificationStatus {
        logger.info("Received Presentation For Verification - getPresentationVerificationStatus - Start")
        val vcJsonLdObject: JsonLDObject

        try {
            vcJsonLdObject = JsonLDObject.fromJson(presentation)
        } catch (_: RuntimeException) {
            throw PresentationNotSupportedException("Unsupported VP Token type")
        }

        return try {
            if (verifyPresentationProof(vcJsonLdObject)) {
                //perform holder binding check
                return if (validateHolderBindingForDidKeyAndJwk(vcJsonLdObject).verificationStatus)
                    VPVerificationStatus.VALID
                else
                    VPVerificationStatus.INVALID
            }
            else
                VPVerificationStatus.INVALID
        } catch (e: Exception) {
            logger.severe("Error while verifying presentation proof : ${e.message}")
            when (e) {
                is PublicKeyNotFoundException,
                is IllegalStateException,
                is UnsupportedDidUrl,
                is InvalidKeySpecException,
                is SignatureNotSupportedException,
                is SignatureVerificationException -> throw e

                else -> {
                    throw UnknownException("Error while doing verification of verifiable presentation")
                }
            }
        }
    }

    private fun getPresentationVerificationResult(presentation: String): VerificationResult {
        logger.info("Received Presentation For Verification - getPresentationVerificationResult Start")
        val vcJsonLdObject: JsonLDObject

        try {
            vcJsonLdObject = JsonLDObject.fromJson(presentation)
        } catch (_: RuntimeException) {
            throw PresentationNotSupportedException("Unsupported VP Token type")
        }
        return try {
            val isVerified = verifyPresentationProof(vcJsonLdObject)

            if (isVerified) {
                //perform holder binding check
                return validateHolderBindingForDidKeyAndJwk(vcJsonLdObject)
            } else {
                VerificationResult(
                    false,
                    ERROR_MESSAGE_VERIFICATION_FAILED,
                    ERROR_CODE_VERIFICATION_FAILED
                )
            }
        } catch (e: Exception) {
            logger.severe("Error while verifying presentation : ${e.message}")
            when (e) {
                is PublicKeyNotFoundException,
                is IllegalStateException,
                is UnsupportedDidUrl,
                is InvalidKeySpecException,
                is SignatureNotSupportedException,
                is SignatureVerificationException -> throw e

                else -> {
                    throw UnknownException("Error while doing verification of verifiable presentation")
                }
            }
        }
    }

    private fun validateHolderBindingForDidKeyAndJwk(
        vcJsonLdObject: JsonLDObject
    ): VerificationResult {

        val presentationVerified = VerificationResult(
            true,
            "",
            ""
        )

        return try {
            logger.info("Starting holder binding check")
            val holderStr = vcJsonLdObject.jsonObject[HOLDER] as? String
                ?: return VerificationResult(
                    false,
                    HOLDER_MISSING_MSG,
                    HOLDER_VERIFICATION_FAIL_ERROR
                )

            val verifiableCredentials =
                vcJsonLdObject.jsonObject[KEY_VERIFIABLE_CREDENTIAL]
                    ?.let {
                        val vcs = it as? List<*> ?: listOf(it)

                        if (vcs.isEmpty()) {
                            throw HolderBindingException(
                                VERIFIABLE_CREDENTIAL_MISSING_MSG,
                                HOLDER_VERIFICATION_FAIL_ERROR
                            )
                        }

                        vcs
                    }
                    ?: throw HolderBindingException(
                        VERIFIABLE_CREDENTIAL_MISSING_MSG,
                        HOLDER_VERIFICATION_FAIL_ERROR
                    )

            val holderPublicKeyJson = extractPublicKeyJson(holderStr)

            if (holderPublicKeyJson == null) {
                logger.info(
                    "Skipping holder binding check: Method not supported for $holderStr"
                )
                return presentationVerified
            }

            validateHolderProofOfPossession(
                vcJsonLdObject,
                holderPublicKeyJson
            )

            verifiableCredentials.forEach { credentialObj ->

                val credential = credentialObj as? Map<*, *>
                    ?: throw HolderBindingException(
                        VERIFIABLE_CREDENTIAL_MISSING_MSG,
                        HOLDER_VERIFICATION_FAIL_ERROR
                    )

                val credentialSubject = credential[CREDENTIAL_SUBJECT]

                val subjects = when (credentialSubject) {
                    is Map<*, *> -> listOf(credentialSubject)
                    is List<*> -> credentialSubject.ifEmpty { null }
                    else -> null
                } ?: throw HolderBindingException(
                    SUBJECT_ID_MISSING_MSG,
                    HOLDER_VERIFICATION_FAIL_ERROR
                )

                subjects.forEach subjectLoop@ { subject ->

                    val subjectStr =
                        (subject as? Map<*, *>)?.get(ID) as? String

                    if (subjectStr == null) {
                        logger.info("Skipping subject binding check: subject.id missing")
                        return@subjectLoop
                    }

                    val subjectPublicKeyJson =
                        extractPublicKeyJson(subjectStr) ?: run {

                            logger.info(
                                "Skipping subject binding check: " +
                                        "Method not supported for $subjectStr"
                            )

                            return@subjectLoop
                        }


                    if (
                        !comparePublicKeyJson(
                            holderPublicKeyJson,
                            subjectPublicKeyJson
                        )
                    ) {
                        throw HolderBindingException(
                            HOLDER_MISMATCH_MSG.format(
                                holderStr,
                                subjectStr
                            ),
                            HOLDER_VERIFICATION_FAIL_ERROR
                        )
                    }
                }
            }

            presentationVerified

        } catch (e: HolderBindingException) {
            logger.severe("Error while doing holder binding check, returning verification failed : ${e.errorCode} :  ${e.errorMessage}")
            VerificationResult(
                false,
                e.errorMessage,
                e.errorCode
            )
        }
    }

    private fun validateHolderProofOfPossession(
        vcJsonLdObject: JsonLDObject,
        holderPublicKeyJson: JSONObject
    ) {
        logger.info("Starting holder proof-of-possession check")
        val proof = LdProof.getFromJsonLDObject(vcJsonLdObject)

        val verificationMethod = proof.verificationMethod?.toString()
            ?: throw HolderBindingException(
                HOLDER_PROOF_MISSING_MSG,
                HOLDER_VERIFICATION_FAIL_ERROR
            )

        val verificationMethodKeyJson =
            extractPublicKeyJson(verificationMethod) ?: run {
                logger.severe(
                    "Invalid proof-of-possession verificationMethod $verificationMethod"
                )

                throw HolderBindingException(
                    INVALID_HOLDER_PROOF_MSG,
                    HOLDER_VERIFICATION_FAIL_ERROR
                )
            }

        if (!comparePublicKeyJson(holderPublicKeyJson, verificationMethodKeyJson)) {
            throw HolderBindingException(
                INVALID_HOLDER_PROOF_MSG,
                HOLDER_VERIFICATION_FAIL_ERROR
            )
        }
    }

    //TODO when DidKeyPublicKeyResolver/DidJwkPublicKeyResolver is extended to support RSA, generic EC, OKP
    // along with current Ed25519, P-256 below code should be replaced with DidKeyPublicKeyResolver / DidJwkPublicKeyResolver
    private fun extractPublicKeyJson(input: String): JSONObject? {
        return when {
            input.startsWith("did:jwk:") -> {
                try {
                    val encodedJwk = input
                        .removePrefix("did:jwk:")
                        .split('#', '?', ';')[0]
                    val jwkJson = String(
                        Base64Decoder().decodeFromBase64Url(encodedJwk)
                    )
                    val parsedJwk = JWK.parse(jwkJson)
                    val publicJwk = parsedJwk.toPublicJWK()
                    JSONObject(publicJwk.toJSONObject())
                } catch (e: HolderBindingException) {
                    throw e
                } catch (e: Exception) {
                    throw HolderBindingException(
                        FAILED_TO_DECODE,
                        HOLDER_VERIFICATION_FAIL_ERROR
                    )
                }
            }

            input.startsWith("did:key:") -> {
                try {
                    val methodSpecificId = input
                        .removePrefix("did:key:")
                        .split('#', '?', ';')[0]

                    val decodedKey = Multibase.decode(methodSpecificId)
                    when {
                        isEd25519KeyType(decodedKey) -> {
                            val x = Base64URL.encode(
                                decodedKey.copyOfRange(2, 34)
                            )
                            JSONObject(
                                OctetKeyPair.Builder(Curve.Ed25519, x)
                                    .build()
                                    .toJSONObject()
                            )
                        }
                        isP256KeyType(decodedKey) -> {
                            val publicKeyBytes =
                                decodedKey.copyOfRange(2, decodedKey.size)
                            val decompressed =
                                decompressP256Key(publicKeyBytes)
                            val x = Base64URL.encode(
                                decompressed.copyOfRange(1, 33)
                            )
                            val y = Base64URL.encode(
                                decompressed.copyOfRange(33, 65)
                            )
                            JSONObject(
                                ECKey.Builder(Curve.P_256, x, y)
                                    .build()
                                    .toJSONObject()
                            )
                        }
                        else -> {
                            throw HolderBindingException(
                                UNSUPPORTED_KEY_TYPE.format(decodedKey),
                                HOLDER_VERIFICATION_FAIL_ERROR
                            )
                        }
                    }
                } catch (e: HolderBindingException) {
                    throw e
                } catch (e: Exception) {
                    throw HolderBindingException(
                        FAILED_TO_DECODE,
                        HOLDER_VERIFICATION_FAIL_ERROR
                    )
                }
            }
            else -> null
        }
    }

    private fun comparePublicKeyJson(publicKeyJson1: JSONObject, publicKeyJson2: JSONObject): Boolean {
        val keyType = publicKeyJson1.optString("kty")
        if (keyType != publicKeyJson2.optString("kty")) return false

        return when (keyType) {
            "EC" -> publicKeyJson1.optString("crv") == publicKeyJson2.optString("crv") &&
                    publicKeyJson1.optString("x") == publicKeyJson2.optString("x") &&
                    publicKeyJson1.optString("y") == publicKeyJson2.optString("y")

            "OKP" -> publicKeyJson1.optString("crv") == publicKeyJson2.optString("crv") &&
                    publicKeyJson1.optString("x") == publicKeyJson2.optString("x")

            "RSA" -> publicKeyJson1.optString("n") == publicKeyJson2.optString("n") &&
                    publicKeyJson1.optString("e") == publicKeyJson2.optString("e")

            else -> false
        }
    }

    private fun isEd25519KeyType(decodedKey: ByteArray) =
        (decodedKey[0] == ED_KEY_PREFIX && decodedKey[1] == MULTICODEC_TRAILING_BYTE) && decodedKey.size == MULTIBASE_KEY_SIZE

    private fun isP256KeyType(decodedKey: ByteArray) =
        decodedKey[0] == P256_KEY_PREFIX_FIRST && decodedKey[1] == P256_KEY_PREFIX_SECOND

    private fun verifyPresentationProof(vcJsonLdObject: JsonLDObject): Boolean {

        vcJsonLdObject.documentLoader = Util.getConfigurableDocumentLoader()
        val ldProof = LdProof.getFromJsonLDObject(vcJsonLdObject)

        val canonicalHashBytes =
            URDNA2015Canonicalizer().canonicalize(ldProof, vcJsonLdObject)

        val publicKey =
            PublicKeyResolverFactory().get(ldProof.verificationMethod)

        return when {
            ldProof.type == ED25519_PROOF_TYPE_2018 && !ldProof.jws.isNullOrEmpty() -> {
                val jws = JWSObject.parse(ldProof.jws)
                val actualData =
                    JWSUtil.getJwsSigningInput(jws.header, canonicalHashBytes)

                ED25519SignatureVerifierImpl().verify(
                    publicKey,
                    actualData,
                    jws.signature.decode()
                )
            }

            ldProof.type == ED25519_PROOF_TYPE_2020 && !ldProof.proofValue.isNullOrEmpty() -> {
                ED25519SignatureVerifierImpl().verify(
                    publicKey,
                    canonicalHashBytes,
                    Multibase.decode(ldProof.proofValue)
                )
            }

            (ldProof.type == ES256K_PROOF_TYPE_2019) && !ldProof.proofValue.isNullOrEmpty() -> {
                ES256KSignatureVerifierImpl().verify(
                    publicKey,
                    canonicalHashBytes,
                    Multibase.decode(ldProof.proofValue)
                )
            }

            (ldProof.type == ES256_PROOF_TYPE_2019) && !ldProof.proofValue.isNullOrEmpty() -> {
                ES256SignatureVerifierImpl().verify(
                    publicKey,
                    canonicalHashBytes,
                    Multibase.decode(ldProof.proofValue)
                )
            }

            (ldProof.type == ES256K_PROOF_TYPE_2019) && !ldProof.jws.isNullOrEmpty() -> {
                val jws = JWSObject.parse(ldProof.jws)
                val actualData = JWSUtil.getJwsSigningInput(jws.header, canonicalHashBytes)
                if (jws.header.algorithm != JWSAlgorithm.ES256K) {
                    throw SignatureNotSupportedException("Unsupported JWS algorithm")
                }
                ES256KSignatureVerifierImpl().verify(
                    publicKey,
                    actualData,
                    jws.signature.decode()
                )
            }

            (ldProof.type == ES256_PROOF_TYPE_2019) && !ldProof.jws.isNullOrEmpty() -> {
                val jws = JWSObject.parse(ldProof.jws)
                val actualData = JWSUtil.getJwsSigningInput(jws.header, canonicalHashBytes)
                if (jws.header.algorithm != JWSAlgorithm.ES256) {
                    throw SignatureNotSupportedException("Unsupported JWS algorithm")
                }
                ES256SignatureVerifierImpl().verify(
                    publicKey,
                    actualData,
                    jws.signature.decode()
                )
            }

            ldProof.type == JSON_WEB_PROOF_TYPE_2020 && !ldProof.jws.isNullOrEmpty() -> {
                val jws = JWSObject.parse(ldProof.jws)
                if (jws.header.algorithm != JWSAlgorithm.EdDSA && jws.header.algorithm != JWSAlgorithm.ES256K && jws.header.algorithm != JWSAlgorithm.ES256) {
                    throw SignatureNotSupportedException("Unsupported JWS algorithm")
                }

                val actualData =
                    JWSUtil.getJwsSigningInput(jws.header, canonicalHashBytes)

                when (jws.header.algorithm) {
                    JWSAlgorithm.EdDSA -> {
                        ED25519SignatureVerifierImpl().verify(
                            publicKey,
                            actualData,
                            jws.signature.decode()
                        )
                    }
                    JWSAlgorithm.ES256K -> {
                        ES256KSignatureVerifierImpl().verify(
                            publicKey,
                            actualData,
                            jws.signature.decode()
                        )
                    }
                    JWSAlgorithm.ES256 -> {
                        ES256SignatureVerifierImpl().verify(
                            publicKey,
                            actualData,
                            jws.signature.decode()
                        )
                    }
                    else -> false
                }
            }
            else -> false
        }
    }

    private fun getVCVerificationResults(verifiableCredentials: JSONArray): List<VCResult> {
        return verifiableCredentials.asIterable().map { item ->
            val verificationResult: VerificationResult =
                credentialsVerifier.verify((item as JSONObject).toString(), CredentialFormat.LDP_VC)
            val singleVCVerification: VerificationStatus =
                Util.getVerificationStatus(verificationResult)

            /*
            Here we are adding the entire VC as a string in the method response. We know that this is not very efficient.
            But in newer draft of OpenId4VP specifications the Presentation Exchange
            is fully removed so we rather not use the submission_requirements for giving the VC reference
            for response. As of now we could not find anything unique that can be referred in a vp_token
            VC we will be going with the approach of sending whole VC back in response.
            */
            VCResult(
                item.toString(),
                singleVCVerification
            )
        }
    }

    private fun getVCVerificationResultsV2(verifiableCredentials: JSONArray): List<VCResultV2> {
        return verifiableCredentials.asIterable().map { item ->
            val verificationResult: VerificationResult =
                credentialsVerifier.verify((item as JSONObject).toString(), CredentialFormat.LDP_VC)

            /*
            Here we are adding the entire VC as a string in the method response. We know that this is not very efficient.
            But in newer draft of OpenId4VP specifications the Presentation Exchange
            is fully removed so we rather not use the submission_requirements for giving the VC reference
            for response. As of now we could not find anything unique that can be referred in a vp_token
            VC we will be going with the approach of sending whole VC back in response.
            */
            VCResultV2(
                item.toString(),
                verificationResult
            )
        }
    }

    private fun getVCVerificationResultsWithCredentialStatus(verifiableCredentials: JSONArray, statusPurposeList: List<String>): List<VCResultWithCredentialStatus> {
        return verifiableCredentials.asIterable().map { item ->
            val credentialVerificationSummary = credentialsVerifier.verifyAndGetCredentialStatus((item as JSONObject).toString(), CredentialFormat.LDP_VC, statusPurposeList)
            val verificationResult: VerificationResult = credentialVerificationSummary.verificationResult
            val singleVCVerification: VerificationStatus = Util.getVerificationStatus(verificationResult)
            val credentialStatus = credentialVerificationSummary.credentialStatus

            VCResultWithCredentialStatus(item.toString(), singleVCVerification, credentialStatus)
        }
    }

    private fun getVCVerificationResultsWithCredentialStatusV2(verifiableCredentials: JSONArray, statusPurposeList: List<String>): List<VCResultWithCredentialStatusV2> {
        return verifiableCredentials.asIterable().map { item ->
            val credentialVerificationSummary = credentialsVerifier.verifyAndGetCredentialStatus((item as JSONObject).toString(), CredentialFormat.LDP_VC, statusPurposeList)
            val verificationResult: VerificationResult = credentialVerificationSummary.verificationResult
            val credentialStatus = credentialVerificationSummary.credentialStatus

            VCResultWithCredentialStatusV2(item.toString(), verificationResult, credentialStatus)
        }
    }

    fun verifyAndGetCredentialStatus(
        presentation: String,
        statusPurposeList: List<String> = emptyList()
    ): PresentationResultWithCredentialStatus {
        val presentationVerificationStatus = getPresentationVerificationStatus(presentation)

        val verifiableCredentials =
            JSONObject(presentation).optJSONArray(KEY_VERIFIABLE_CREDENTIAL)
                ?: JSONArray()
        val vcVerificationResults: List<VCResultWithCredentialStatus> = getVCVerificationResultsWithCredentialStatus(verifiableCredentials, statusPurposeList)

        return PresentationResultWithCredentialStatus(presentationVerificationStatus, vcVerificationResults)
    }

    fun verifyAndGetCredentialStatusV2(
        presentation: String,
        statusPurposeList: List<String> = emptyList()
    ): PresentationResultWithCredentialStatusV2 {
        val presentationVerificationResult = getPresentationVerificationResult(presentation)

        val verifiableCredentials =
            JSONObject(presentation).optJSONArray(KEY_VERIFIABLE_CREDENTIAL)
                ?: JSONArray()
        val vcVerificationResults: List<VCResultWithCredentialStatusV2> = getVCVerificationResultsWithCredentialStatusV2(verifiableCredentials, statusPurposeList)

        return PresentationResultWithCredentialStatusV2(presentationVerificationResult, vcVerificationResults)
    }

}
