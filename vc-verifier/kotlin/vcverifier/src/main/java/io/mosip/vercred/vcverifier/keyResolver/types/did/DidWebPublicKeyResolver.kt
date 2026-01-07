package io.mosip.vercred.vcverifier.keyResolver.types.did

import com.fasterxml.jackson.databind.ObjectMapper
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_HEX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_JWK
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_MULTIBASE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_PEM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.VERIFICATION_METHOD
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.DidDocumentNotFound
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.DidResolutionFailed
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.networkManager.HttpMethod
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.vercred.vcverifier.keyResolver.getPublicKeyFromHex
import io.mosip.vercred.vcverifier.keyResolver.getPublicKeyFromJWK
import io.mosip.vercred.vcverifier.keyResolver.getPublicKeyObjectFromPemPublicKey
import io.mosip.vercred.vcverifier.keyResolver.getPublicKeyObjectFromPublicKeyMultibase
import java.security.PublicKey
import java.util.logging.Logger

private const val ID = "id"
private const val DOC_PATH = "/did.json"
private const val WELL_KNOWN_PATH = ".well-known"

class DidWebPublicKeyResolver : DidPublicKeyResolver() {

    private val logger = Logger.getLogger(DidWebPublicKeyResolver::class.java.name)

    override fun extractPublicKey(parsedDID: ParsedDID, keyId: String?): PublicKey {
        try {
            val didDocument = resolveDidDocument(parsedDID)

            val verificationMethods = didDocument[VERIFICATION_METHOD] as? List<Map<String, Any>>
                ?: throw PublicKeyNotFoundException("Verification method not found in DID document")

            val verificationMethodId = keyId ?: parsedDID.didUrl
            val verificationMethod = verificationMethods.find {
                it[ID] == verificationMethodId
            }
                ?: throw PublicKeyResolutionFailedException("Public key extraction failed for kid: $verificationMethodId")

            val publicKeyStr = getKeyValue(
                verificationMethod, arrayOf(
                    PUBLIC_KEY_PEM, PUBLIC_KEY_MULTIBASE, PUBLIC_KEY_JWK, PUBLIC_KEY_HEX
                )
            )
            val keyType = getKeyValue(verificationMethod, arrayOf(KEY_TYPE))
            return when {
                PUBLIC_KEY_JWK in verificationMethod -> getPublicKeyFromJWK(
                    publicKeyStr, keyType
                )

                PUBLIC_KEY_HEX in verificationMethod -> getPublicKeyFromHex(
                    publicKeyStr, keyType
                )

                PUBLIC_KEY_PEM in verificationMethod -> getPublicKeyObjectFromPemPublicKey(
                    publicKeyStr, keyType
                )

                PUBLIC_KEY_MULTIBASE in verificationMethod -> getPublicKeyObjectFromPublicKeyMultibase(
                    publicKeyStr, keyType
                )

                else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
            }
        } catch (e: Exception) {
            logger.severe("Error fetching public key: ${e.message}")
            when (e) {
                is PublicKeyNotFoundException,
                is PublicKeyResolutionFailedException,
                is PublicKeyTypeNotSupportedException -> throw e

                else -> throw PublicKeyResolutionFailedException(e.message ?: "Unknown error")
            }
        }
    }

    private fun resolveDidDocument(parsedDID: ParsedDID): Map<String, Any> {
        try {
            val url = constructDIDUrl(parsedDID)
            return sendHTTPRequest(url, HttpMethod.GET)
                ?: throw DidDocumentNotFound("Did document could not be fetched")
        } catch (e: Exception) {
            logger.severe("Error fetching DID document: ${e.message}")
            throw DidResolutionFailed(e.message)
        }
    }

    private fun constructDIDUrl(parsedDid: ParsedDID): String {
        val idComponents = parsedDid.id.split(":").map { it }
        val baseDomain = idComponents.first()
        val path = idComponents.drop(1).joinToString("/")
        val urlPath = if (path.isEmpty()) {
            WELL_KNOWN_PATH + DOC_PATH
        } else {
            path + DOC_PATH
        }

        return "https://$baseDomain/$urlPath"
    }

    /**
     * Extracts the first available value for a given list of keys.
     */
    private fun getKeyValue(responseObjectNode: Map<String, Any>, keys: Array<String>): String {
        for (key in keys) {
            responseObjectNode[key]?.let { value ->
                return when (value) {
                    is String -> value
                    else -> ObjectMapper().writeValueAsString(value)
                }
            }
        }

        throw PublicKeyNotFoundException("None of the provided keys were found in verification method")
    }
}
