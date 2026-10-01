package io.mosip.vercred.vcverifier.keyResolver.types.did

import io.mosip.vercred.vcverifier.constants.DidMethod
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolver
import java.security.PublicKey

open class DidPublicKeyResolver : PublicKeyResolver {
    companion object {
        private const val PCT_ENCODED = "(?:%[0-9a-fA-F]{2})"
        private const val ID_CHAR = "(?:[a-zA-Z0-9._-]|$PCT_ENCODED)"
        private const val METHOD = "([a-z0-9]+)"
        private const val METHOD_ID = "((?:$ID_CHAR*:)*($ID_CHAR+))"
        private const val PARAM_CHAR = "[a-zA-Z0-9_.:%-]"
        private const val PARAM = ";$PARAM_CHAR+=$PARAM_CHAR*"
        private const val PARAMS = "(($PARAM)*)"
        private const val PATH = "(/[^#?]*)?"
        private const val QUERY = "([?][^#]*)?"
        private const val FRAGMENT = "(#.*)?"
        private val DID_MATCHER = "^did:$METHOD:$METHOD_ID$PARAMS$PATH$QUERY$FRAGMENT$".toRegex()
    }

    open fun extractPublicKey(
        parsedDID: ParsedDID,
        keyId: String? = null
    ): PublicKey {
        throw RuntimeException("extractPublicKey is not implemented for DidPublicKeyResolver")
    }

    final override fun resolve(uri: String, keyId: String?): PublicKey {
        val parsedDID: ParsedDID = parseDidUrl(stripDidJwkPadding(uri))
        val didPublicKeyResolver: DidPublicKeyResolver = resolver(parsedDID)

        return didPublicKeyResolver.extractPublicKey(parsedDID, keyId)
    }

    private fun resolver(parsedDID: ParsedDID): DidPublicKeyResolver {
        return when (parsedDID.method) {
            DidMethod.WEB -> DidWebPublicKeyResolver()
            DidMethod.KEY -> DidKeyPublicKeyResolver()
            DidMethod.JWK -> DidJwkPublicKeyResolver()
        }
    }

    // Some issuers encode did:jwk with base64url "=" padding, which DID syntax does not allow;
    // strip it so those holder DIDs still resolve.
    private fun stripDidJwkPadding(didUrl: String): String {
        if (!didUrl.startsWith("did:jwk:")) return didUrl
        val did = didUrl.substringBefore('#').trimEnd('=')
        return if (didUrl.contains('#')) "$did#${didUrl.substringAfter('#')}" else did
    }

    private fun parseDidUrl(didUrl: String): ParsedDID {
        val matchResult = DID_MATCHER.find(didUrl) ?: throw UnsupportedDidUrl()
        val sections = matchResult.groupValues

        val didMethod = DidMethod.fromValue(sections[1])
            ?: throw UnsupportedDidUrl("Unsupported DID method: ${sections[1]}")

        return sections.let {
            ParsedDID(
                did = "did:${it[1]}:${it[2]}",
                method = didMethod,
                id = it[2],
                didUrl = didUrl
            ).apply {
                if (it[4].isNotEmpty()) {
                    params = it[4].substring(1)
                        .split(";")
                        .filter { param -> param.isNotEmpty() }
                        .associate { param ->
                            val kv = param.split("=")
                            kv[0] to (kv.getOrNull(1) ?: "")
                        }
                }

                if (it[6].isNotEmpty()) path = it[6]
                if (it[7].isNotEmpty()) query = it[7].substring(1)
                if (it[8].isNotEmpty()) fragment = it[8].substring(1)
            }
        }
    }
}
