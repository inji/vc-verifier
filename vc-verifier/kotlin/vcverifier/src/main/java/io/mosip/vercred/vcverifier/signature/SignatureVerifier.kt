package io.mosip.vercred.vcverifier.signature

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.Security

val bouncyCastleProvider: BouncyCastleProvider by lazy {
    val existingProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)
    existingProvider as? BouncyCastleProvider
        ?: BouncyCastleProvider().also {
            Security.addProvider(it)
        }
}
interface SignatureVerifier {
    fun verify(
        publicKey: PublicKey,
        signData: ByteArray,
        signature: ByteArray?,
        provider: BouncyCastleProvider? = bouncyCastleProvider
    ): Boolean
}