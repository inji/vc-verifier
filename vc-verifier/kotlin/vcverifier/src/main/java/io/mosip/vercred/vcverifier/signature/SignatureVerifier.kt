package io.mosip.vercred.vcverifier.signature

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey

internal var bouncyCastleProvider: BouncyCastleProvider = BouncyCastleProvider()
interface SignatureVerifier {
    fun verify(
        publicKey: PublicKey,
        signData: ByteArray,
        signature: ByteArray?,
        provider: BouncyCastleProvider? = bouncyCastleProvider
    ): Boolean
}