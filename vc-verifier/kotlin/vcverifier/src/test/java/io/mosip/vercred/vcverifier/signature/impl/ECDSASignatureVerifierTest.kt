package io.mosip.vercred.vcverifier.signature.impl

import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve

private const val CURVE = "secp256r1"
private const val SIGNED_DATA = "verifiable credential payload"

/**
 * Guards the curve check against provider differences.
 *
 * BouncyCastle reports key parameters as an ECNamedCurveSpec, but Conscrypt - the default
 * X.509 provider on Android - reports a plain ECParameterSpec that carries no curve name.
 * These tests cover both shapes so the Android path is exercised on the JVM.
 */
class ECDSASignatureVerifierTest {

    private val provider = BouncyCastleProvider()

    /** Reports a plain [ECParameterSpec] for an otherwise valid key, as Conscrypt does. */
    private class UnnamedCurveEcPublicKey(
        private val delegate: ECPublicKey,
        private val unnamedParams: ECParameterSpec,
    ) : ECPublicKey by delegate {
        override fun getParams(): ECParameterSpec = unnamedParams
    }

    @Test
    fun `should verify a key whose parameters carry the curve name`() {
        val keyPair = generateKeyPair()
        val signature = sign(keyPair, SIGNED_DATA)

        assertTrue(
            ES256SignatureVerifierImpl()
                .verify(keyPair.public, SIGNED_DATA.toByteArray(), signature, provider)
        )
    }

    @Test
    fun `should verify a key whose parameters carry no curve name`() {
        val keyPair = generateKeyPair()
        val signature = sign(keyPair, SIGNED_DATA)
        val publicKey = withoutCurveName(keyPair.public as ECPublicKey)

        assertFalse(publicKey.params is ECNamedCurveSpec)
        assertTrue(
            ES256SignatureVerifierImpl()
                .verify(publicKey, SIGNED_DATA.toByteArray(), signature, provider)
        )
    }

    @Test
    fun `should reject a key whose parameters carry no curve name and a mismatched curve`() {
        val keyPair = generateKeyPair()
        val signature = sign(keyPair, SIGNED_DATA)
        val publicKey = withoutCurveName(keyPair.public as ECPublicKey)

        val exception = assertThrows<SignatureVerificationException> {
            ES256KSignatureVerifierImpl()
                .verify(publicKey, SIGNED_DATA.toByteArray(), signature, provider)
        }

        assertTrue(exception.message!!.contains("does not match proof type"))
    }

    private fun generateKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC", provider)
            .apply { initialize(ECGenParameterSpec(CURVE)) }
            .generateKeyPair()

    /** Rebuilds the key parameters as a plain [ECParameterSpec], dropping the curve name. */
    private fun withoutCurveName(publicKey: ECPublicKey): ECPublicKey {
        val curve = ECNamedCurveTable.getParameterSpec(CURVE)
        val field = curve.curve.field.characteristic
        val unnamedParams = ECParameterSpec(
            EllipticCurve(
                ECFieldFp(field),
                curve.curve.a.toBigInteger(),
                curve.curve.b.toBigInteger(),
            ),
            ECPoint(
                curve.g.normalize().affineXCoord.toBigInteger(),
                curve.g.normalize().affineYCoord.toBigInteger(),
            ),
            curve.n,
            curve.h.toInt(),
        )
        return UnnamedCurveEcPublicKey(publicKey, unnamedParams)
    }

    /** Signs [data] and returns the signature in the raw R || S form the verifier expects. */
    private fun sign(keyPair: KeyPair, data: String): ByteArray {
        val derSignature = Signature.getInstance("SHA256withECDSA", provider)
            .apply {
                initSign(keyPair.private)
                update(data.toByteArray())
            }
            .sign()
        return derToRaw(derSignature)
    }

    private fun derToRaw(derSignature: ByteArray): ByteArray {
        var offset = 3
        val rLength = derSignature[offset].toInt()
        offset++
        val r = BigInteger(1, derSignature.copyOfRange(offset, offset + rLength))
        offset += rLength + 1
        val sLength = derSignature[offset].toInt()
        offset++
        val s = BigInteger(1, derSignature.copyOfRange(offset, offset + sLength))

        return toFixedWidth(r) + toFixedWidth(s)
    }

    private fun toFixedWidth(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        val fixed = ByteArray(32)
        val source = if (bytes.size > 32) bytes.copyOfRange(bytes.size - 32, bytes.size) else bytes
        source.copyInto(fixed, 32 - source.size)
        return fixed
    }
}
