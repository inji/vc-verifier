package io.mosip.vercred.vcverifier.testHelpers

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.android.identity.internal.Util
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x509.Time
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import java.util.zip.Deflater

object MdocStatusListFixtures {
    const val STATUS_URI = "https://example.com/statuslists/1"
    const val WRONG_STATUS_URI = "https://example.com/statuslists/other"
    const val STATUS_IDX = 0L
    const val TTL_SECONDS = 3600L
    const val VALID_IAT = 1_700_000_000L
    const val VALID_EXP = 4_102_444_800L
    const val EXPIRED_EXP = 1_600_000_000L
    const val DOC_TYPE = "org.iso.18013.5.1.mDL"

    val keyMaterial: StatusListKeyMaterial by lazy { generateKeyMaterial() }

    data class StatusListKeyMaterial(
        val keyPair: KeyPair,
        val certificate: X509Certificate
    )

    fun generateKeyMaterial(): StatusListKeyMaterial {
        val keyGen = KeyPairGenerator.getInstance("EC")
        keyGen.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = keyGen.generateKeyPair()
        return StatusListKeyMaterial(keyPair, selfSignedCertificate(keyPair))
    }

    fun statusListCwt(
        bits: Int,
        valuesAtIndex: IntArray,
        uri: String = STATUS_URI,
        exp: Long = VALID_EXP,
        includeX5chain: Boolean = true,
        corruptSignature: Boolean = false,
        keyMaterial: StatusListKeyMaterial = this.keyMaterial,
        ttlSeconds: Long? = TTL_SECONDS,
        typ: String = "application/statuslist+cwt",
        includeTyp: Boolean = true
    ): ByteArray {
        val compressed = zlibCompress(packBits(bits, valuesAtIndex))
        val statusList = Map().apply {
            put(UnicodeString("bits"), UnsignedInteger(bits.toLong()))
            put(UnicodeString("lst"), ByteString(compressed))
        }
        val claims = Map().apply {
            put(UnsignedInteger(2), UnicodeString(uri))
            put(UnsignedInteger(6), UnsignedInteger(VALID_IAT))
            put(UnsignedInteger(4), UnsignedInteger(exp))
            if (ttlSeconds != null) {
                put(UnsignedInteger(65534), UnsignedInteger(ttlSeconds))
            }
            put(UnsignedInteger(65533), statusList)
        }
        return signCwt(
            claims,
            keyMaterial,
            includeX5chain = includeX5chain,
            corruptSignature = corruptSignature,
            typ = typ,
            includeTyp = includeTyp
        )
    }

    fun emptyListCwt(bits: Int = 1, uri: String = STATUS_URI): ByteArray {
        val statusList = Map().apply {
            put(UnicodeString("bits"), UnsignedInteger(bits.toLong()))
            put(UnicodeString("lst"), ByteString(zlibCompress(ByteArray(0))))
        }
        val claims = Map().apply {
            put(UnsignedInteger(2), UnicodeString(uri))
            put(UnsignedInteger(6), UnsignedInteger(VALID_IAT))
            put(UnsignedInteger(4), UnsignedInteger(VALID_EXP))
            put(UnsignedInteger(65534), UnsignedInteger(TTL_SECONDS))
            put(UnsignedInteger(65533), statusList)
        }
        return signCwt(claims, keyMaterial)
    }

    fun mdocWithStatus(
        uri: String = STATUS_URI,
        idx: Long = STATUS_IDX,
        validUntil: String = "2099-01-01T00:00:00Z",
        includeStatus: Boolean = true
    ): String {
        val validityInfo = Map().apply {
            put(UnicodeString("validFrom"), taggedDate("2024-01-01T00:00:00Z"))
            put(UnicodeString("validUntil"), taggedDate(validUntil))
        }
        val mso = Map().apply {
            put(UnicodeString("version"), UnicodeString("1.0"))
            put(UnicodeString("digestAlgorithm"), UnicodeString("SHA-256"))
            put(UnicodeString("valueDigests"), Map())
            put(UnicodeString("deviceKeyInfo"), Map())
            put(UnicodeString("docType"), UnicodeString(DOC_TYPE))
            put(UnicodeString("validityInfo"), validityInfo)
            if (includeStatus) {
                val statusList = Map().apply {
                    put(UnicodeString("uri"), UnicodeString(uri))
                    put(UnicodeString("idx"), UnsignedInteger(idx))
                }
                put(
                    UnicodeString("status"),
                    Map().apply { put(UnicodeString("status_list"), statusList) }
                )
            }
        }
        val issuerAuth = Util.coseSign1Sign(
            keyMaterial.keyPair.private,
            "SHA256withECDSA",
            encode(mso),
            byteArrayOf(),
            listOf(keyMaterial.certificate)
        )
        val credential = Map().apply {
            put(UnicodeString("docType"), UnicodeString(DOC_TYPE))
            put(
                UnicodeString("issuerSigned"),
                Map().apply {
                    put(UnicodeString("issuerAuth"), issuerAuth)
                    put(UnicodeString("nameSpaces"), Map())
                }
            )
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encode(credential))
    }

    fun mdocNoStatus(): String = mdocWithStatus(includeStatus = false)

    fun mdocExpired(): String = mdocWithStatus(validUntil = "2020-01-01T00:00:00Z")

    fun packBits(bitSize: Int, values: IntArray): ByteArray {
        if (values.isEmpty()) {
            return ByteArray(0)
        }
        val totalBits = values.size * bitSize
        val bytes = ByteArray((totalBits + 7) / 8)
        values.forEachIndexed { index, value ->
            val bitIndex = index * bitSize
            for (i in 0 until bitSize) {
                val bit = (value shr i) and 1
                if (bit == 1) {
                    val absoluteBit = bitIndex + i
                    val byteIndex = absoluteBit / 8
                    val bitOffset = absoluteBit % 8
                    bytes[byteIndex] = (bytes[byteIndex].toInt() or (1 shl bitOffset)).toByte()
                }
            }
        }
        return bytes
    }

    fun zlibCompress(data: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.BEST_COMPRESSION)
        deflater.setInput(data)
        deflater.finish()
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(256)
        while (!deflater.finished()) {
            val count = deflater.deflate(buffer)
            output.write(buffer, 0, count)
        }
        deflater.end()
        return output.toByteArray()
    }

    fun signCwt(
        claims: Map,
        keyMaterial: StatusListKeyMaterial = this.keyMaterial,
        includeX5chain: Boolean = true,
        corruptSignature: Boolean = false,
        typ: String = "application/statuslist+cwt",
        includeTyp: Boolean = true,
        tag: Long = 18L
    ): ByteArray {
        val protectedMap = Map().apply {
            put(UnsignedInteger(1), NegativeInteger(-7))
            if (includeTyp) {
                put(UnsignedInteger(16), UnicodeString(typ))
            }
        }
        val protectedBytes = encode(protectedMap)
        val payload = encode(claims)
        val unprotected = Map().apply {
            if (includeX5chain) {
                put(UnsignedInteger(33), ByteString(keyMaterial.certificate.encoded))
            }
        }
        val toBeSigned = Array().apply {
            add(UnicodeString("Signature1"))
            add(ByteString(protectedBytes))
            add(ByteString(ByteArray(0)))
            add(ByteString(payload))
        }
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(keyMaterial.keyPair.private)
        signer.update(encode(toBeSigned))
        val signature = derToRaw(signer.sign()).also { bytes ->
            if (corruptSignature && bytes.isNotEmpty()) {
                bytes[0] = (bytes[0].toInt() xor 0xFF).toByte()
            }
        }
        val coseSign1 = Array().apply {
            add(ByteString(protectedBytes))
            add(unprotected)
            add(ByteString(payload))
            add(ByteString(signature))
            setTag(tag)
        }
        return encode(coseSign1)
    }

    private fun taggedDate(value: String): DataItem {
        return UnicodeString(value).apply { setTag(0) }
    }

    private fun encode(dataItem: DataItem): ByteArray =
        ByteArrayOutputStream().also { CborEncoder(it).encode(dataItem) }.toByteArray()

    private fun selfSignedCertificate(keyPair: KeyPair): X509Certificate {
        val now = Date()
        val notAfter = Date(now.time + 20L * 365 * 24 * 60 * 60 * 1000)
        val name = X500Name("CN=mDoc Status List Test")
        val signatureAlgorithm = AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)
        val tbs = V3TBSCertificateGenerator().apply {
            setSerialNumber(ASN1Integer(BigInteger.ONE))
            setSignature(signatureAlgorithm)
            setIssuer(name)
            setStartDate(Time(now))
            setEndDate(Time(notAfter))
            setSubject(name)
            setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.public.encoded))
        }.generateTBSCertificate()
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(keyPair.private)
        signer.update(tbs.encoded)
        val vector = ASN1EncodableVector().apply {
            add(tbs)
            add(signatureAlgorithm)
            add(DERBitString(signer.sign()))
        }
        val encoded = DERSequence(vector).encoded
        return CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
    }

    private fun derToRaw(der: ByteArray, fieldSize: Int = 32): ByteArray {
        val sequence = ASN1Sequence.getInstance(der)
        val r = (sequence.getObjectAt(0) as ASN1Integer).value
        val s = (sequence.getObjectAt(1) as ASN1Integer).value
        return unsignedFixed(r, fieldSize) + unsignedFixed(s, fieldSize)
    }

    private fun unsignedFixed(value: BigInteger, size: Int): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == size -> bytes
            bytes.size < size -> ByteArray(size - bytes.size) + bytes
            else -> bytes.copyOfRange(bytes.size - size, bytes.size)
        }
    }
}
