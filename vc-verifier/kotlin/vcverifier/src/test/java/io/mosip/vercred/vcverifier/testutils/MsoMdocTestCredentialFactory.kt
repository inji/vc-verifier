package testutils

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

internal object MsoMdocTestCredentialFactory {
    private const val MDL_DOC_TYPE = "org.iso.18013.5.1.mDL"
    private const val MDL_NAMESPACE = "org.iso.18013.5.1"

    fun create(
        legacyShape: Boolean = false,
        includeKeyUsage: Boolean = true,
        signed: Instant = Instant.now().minusSeconds(120),
        topLevelDocType: String? = MDL_DOC_TYPE,
        omitDigestId: Long? = null,
    ): String {
        val now = Instant.now()
        val privateKey = loadPrivateKey()
        val certificate = loadCertificate(includeKeyUsage)

        val records = mandatoryRecords()
        val namespaceItems = CborArray()
        val digestMap = CborMap()
        records.forEachIndexed { index, (identifier, value) ->
            val digestId = index.toLong()
            val item = CborMap().apply {
                put(UnicodeString("digestID"), UnsignedInteger(digestId))
                put(UnicodeString("random"), ByteString(ByteArray(16) { (index + 1).toByte() }))
                put(UnicodeString("elementIdentifier"), UnicodeString(identifier))
                put(UnicodeString("elementValue"), value)
            }
            val itemBytes = encode(item)
            val taggedItem = ByteString(itemBytes).apply { setTag(24) }
            namespaceItems.add(taggedItem)
            if (digestId != omitDigestId) {
                digestMap.put(
                    UnsignedInteger(digestId),
                    ByteString(java.security.MessageDigest.getInstance("SHA-256").digest(encode(taggedItem)))
                )
            }
        }

        val validFrom = now.minusSeconds(60)
        val validUntil = now.plusSeconds(365L * 24 * 60 * 60)
        val mso = CborMap().apply {
            put(UnicodeString("version"), UnicodeString("1.0"))
            put(UnicodeString("digestAlgorithm"), UnicodeString("SHA-256"))
            put(
                UnicodeString("valueDigests"),
                CborMap().apply {
                    put(UnicodeString(MDL_NAMESPACE), digestMap)
                }
            )
            put(UnicodeString("deviceKeyInfo"), CborMap())
            put(UnicodeString("docType"), UnicodeString(MDL_DOC_TYPE))
            put(
                UnicodeString("validityInfo"),
                CborMap().apply {
                    put(UnicodeString("signed"), taggedDate(signed))
                    put(UnicodeString("validFrom"), taggedDate(validFrom))
                    put(UnicodeString("validUntil"), taggedDate(validUntil))
                }
            )
        }
        val payload = encode(ByteString(encode(mso)).apply { setTag(24) })
        val protectedHeader = encode(
            CborMap().apply { put(UnsignedInteger(1), NegativeInteger(-7)) }
        )
        val issuerAuth = CborArray().apply {
            add(ByteString(protectedHeader))
            add(
                CborMap().apply {
                    put(UnsignedInteger(33), ByteString(certificate.encoded))
                }
            )
            add(ByteString(payload))
            add(ByteString(sign(privateKey, protectedHeader, payload)))
        }
        val namespaces = CborMap().apply {
            put(UnicodeString(MDL_NAMESPACE), namespaceItems)
        }
        val credential = if (legacyShape) {
            CborMap().apply {
                topLevelDocType?.let { put(UnicodeString("docType"), UnicodeString(it)) }
                put(
                    UnicodeString("issuerSigned"),
                    CborMap().apply {
                        put(UnicodeString("issuerAuth"), issuerAuth)
                        put(UnicodeString("nameSpaces"), namespaces)
                    }
                )
            }
        } else {
            CborMap().apply {
                put(UnicodeString("issuerAuth"), issuerAuth)
                put(UnicodeString("nameSpaces"), namespaces)
            }
        }

        return Base64.getUrlEncoder().withoutPadding().encodeToString(encode(credential))
    }

    private fun loadPrivateKey(): PrivateKey {
        val pem = readFixture("test_ds_key_pkcs8.pem")
        val encoded = pem.lineSequence()
            .filterNot { it.startsWith("-----") }
            .joinToString("")
        return KeyFactory.getInstance("EC").generatePrivate(
            PKCS8EncodedKeySpec(Base64.getDecoder().decode(encoded))
        )
    }

    private fun loadCertificate(includeKeyUsage: Boolean): X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(
                ByteArrayInputStream(
                    readFixture(
                        if (includeKeyUsage) "test_ds_mdl.pem" else "test_ds_no_key_usage.pem"
                    ).toByteArray()
                )
            ) as X509Certificate

    private fun readFixture(name: String): String =
        MsoMdocTestCredentialFactory::class.java.getResourceAsStream("/mso_mdoc/$name")
            ?.bufferedReader()
            ?.use { it.readText() }
            ?: error("Missing mDL test fixture: $name")

    private fun mandatoryRecords(): List<Pair<String, DataItem>> {
        val today = LocalDate.now(ZoneOffset.UTC)
        val fullDate = DateTimeFormatter.ISO_LOCAL_DATE
        return listOf(
            "family_name" to UnicodeString("Doe"),
            "given_name" to UnicodeString("Jane"),
            "birth_date" to UnicodeString("1990-01-01"),
            "issue_date" to UnicodeString(today.minusDays(1).format(fullDate)),
            "expiry_date" to UnicodeString(today.plusYears(5).format(fullDate)),
            "issuing_country" to UnicodeString("IN"),
            "issuing_authority" to UnicodeString("Test Authority"),
            "document_number" to UnicodeString("A1234567"),
            "portrait" to ByteString(byteArrayOf(1, 2, 3)),
            "driving_privileges" to CborArray().apply {
                add(
                    CborMap().apply {
                        put(UnicodeString("vehicle_category_code"), UnicodeString("A"))
                        put(UnicodeString("issue_date"), UnicodeString(today.minusDays(1).format(fullDate)))
                        put(UnicodeString("expiry_date"), UnicodeString(today.plusYears(5).format(fullDate)))
                    }
                )
            },
            "un_distinguishing_sign" to UnicodeString("IND"),
        )
    }

    private fun taggedDate(value: Instant): DataItem =
        UnicodeString(DateTimeFormatter.ISO_INSTANT.format(value.truncatedTo(java.time.temporal.ChronoUnit.SECONDS)))
            .apply { setTag(0) }

    private fun encode(dataItem: DataItem): ByteArray =
        ByteArrayOutputStream().also { CborEncoder(it).encode(dataItem) }.toByteArray()

    private fun sign(privateKey: PrivateKey, protectedHeader: ByteArray, payload: ByteArray): ByteArray {
        val structure = CborArray().apply {
            add(UnicodeString("Signature1"))
            add(ByteString(protectedHeader))
            add(ByteString(ByteArray(0)))
            add(ByteString(payload))
        }
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(encode(structure))
        val derSignature = ASN1Sequence.getInstance(signer.sign())
        val r = (derSignature.getObjectAt(0) as ASN1Integer).positiveValue
        val s = (derSignature.getObjectAt(1) as ASN1Integer).positiveValue
        return fixedWidth(r) + fixedWidth(s)
    }

    private fun fixedWidth(value: BigInteger): ByteArray {
        val bytes = value.toByteArray().let {
            if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it
        }
        return ByteArray(32 - bytes.size) + bytes
    }
}
