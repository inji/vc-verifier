package io.mosip.vercred.vcverifier.credentialverifier.verifier

import android.os.Build
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnsignedInteger
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ALG
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DIGEST_ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DIGEST_SALT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DS_CERT_EKU
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DS_CERT_VALIDITY
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUING_COUNTRY
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_ISSUING_JURISDICTION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VALUE_DIGESTS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING_ALG
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_DIGEST_ID_OUT_OF_RANGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DIGEST_ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUE_DATE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_ISSUER_SIGNED_ITEM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_MSO_ALG
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_ALG
import java.math.BigInteger
import io.mosip.vercred.vcverifier.exception.InvalidPropertyException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.BuildConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.lang.reflect.InvocationTargetException

class MsoMdocVerifierTest {
    val validMdoc =
        "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkB2TCCAdUwggF7oAMCAQICFBRDWWSBLltTWt65yytaZ01baoM9MAoGCCqGSM49BAMCMFkxCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTENMAsGA1UEBwwETW9jazENMAsGA1UECgwETW9jazENMAsGA1UECwwETU9jazENMAsGA1UEAwwETW9jazAeFw0yNDEwMjEwNzU2MTBaFw0yNTEwMjEwNzU2MTBaMFkxCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTENMAsGA1UEBwwETW9jazENMAsGA1UECgwETW9jazENMAsGA1UECwwETU9jazENMAsGA1UEAwwETW9jazBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABA8PMic1jzZYunhb2Ymq3eH2qEudb5rBnGMk1RAmFuLbPYBgFhDjdhK7j3ciE16-XfCFHnVEX8cANHw1_XjU2nejITAfMB0GA1UdDgQWBBQmaVJHKU-6Y7m6g6qolUJ3p94yhjAKBggqhkjOPQQDAgNIADBFAiEAwXQgNSUrhHIlPE1N24u5UCRwBTqYKKpJqBlC0niZRHgCIFryTL85LV-hab5RL4YiDpDeNOL6_YyiS-STfjrv-OL4WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggahyUDZzWwyVz1oYQSOSTOl3XfzVAAVi-ILLpwP3DMtUGWCBJiBVoqzuOj8ZRrOsV7DNFe0QBWplIKWMU3aILs8y6lwNYILzO8fswbC_wn7rQYO8eq91XotAltVllVzYTwyYHHWYIAVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjFUMDg6MTE6MTNaaXZhbGlkRnJvbcB0MjAyNC0xMC0yMVQwODoxMToxM1pqdmFsaWRVbnRpbMB0MjAyNS0xMC0yMVQwODoxMToxM1pYQBZJtQ6yPA--sITjOK29mGLGKeG2DEx3qDHQEw99esCHwUnPJtobUfLGHhfmM0nawMZai21LXq5ZEdInOkEDSNRqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYaqRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVleBsyMDI0LTEwLTIxVDA4OjExOjEzLjQ5NTQ3OFrYGFhrpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVleBsyMDI1LTEwLTIxVDA4OjExOjEzLjQ5NTQ3OFrYGFjBpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhqe2lzc3VlX2RhdGU9MjAyNC0xMC0yMVQwODoxMToxMy40OTU0NzhaLCB2ZWhpY2xlX2NhdGVnb3J5X2NvZGU9QSwgZXhwaXJ5X2RhdGU9MjAyNS0xMC0yMVQwODoxMToxMy40OTU0NzhafdgYWFekaGRpZ2VzdElEAWZyYW5kb21Q46GI__EQWetvvOYmVd-9b3FlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXJsZWxlbWVudFZhbHVlZDEyMzPYGFhVpGhkaWdlc3RJRARmcmFuZG9tUIO4lnDW2fm_Utg97twL9mJxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWJNS9gYWFikaGRpZ2VzdElEAGZyYW5kb21QBYNczBataC2MR4om9FAnmHFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZWoxOTk0LTExLTA22BhYVKRoZGlnZXN0SUQHZnJhbmRvbVBJWZtW3VOzNRpXK0Dyf3LTcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZkpvc2VwaNgYWFWkaGRpZ2VzdElEBWZyYW5kb21QfzR7XZl5Fiz6lZ0oMqRhlnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVmQWdhdGhh"

    @BeforeEach
    fun setUp() {
        mockkObject(BuildConfig)
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O
    }

    @AfterEach
    fun after() {
        clearAllMocks()
    }

    @Test
    @Disabled("Requires ISO-conformant DS certificates from inji-certify#1123 (mDL EKU 1.0.18013.5.1.2)")
    fun `should return true when credential is successfully verified`() {
        val inputs =
            listOf(
                "omppc3N1ZXJBdXRohEOhASahGCFZAxQwggMQMIIB-KADAgECAggGru5Xjrda-DANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9SRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMR8wHQYDVQQDDBZ3d3cuZXhhbXBsZS5jb20gKFJPT1QpMB4XDTI2MDcxMzA2MzY0NloXDTI5MDcxMjA2MzY0NlowgZsxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxQjBABgNVBAMMOXd3dy5leGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VDX1IxLUVDX1NFQ1AyNTZSMV9TSUdOKTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCxNsdJnJDCpzS-oiskMiAXKts0KfSq0bKAcAF9AIVcylo234k6c5ze6zd-LYUq4qZt2Epj0JtzVJzWtXJBmy5-jRTBDMBIGA1UdEwEB_wQIMAYBAf8CAQEwHQYDVR0OBBYEFNTUxJGN9cvnw0bkpOY7hXCOgEIgMA4GA1UdDwEB_wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAdCMKCVQqQFNuXfZVD2JrmGHMdqmBsyEITavF8uIjOUu39qaaXyhvLeCggP7PjXJ8Cu141VKCkj6XHtvHM5iqCQsAQpjgzp6Hi27sau_yKLOOKBz8E2G9N9-skn9UiVJqSeZLOl_gRcPhbxVndQp7FZ4cdct4r_kObVt-W-BTlDJWjz54bPVhInnFfLpv2KlSqASRBIpbasMehVaYR7E9Rq_Ya5Ms5A8MYzXzdLeBdSWJCIyxmHasTax6cVM5GdqpAOjbJF_7k7X4JHBEIiDrJ_O0p9zwpBWdAn_Kb-oCe3VQHzrmeCsp2uyNRvzEqJ5Yd5b26-V8C8yBj7P7Uaa-PlkCUNgYWQJLpmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB4GzIwMjYtMDctMjBUMDQ6NDc6NDIuNzE2OTA5Wml2YWxpZEZyb23AeBsyMDI2LTA3LTIwVDA0OjQ3OjQyLjcxNjkwOVpqdmFsaWRVbnRpbMB4GDIwMjgtMDctMjBUMDQ6NDc6NDIuNzE3Wmx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xpgBYILcu1K9SpiobtelCZX5_BHQrOJCCoaXtJCGX35eeFnQSAVggApvPGQYz3DLYRbetDpT0-31okQ5uzWRwzrff00yMD7oCWCD4d3HGgi-70QBlGoiU5nggSPzpSI5GkxXdsOyG4ArVLgNYIOQbLhdNqN_8kCZzqVswmMeQ6MtpvttlT16uBgWMKdFyBFgg_hMVI7VctilrrgdQPGCdIEL4VgkVVaEMEvKcIY_xJKUFWCAtv66ml2lD15WYUUzAS6gJYj1DALcrbw9xjFFrZkhUuG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmmAQICWCtlNjVnMnVDNmJCMEREZGZNRzhTYlZ2TDFNSWxSNENxcGRoUWE4YmZQUDNVAyYgASFYILQicKMUp8767SCHDrTO6yWjmAm-WIjudd3pRo_zI7myIlggPBprbay4iRPtNiVtbVob_u3AQxpRmqWQSup7zPyNuLlvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZYQBCVJ3YkZ1ETAuhULd1ZGTv6ONhH_NsP61FIfpe69uLWEBThcUiJq7y_KRMms9KVi7pYcU3WhiNlOUC6hSYrB_1qbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGG2BhYZaRmcmFuZG9tWBiq53HDBUk9X9igBaZDmBelpFQndR2-nl9oZGlnZXN0SUQAbGVsZW1lbnRWYWx1ZW0ke2ZhbWlseU5hbWV9cWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1l2BhYY6RmcmFuZG9tWBgvL1T9pXgeuDdhIpe9VL0dEFL8IXB5rkJoZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZWwke2dpdmVuTmFtZX1xZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWGOkZnJhbmRvbVgYMuPQgcDhX9FgtaLBg5aC2SmZpPPsyUYlaGRpZ2VzdElEAmxlbGVtZW50VmFsdWVsJHtiaXJ0aERhdGV9cWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGXYGFhepGZyYW5kb21YGG9QaSwv6jAPrlLBDqMcpymi-NiA9MEChGhkaWdlc3RJRANsZWxlbWVudFZhbHVlYklOcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWG2kZnJhbmRvbVgYKA4VkRJdH22UPLypb9bl72lXGuja-E2xaGRpZ2VzdElEBGxlbGVtZW50VmFsdWVxJHtkb2N1bWVudE51bWJlcn1xZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVy2BhYYKRmcmFuZG9tWBhb4Thi6agJuh0LXOhY3pRuffpIZgeZq9xoZGlnZXN0SUQFbGVsZW1lbnRWYWx1ZWske3BvcnRyYWl0fXFlbGVtZW50SWRlbnRpZmllcmhwb3J0cmFpdA",
                "omppc3N1ZXJBdXRohEOhASahGCFZAxQwggMQMIIB-KADAgECAggGru5Xjrda-DANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9SRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMR8wHQYDVQQDDBZ3d3cuZXhhbXBsZS5jb20gKFJPT1QpMB4XDTI2MDcxMzA2MzY0NloXDTI5MDcxMjA2MzY0NlowgZsxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxQjBABgNVBAMMOXd3dy5leGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VDX1IxLUVDX1NFQ1AyNTZSMV9TSUdOKTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCxNsdJnJDCpzS-oiskMiAXKts0KfSq0bKAcAF9AIVcylo234k6c5ze6zd-LYUq4qZt2Epj0JtzVJzWtXJBmy5-jRTBDMBIGA1UdEwEB_wQIMAYBAf8CAQEwHQYDVR0OBBYEFNTUxJGN9cvnw0bkpOY7hXCOgEIgMA4GA1UdDwEB_wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAdCMKCVQqQFNuXfZVD2JrmGHMdqmBsyEITavF8uIjOUu39qaaXyhvLeCggP7PjXJ8Cu141VKCkj6XHtvHM5iqCQsAQpjgzp6Hi27sau_yKLOOKBz8E2G9N9-skn9UiVJqSeZLOl_gRcPhbxVndQp7FZ4cdct4r_kObVt-W-BTlDJWjz54bPVhInnFfLpv2KlSqASRBIpbasMehVaYR7E9Rq_Ya5Ms5A8MYzXzdLeBdSWJCIyxmHasTax6cVM5GdqpAOjbJF_7k7X4JHBEIiDrJ_O0p9zwpBWdAn_Kb-oCe3VQHzrmeCsp2uyNRvzEqJ5Yd5b26-V8C8yBj7P7Uaa-PlkCHNgYWQIXpmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB4GDIwMjYtMDctMjBUMTI6NDA6NDAuMjM2Wml2YWxpZEZyb23AeBgyMDI2LTA3LTIwVDEyOjQwOjQwLjIzNlpqdmFsaWRVbnRpbMB4GDIwMjgtMDctMjBUMTI6NDA6NDAuMjM2Wmx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xpgBYIIPzsBxULYNSOraa4mUk1RYhw2znXxLcXiNw8liLr6WwAVggQpWQTqda_zQ2YnoYLife0Rs8UfYheMNVZiQyKaW6ONICWCBBZTssWASAQkym-mpxiFEhwBXnuXl1WiiICQ0jOkPg1gNYIPx6Pq-3mZD9Xh4YU3YV6n7spjjpAq9Jb0JJr6PqNNW0BFggvt5vItN3MzvL2aCr4mbNW5v5ubzUhIXrhQj09PqbHCgFWCAtnG8OZaKTOLa7KKBAFSzp8XNVIRHSFEzBKC7VF401fm1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmlAQIDJiABIVgg2sT92lxQIpBZlrgazvdU4-ytsXMWjSx0D1trnyGfaqkiWCD7E3cPgXcs5aVwz32XcqfcqfFa2x3vDE7l74ol-G42Fm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAlK_FV4ybsdj0Ji3eJ38nxvyvvJ971F9sBa1eDfppFmSzAEL4fU7xKzA2pxuI32gRK27e1ZlRYIr6G25hqrCDempuYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYbYGFhlpGZyYW5kb21YGA-mGSSAZNU7EyBOSqF3E_FuYOcpQ_ExTGhkaWdlc3RJRABsZWxlbWVudFZhbHVlbSR7ZmFtaWx5TmFtZX1xZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhjpGZyYW5kb21YGDVFJC-NpLN_YsqnLc4YEvC-ewunAUhxcWhkaWdlc3RJRAFsZWxlbWVudFZhbHVlbCR7Z2l2ZW5OYW1lfXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYY6RmcmFuZG9tWBhBUCwuKcgXWVLf7PiUJox62VF2rSJDl4loZGlnZXN0SUQCbGVsZW1lbnRWYWx1ZWwke2JpcnRoRGF0ZX1xZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWF6kZnJhbmRvbVgYEBDCc9pvTh-aOSF6iqo483mGtrlCo519aGRpZ2VzdElEA2xlbGVtZW50VmFsdWViSU5xZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ52BhYbaRmcmFuZG9tWBiRDNgazEZVT04zy8lNiQfAmaHp2KHfKnloZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZXEke2RvY3VtZW50TnVtYmVyfXFlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXLYGFhgpGZyYW5kb21YGEz2PD-m2YgC9nBaHW9BBtrOCbrJtwLGrGhkaWdlc3RJRAVsZWxlbWVudFZhbHVlayR7cG9ydHJhaXR9cWVsZW1lbnRJZGVudGlmaWVyaHBvcnRyYWl0"
            )
        val verifier = MsoMdocVerifier()
        inputs.forEach { input ->
            val isVerified = verifier.verify(
                input
            )
            assertTrue(isVerified)
        }
    }

    @Test
    fun `should fail current fixtures on missing mDL DS EKU until certify provides conformant certs`() {
        val exception = assertThrows(ValidationException::class.java) {
            MsoMdocVerifier().verify(
                "omppc3N1ZXJBdXRohEOhASahGCFZAxQwggMQMIIB-KADAgECAggGru5Xjrda-DANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEjAQBgNVBAcMCUJBTkdBTE9SRTEOMAwGA1UECgwFSUlJVEIxFzAVBgNVBAsMDkVYQU1QTEUtQ0VOVEVSMR8wHQYDVQQDDBZ3d3cuZXhhbXBsZS5jb20gKFJPT1QpMB4XDTI2MDcxMzA2MzY0NloXDTI5MDcxMjA2MzY0NlowgZsxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxQjBABgNVBAMMOXd3dy5leGFtcGxlLmNvbSAoQ0VSVElGWV9WQ19TSUdOX0VDX1IxLUVDX1NFQ1AyNTZSMV9TSUdOKTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCxNsdJnJDCpzS-oiskMiAXKts0KfSq0bKAcAF9AIVcylo234k6c5ze6zd-LYUq4qZt2Epj0JtzVJzWtXJBmy5-jRTBDMBIGA1UdEwEB_wQIMAYBAf8CAQEwHQYDVR0OBBYEFNTUxJGN9cvnw0bkpOY7hXCOgEIgMA4GA1UdDwEB_wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEAdCMKCVQqQFNuXfZVD2JrmGHMdqmBsyEITavF8uIjOUu39qaaXyhvLeCggP7PjXJ8Cu141VKCkj6XHtvHM5iqCQsAQpjgzp6Hi27sau_yKLOOKBz8E2G9N9-skn9UiVJqSeZLOl_gRcPhbxVndQp7FZ4cdct4r_kObVt-W-BTlDJWjz54bPVhInnFfLpv2KlSqASRBIpbasMehVaYR7E9Rq_Ya5Ms5A8MYzXzdLeBdSWJCIyxmHasTax6cVM5GdqpAOjbJF_7k7X4JHBEIiDrJ_O0p9zwpBWdAn_Kb-oCe3VQHzrmeCsp2uyNRvzEqJ5Yd5b26-V8C8yBj7P7Uaa-PlkCUNgYWQJLpmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB4GzIwMjYtMDctMjBUMDQ6NDc6NDIuNzE2OTA5Wml2YWxpZEZyb23AeBsyMDI2LTA3LTIwVDA0OjQ3OjQyLjcxNjkwOVpqdmFsaWRVbnRpbMB4GDIwMjgtMDctMjBUMDQ6NDc6NDIuNzE3Wmx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xpgBYILcu1K9SpiobtelCZX5_BHQrOJCCoaXtJCGX35eeFnQSAVggApvPGQYz3DLYRbetDpT0-31okQ5uzWRwzrff00yMD7oCWCD4d3HGgi-70QBlGoiU5nggSPzpSI5GkxXdsOyG4ArVLgNYIOQbLhdNqN_8kCZzqVswmMeQ6MtpvttlT16uBgWMKdFyBFgg_hMVI7VctilrrgdQPGCdIEL4VgkVVaEMEvKcIY_xJKUFWCAtv66ml2lD15WYUUzAS6gJYj1DALcrbw9xjFFrZkhUuG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmmAQICWCtlNjVnMnVDNmJCMEREZGZNRzhTYlZ2TDFNSWxSNENxcGRoUWE4YmZQUDNVAyYgASFYILQicKMUp8767SCHDrTO6yWjmAm-WIjudd3pRo_zI7myIlggPBprbay4iRPtNiVtbVob_u3AQxpRmqWQSup7zPyNuLlvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZYQBCVJ3YkZ1ETAuhULd1ZGTv6ONhH_NsP61FIfpe69uLWEBThcUiJq7y_KRMms9KVi7pYcU3WhiNlOUC6hSYrB_1qbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGG2BhYZaRmcmFuZG9tWBiq53HDBUk9X9igBaZDmBelpFQndR2-nl9oZGlnZXN0SUQAbGVsZW1lbnRWYWx1ZW0ke2ZhbWlseU5hbWV9cWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1l2BhYY6RmcmFuZG9tWBgvL1T9pXgeuDdhIpe9VL0dEFL8IXB5rkJoZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZWwke2dpdmVuTmFtZX1xZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWGOkZnJhbmRvbVgYMuPQgcDhX9FgtaLBg5aC2SmZpPPsyUYlaGRpZ2VzdElEAmxlbGVtZW50VmFsdWVsJHtiaXJ0aERhdGV9cWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGXYGFhepGZyYW5kb21YGG9QaSwv6jAPrlLBDqMcpymi-NiA9MEChGhkaWdlc3RJRANsZWxlbWVudFZhbHVlYklOcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWG2kZnJhbmRvbVgYKA4VkRJdH22UPLypb9bl72lXGuja-E2xaGRpZ2VzdElEBGxlbGVtZW50VmFsdWVxJHtkb2N1bWVudE51bWJlcn1xZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVy2BhYYKRmcmFuZG9tWBhb4Thi6agJuh0LXOhY3pRuffpIZgeZq9xoZGlnZXN0SUQFbGVsZW1lbnRWYWx1ZWske3BvcnRyYWl0fXFlbGVtZW50SWRlbnRpZmllcmhwb3J0cmFpdA"
            )
        }
        assertEquals(ERROR_CODE_INVALID_DS_CERT_EKU, exception.errorCode)
    }

    @Test
    @Disabled("Requires ISO-conformant DS certificates from inji-certify#1123")
    fun `should return true when legacy issuerSigned mDoc mso payload is not tagged with 24`() {
        // Legacy docType/issuerSigned credentials are exempt from the tag-24 requirement,
        // which only applies to the latest OpenID4VCI 1.0 structure.
        val isVerified = MsoMdocVerifier().verify(
            "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkDFDCCAxAwggH4oAMCAQICCFQD_uck0G08MA0GCSqGSIb3DQEBCwUAMHgxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEXMBUGA1UECwwORVhBTVBMRS1DRU5URVIxHzAdBgNVBAMMFnd3dy5leGFtcGxlLmNvbSAoUk9PVCkwHhcNMjYwMTE5MTM1MDQ2WhcNMjkwMTE4MTM1MDQ2WjCBmzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoMBUlJSVRCMRcwFQYDVQQLDA5FWEFNUExFLUNFTlRFUjFCMEAGA1UEAww5d3d3LmV4YW1wbGUuY29tIChDRVJUSUZZX1ZDX1NJR05fRUNfUjEtRUNfU0VDUDI1NlIxX1NJR04pMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3Y_vIMN8LpOXj7ldttDl2PQf39EvIRAhOXFyvnFwctdU9rxY31WHRsJdMGJQRuc4wLPz6Ii3eHdSLQph8226W6NFMEMwEgYDVR0TAQH_BAgwBgEB_wIBATAdBgNVHQ4EFgQUE8etKEgc7LmfW_WgkcB6Dtc-O9owDgYDVR0PAQH_BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQBUp2oWwpcpCNYd_GgORojXV1L7cYO0YVG-bmvfGt5QqmXZzmHd79tTJF4PAzTRgz_zPyMU9UBaVzCyi3sj8C9mFnB0hXDkbk3dw7ZVxHp7LFpxjl99peaKfcz39Dczk4LoCn7ZwuS-qhc8gsDFzxX42dgXp1BZUzzj17Syzs8lpDAXxieaj0hjfr7neq07pODyDMAZ3wy7SVPJOhuGHRada3UFgS3uOJH6zhOTGn-IbTvYZ-tkzkgKh6xcG_PBipBh5vIciSvcfvHyZ2UANVY_kseRTsuiZv0KXvgISOv3bvqqQyCDy_FD-_yuqdyT9YPuj_Cr2UWCn_aoZmJoru3qWQIWpmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-iaXZhbGlkRnJvbXgYMjAyNi0wNy0xNVQwNjo0OToyMi45MDNaanZhbGlkVW50aWx4GDIwMjgtMDctMTVUMDY6NDk6MjIuOTA0Wmx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xpwBYIHrRv_fnGSHyqGeIW2I-NbZFiJ06NCIH_3iceOkWCVG1AVgg4UkMtcuCtQf-F0750zy2UWAXSW4GBXlC9d1-gantrT8CWCC4JSaKgrcH_RXdlK4d3ZuSL9_ECtTQ_0R8ltUD_cvaYQNYILwBk-WC4x9dwH12ZVQ66b-42xBXrM2rSRr79q9IM6ygBFgg2U-S07CL6bxsotMyZfffhj-d-XbuxBhDtwS51ZWC0zYFWCCZsZufSbOAF1NIpEhA279eU_mOkFEBWoePusO1zkH56gZYIPGxEvjbKhkxEUsppn__AxNop-R8mDs_Y1AKx3HhliqIbWRldmljZUtleUluZm-haWRldmljZUtleaUBAgMmIAEhWCDaxP3aXFAikFmWuBrO91Tj7K2xcxaNLHQPW2ufIZ9qqSJYIPsTdw-BdyzlpXDPfZdyp9yp8VrbHe8MTuXviiX4bjYWb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2WECfJH_Dh71RiMaceuM5Xm98NLLdhPQo635ZRRiqXXM6oUFzDqkGo94famCO8jegdtWuhLaqanUJJMz7xGd_5GUEam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xh9gYWF2kZnJhbmRvbVgYyA4LdT-w3uprgtB_lMM-hBWpjZ3VzW1CaGRpZ2VzdElEAGxlbGVtZW50VmFsdWVlVXNlcjFxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhcpGZyYW5kb21YGL6jSd2nyx2np8RZVZwRwfNKBHeyGtyl62hkaWdlc3RJRAFsZWxlbWVudFZhbHVlZVRlc3QxcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWXYGFhkpGZyYW5kb21YGG1meiknZB0H24gJ1MjCRZq3pGkzdhg8l2hkaWdlc3RJRAJsZWxlbWVudFZhbHVl2QPsajE5OTMtMDQtMTVxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWF6kZnJhbmRvbVgYDUTmWgzbQFH5GoHEue0GWV7sKwcacpaPaGRpZ2VzdElEA2xlbGVtZW50VmFsdWViSU5xZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ52BhYaKRmcmFuZG9tWBh1Sc7RYZ2utrPfz86QhMlqVQkj-CA_O8toZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZWxETDIwNDIzNTEzMDdxZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVy2BhY4KRmcmFuZG9tWBjqUT9vI8EfIFIRl8s4biqPCGxJKFiJsEdoZGlnZXN0SUQFbGVsZW1lbnRWYWx1ZXiKZGF0YTppbWFnZS9wbmc7YmFzZTY0LGlWQk9SdzBLR2dvQUFBQU5TVWhFVWdBQUFCd0FBQUFGQ0FZQUFBQlcxSXpIQUFBQUhrbEVRVlFva1dOZ0dQYUFrWkh4UHlNajQzOXNZclNRbzUxUEJnc0FBTGEwRUNGMzBKU2RBQUFBQUVsRlRrU3VRbUNDcWVsZW1lbnRJZGVudGlmaWVyaHBvcnRyYWl02BhYjqRmcmFuZG9tWBi5MVz5iRw3KK8SXGKGcp_DUH4VKu-lf8RoZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZYGiaWlzc3VlRGF0ZdkD7GoyMDIzLTAxLTE1c3ZlaGljbGVDYXRlZ29yeUNvZGVhQnFlbGVtZW50SWRlbnRpZmllcnJkcml2aW5nX3ByaXZpbGVnZXM"
        )

        assertTrue(isVerified)
    }

    @Test
    fun `should throw exception when no certificate is present`() {
        val verificationException = assertThrows(SignatureVerificationException::class.java) {
            MsoMdocVerifier().verify(
                "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqBZAlHYGFkCTKZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZnZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMagCWCBIsV2f_hPck41lG5I2ghsShngnyzWaB0qG5C_C99LqIQZYICsFlGVr6z7d3cvd2KpbFbExFwEUDcj_wS1StNhFHdF1A1ggVa2R-KGknVkwLmU4hf6u-38Bu7nTy_CTAjlnItAy7_ABWCBOOOe-kKOSAGTvlWG4T0yvl_u9yiAnhHYq4W7seDxozgRYIGAWclozHIhXlMDIi9CRm5Ast-Wml1G2kCujw0kbByGvAFggEQeEohw1_RnCBxM4W8iqh_Jzwb11kbjYiLKdmG2eHwEHWCCbMVkB7eOe7UISBHVtzCVFSj7juwryBNkxDfhrPNck9wVYID4imaKvIR_SiBGGPIIWfrds6O9rXAjbB8ktNS71LwI_bWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggnww0vMC-Sx0-LgD0Q7arJDKKeZzN8He7i6cfoozCGHUiWCBaqQUX2LgGwRC_OeJo2PR3fqDbKdUW4iSAcHThp_ttGWx2YWxpZGl0eUluZm-jZnNpZ25lZMB0MjAyNC0xMC0xN1QxMDoxNDo0MVppdmFsaWRGcm9twHQyMDI0LTEwLTE3VDEwOjE0OjQxWmp2YWxpZFVudGlswHQyMDI0LTExLTE5VDE4OjMwOjAwWlhAMMc06E9hVOLVidx0ut4I4SYSZKk8IVeNuQ4JDdCnYjb7gQhZiOSN6rkj6xUvAyIDmI7xjGt0v8KRw3ZSs5bZOmpuYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYjYGFhVpGhkaWdlc3RJRAJmcmFuZG9tUG2FLLW-amGqmgxhF71nQ-dxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVsZWxlbWVudFZhbHVlZkFnYXRoYdgYWFSkaGRpZ2VzdElEBmZyYW5kb21Q3JeFc5mOaF6IXLNh-GyXRnFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1lbGVsZW1lbnRWYWx1ZWZKb3NlcGjYGFiBpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZWxlbGVtZW50VmFsdWVYMqztAAVzcgANamF2YS50aW1lLlNlcpVdhLobIkiyDAAAeHB3DQIAAAAAOYTBgAAAAAB42BhYaqRoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVleBsyMDI0LTEwLTE3VDEwOjE0OjQxLjkzOTU0OFrYGFhrpGhkaWdlc3RJRARmcmFuZG9tUIO4lnDW2fm_Utg97twL9mJxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVleBsyMDI0LTEwLTI5VDEwOjE0OjQxLjkzOTU0OFrYGFhZpGhkaWdlc3RJRABmcmFuZG9tUAWDXMwWrWgtjEeKJvRQJ5hxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWZJc2xhbmTYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVybGVsZW1lbnRWYWx1ZRh72BhZAVGkaGRpZ2VzdElEBWZyYW5kb21QfzR7XZl5Fiz6lZ0oMqRhlnFlbGVtZW50SWRlbnRpZmllcnJkcml2aW5nX3ByaXZpbGVnZXNsZWxlbWVudFZhbHVlWPqs7QAFc3IAF2phdmEudXRpbC5MaW5rZWRIYXNoTWFwNMBOXBBswPsCAAFaAAthY2Nlc3NPcmRlcnhyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAZ3CAAAAAgAAAADdAAVdmVoaWNsZV9jYXRlZ29yeV9jb2RldAABQXQACmlzc3VlX2RhdGV0ABsyMDI0LTEwLTE3VDEwOjE0OjQxLjkzOTU0OFp0AAtleHBpcnlfZGF0ZXQAGzIwMjQtMTAtMjlUMTA6MTQ6NDEuOTM5NTQ4WngA"
            )
        }

        assertEquals("Error while doing COSE signature verification - certificate chain is empty",verificationException.message)
    }

    @Test
    fun `should throw ERR_INVALID_DS_CERT_VALIDITY when fixture DS certificate is expired`() {
        // Public verify() hits DS validity before signature/digest checks on this expired fixture.
        val verificationException = assertThrows(ValidationException::class.java) {
            MsoMdocVerifier().verify(
                "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkBxDCCAcAwggFloAMCAQICFH6lICTsAhkMivItOT9v6JeZubwmMAoGCCqGSM49BAMCME4xCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTERMA8GA1UEBwwITW9ja0NpdHkxDTALBgNVBAoMBE1vY2sxDTALBgNVBAsMBE1vY2swHhcNMjQxMDIyMDcwMjUwWhcNMjUxMDIyMDcwMjUwWjBOMQswCQYDVQQGEwJNSzEOMAwGA1UECAwFTUstS0ExETAPBgNVBAcMCE1vY2tDaXR5MQ0wCwYDVQQKDARNb2NrMQ0wCwYDVQQLDARNb2NrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjtRcOXgIyR_xqGB-M6d0qkrjQWOBGGdlPgfIfb2xW0egZAVEz_55IXCofWaprRGxX7qQTlNAZyByniay2jzhR6MhMB8wHQYDVR0OBBYEFNqAHypQYcwWoeUfmMv4SbztomFvMAoGCCqGSM49BAMCA0kAMEYCIQDsgsz9wCa56ukpfyvq9371b5GhkSZb38G7xFofWgFtJwIhAKxACllIOtcleKETDFGa3araADjKd2isahQtXZwQmPr1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggkeGezsuDJ_tDOu3Sc3wExf5jwtoGy8uqqRNp6tdAHzQGWCDhz5PP_T4u8YBXfDWb1_11Ov1OumpPaL10VoLXWL10mwNYIKiWCZi4gP_dX6r5_4QZISZzdi8_LO0BYcvnV3QPeac_AVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjJUMDc6MDM6MTBaaXZhbGlkRnJvbcB0MjAyNC0xMC0yMlQwNzowMzoxMFpqdmFsaWRVbnRpbMB0MjAyNS0xMC0yMlQwNzowMzoxMFpYP3dUUFIy1nVZUdzgui9HxMGhQuEAOKD-F2XNL-PGG4lo3J51ri7h3j0ffmFsdrLi3OWPLO-yvh9twGM6BN8O02puYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYjYGFhqpGhkaWdlc3RJRAJmcmFuZG9tUG2FLLW-amGqmgxhF71nQ-dxZWxlbWVudElkZW50aWZpZXJqaXNzdWVfZGF0ZWxlbGVtZW50VmFsdWV4GzIwMjQtMTAtMjJUMDc6MDM6MTAuNjM0OTE4WtgYWGukaGRpZ2VzdElEBmZyYW5kb21Q3JeFc5mOaF6IXLNh-GyXRnFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZWxlbGVtZW50VmFsdWV4GzIwMjUtMTAtMjJUMDc6MDM6MTAuNjM0OTE4WtgYWMGkaGRpZ2VzdElEA2ZyYW5kb21QIL6_sBEAsnZUVxjDD0BsyHFlbGVtZW50SWRlbnRpZmllcnJkcml2aW5nX3ByaXZpbGVnZXNsZWxlbWVudFZhbHVleGp7aXNzdWVfZGF0ZT0yMDI0LTEwLTIyVDA3OjAzOjEwLjYzNDkxOFosIHZlaGljbGVfY2F0ZWdvcnlfY29kZT1BLCBleHBpcnlfZGF0ZT0yMDI1LTEwLTIyVDA3OjAzOjEwLjYzNDkxOFp92BhYV6RoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVkMTIzM9gYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYk1L2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE"
            )
        }

        assertEquals(ERROR_CODE_INVALID_DS_CERT_VALIDITY, verificationException.errorCode)
    }

    @Test
    fun `should throw ERR_INVALID_VALUE_DIGESTS when received digest does not match MSO`() {
        val issuerSignedItem = CborMap().apply {
            put(UnicodeString("digestID"), UnsignedInteger(1))
            put(UnicodeString("random"), ByteString(ByteArray(16)))
            put(UnicodeString("elementIdentifier"), UnicodeString("family_name"))
            put(UnicodeString("elementValue"), UnicodeString("Doe"))
        }
        val itemBytes = ByteArrayOutputStream().also { CborEncoder(it).encode(issuerSignedItem) }.toByteArray()
        val taggedItem = ByteString(itemBytes).apply { setTag(24) }
        val encodedItem = ByteArrayOutputStream().also { CborEncoder(it).encode(taggedItem) }.toByteArray()
        val namespace = UnicodeString("org.iso.18013.5.1")
        val namespaces = CborMap().apply {
            put(namespace, CborArray().apply { add(taggedItem) })
        }
        val encodedItems = mapOf("org.iso.18013.5.1" to listOf(encodedItem))
        val mso = CborMap().apply {
            put(UnicodeString("digestAlgorithm"), UnicodeString("SHA-256"))
            put(
                UnicodeString("valueDigests"),
                CborMap().apply {
                    put(
                        namespace,
                        CborMap().apply {
                            put(UnsignedInteger(1), ByteString(ByteArray(32) { 0x11 }))
                        }
                    )
                }
            )
        }

        val validationException = invokeVerifyValueDigests(namespaces, encodedItems, mso)
        assertEquals(ERROR_CODE_INVALID_VALUE_DIGESTS, validationException.errorCode)
    }

    @Test
    fun `should throw exception when docType is not available in the credential`() {
        val verificationException = assertThrows(ValidationException::class.java) {
            MsoMdocVerifier().verify(
                "oWxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkBxDCCAcAwggFloAMCAQICFH6lICTsAhkMivItOT9v6JeZubwmMAoGCCqGSM49BAMCME4xCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTERMA8GA1UEBwwITW9ja0NpdHkxDTALBgNVBAoMBE1vY2sxDTALBgNVBAsMBE1vY2swHhcNMjQxMDIyMDcwMjUwWhcNMjUxMDIyMDcwMjUwWjBOMQswCQYDVQQGEwJNSzEOMAwGA1UECAwFTUstS0ExETAPBgNVBAcMCE1vY2tDaXR5MQ0wCwYDVQQKDARNb2NrMQ0wCwYDVQQLDARNb2NrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjtRcOXgIyR_xqGB-M6d0qkrjQWOBGGdlPgfIfb2xW0egZAVEz_55IXCofWaprRGxX7qQTlNAZyByniay2jzhR6MhMB8wHQYDVR0OBBYEFNqAHypQYcwWoeUfmMv4SbztomFvMAoGCCqGSM49BAMCA0kAMEYCIQDsgsz9wCa56ukpfyvq9371b5GhkSZb38G7xFofWgFtJwIhAKxACllIOtcleKETDFGa3araADjKd2isahQtXZwQmPr1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggkeGezsuDJ_tDOu3Sc3wExf5jwtoGy8uqqRNp6tdAHzQGWCDhz5PP_T4u8YBXfDWb1_11Ov1OumpPaL10VoLXWL10mwNYIKiWCZi4gP_dX6r5_4QZISZzdi8_LO0BYcvnV3QPeac_AVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjJUMDc6MDM6MTBaaXZhbGlkRnJvbcB0MjAyNC0xMC0yMlQwNzowMzoxMFpqdmFsaWRVbnRpbMB0MjAyNS0xMC0yMlQwNzowMzoxMFpYQHdUUFIy1nVZUdYc4LovR8TBoULhADig_hdlzS_jxhuJaNyeda4u4d49H35hbHay4tzljyzvsr4fbcBjOgTfDtNqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYaqRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVleBsyMDI0LTEwLTIyVDA3OjAzOjEwLjYzNDkxOFrYGFhrpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVleBsyMDI1LTEwLTIyVDA3OjAzOjEwLjYzNDkxOFrYGFjBpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhqe2lzc3VlX2RhdGU9MjAyNC0xMC0yMlQwNzowMzoxMC42MzQ5MThaLCB2ZWhpY2xlX2NhdGVnb3J5X2NvZGU9QSwgZXhwaXJ5X2RhdGU9MjAyNS0xMC0yMlQwNzowMzoxMC42MzQ5MThafdgYWFekaGRpZ2VzdElEAWZyYW5kb21Q46GI__EQWetvvOYmVd-9b3FlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXJsZWxlbWVudFZhbHVlZDEyMzPYGFhVpGhkaWdlc3RJRARmcmFuZG9tUIO4lnDW2fm_Utg97twL9mJxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWJNS9gYWFikaGRpZ2VzdElEAGZyYW5kb21QBYNczBataC2MR4om9FAnmHFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZWoxOTk0LTExLTA22BhYVKRoZGlnZXN0SUQHZnJhbmRvbVBJWZtW3VOzNRpXK0Dyf3LTcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZkpvc2VwaNgYWFWkaGRpZ2VzdElEBWZyYW5kb21QfzR7XZl5Fiz6lZ0oMqRhlnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVmQWdhdGhh"
            )
        }

        assertEquals(ERROR_CODE_INVALID_DS_CERT_VALIDITY, verificationException.errorCode)
    }

    @Test
    fun `should throw exception when docType is not matching with the docType in MSO`() {
        val verificationException = assertThrows(ValidationException::class.java) {
            MsoMdocVerifier().verify(
                "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS41Lm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkBxDCCAcAwggFloAMCAQICFH6lICTsAhkMivItOT9v6JeZubwmMAoGCCqGSM49BAMCME4xCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTERMA8GA1UEBwwITW9ja0NpdHkxDTALBgNVBAoMBE1vY2sxDTALBgNVBAsMBE1vY2swHhcNMjQxMDIyMDcwMjUwWhcNMjUxMDIyMDcwMjUwWjBOMQswCQYDVQQGEwJNSzEOMAwGA1UECAwFTUstS0ExETAPBgNVBAcMCE1vY2tDaXR5MQ0wCwYDVQQKDARNb2NrMQ0wCwYDVQQLDARNb2NrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjtRcOXgIyR_xqGB-M6d0qkrjQWOBGGdlPgfIfb2xW0egZAVEz_55IXCofWaprRGxX7qQTlNAZyByniay2jzhR6MhMB8wHQYDVR0OBBYEFNqAHypQYcwWoeUfmMv4SbztomFvMAoGCCqGSM49BAMCA0kAMEYCIQDsgsz9wCa56ukpfyvq9371b5GhkSZb38G7xFofWgFtJwIhAKxACllIOtcleKETDFGa3araADjKd2isahQtXZwQmPr1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggkeGezsuDJ_tDOu3Sc3wExf5jwtoGy8uqqRNp6tdAHzQGWCDhz5PP_T4u8YBXfDWb1_11Ov1OumpPaL10VoLXWL10mwNYIKiWCZi4gP_dX6r5_4QZISZzdi8_LO0BYcvnV3QPeac_AVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjJUMDc6MDM6MTBaaXZhbGlkRnJvbcB0MjAyNC0xMC0yMlQwNzowMzoxMFpqdmFsaWRVbnRpbMB0MjAyNS0xMC0yMlQwNzowMzoxMFpYQHdUUFIy1nVZUdYc4LovR8TBoULhADig_hdlzS_jxhuJaNyeda4u4d49H35hbHay4tzljyzvsr4fbcBjOgTfDtNqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYaqRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVleBsyMDI0LTEwLTIyVDA3OjAzOjEwLjYzNDkxOFrYGFhrpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVleBsyMDI1LTEwLTIyVDA3OjAzOjEwLjYzNDkxOFrYGFjBpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhqe2lzc3VlX2RhdGU9MjAyNC0xMC0yMlQwNzowMzoxMC42MzQ5MThaLCB2ZWhpY2xlX2NhdGVnb3J5X2NvZGU9QSwgZXhwaXJ5X2RhdGU9MjAyNS0xMC0yMlQwNzowMzoxMC42MzQ5MThafdgYWFekaGRpZ2VzdElEAWZyYW5kb21Q46GI__EQWetvvOYmVd-9b3FlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXJsZWxlbWVudFZhbHVlZDEyMzPYGFhVpGhkaWdlc3RJRARmcmFuZG9tUIO4lnDW2fm_Utg97twL9mJxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWJNS9gYWFikaGRpZ2VzdElEAGZyYW5kb21QBYNczBataC2MR4om9FAnmHFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZWoxOTk0LTExLTA22BhYVKRoZGlnZXN0SUQHZnJhbmRvbVBJWZtW3VOzNRpXK0Dyf3LTcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZkpvc2VwaNgYWFWkaGRpZ2VzdElEBWZyYW5kb21QfzR7XZl5Fiz6lZ0oMqRhlnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVmQWdhdGhh"
            )
        }

        assertEquals(ERROR_CODE_INVALID_DS_CERT_VALIDITY, verificationException.errorCode)
    }

    @Test
    fun `should resolve docType from a documents-wrapped legacy structure`() {
        // "documents"-wrapped legacy credentials keep docType nested inside documents[0], not at the root
        val mso = CborMap().apply { put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL")) }
        val document = CborMap().apply { put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL")) }
        val decodedCredential = CborMap().apply {
            put(UnicodeString("documents"), CborArray().apply { add(document) })
        }

        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod(
            "verifyDocType", CborMap::class.java, CborMap::class.java, Boolean::class.java
        )
        method.isAccessible = true

        val result = method.invoke(verifier, decodedCredential, mso, false) as Boolean

        assertTrue(result)
    }

    @Test
    fun `should throw when docType in documents-wrapped legacy structure mismatches the MSO docType`() {
        val mso = CborMap().apply { put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL")) }
        val document = CborMap().apply { put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.5.mDL")) }
        val decodedCredential = CborMap().apply {
            put(UnicodeString("documents"), CborArray().apply { add(document) })
        }

        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod(
            "verifyDocType", CborMap::class.java, CborMap::class.java, Boolean::class.java
        )
        method.isAccessible = true

        val invocationException = assertThrows(java.lang.reflect.InvocationTargetException::class.java) {
            method.invoke(verifier, decodedCredential, mso, false)
        }

        assertTrue(invocationException.targetException is InvalidPropertyException)
        assertEquals("Property mismatch with docType in the credential", invocationException.targetException.message)
    }

    @Test
    fun `should throw ERR_INVALID_ISSUING_COUNTRY when claim country mismatches DS C`() {
        val issuerSignedItem = CborMap().apply {
            put(UnicodeString("digestID"), UnsignedInteger(1))
            put(UnicodeString("random"), ByteString(ByteArray(16)))
            put(UnicodeString("elementIdentifier"), UnicodeString("issuing_country"))
            put(UnicodeString("elementValue"), UnicodeString("SA"))
        }
        val itemBytes = ByteArrayOutputStream().also { CborEncoder(it).encode(issuerSignedItem) }.toByteArray()
        val namespaces = CborMap().apply {
            put(
                UnicodeString("org.iso.18013.5.1"),
                CborArray().apply { add(ByteString(itemBytes)) }
            )
        }
        val certificate = io.mockk.mockk<java.security.cert.X509Certificate>()
        every { certificate.subjectX500Principal } returns javax.security.auth.x500.X500Principal(
            "CN=Doe\\, Esq,C=IN"
        )

        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod(
            "verifyCountryName",
            java.security.cert.X509Certificate::class.java,
            CborMap::class.java
        )
        method.isAccessible = true
        val invocationException = assertThrows(InvocationTargetException::class.java) {
            method.invoke(verifier, certificate, namespaces)
        }
        val validationException = invocationException.targetException as ValidationException
        assertEquals(ERROR_CODE_INVALID_ISSUING_COUNTRY, validationException.errorCode)
    }

    @Test
    fun `should throw ERR_INVALID_ISSUING_JURISDICTION when claim state mismatches DS ST`() {
        val issuerSignedItem = CborMap().apply {
            put(UnicodeString("digestID"), UnsignedInteger(1))
            put(UnicodeString("random"), ByteString(ByteArray(16)))
            put(UnicodeString("elementIdentifier"), UnicodeString("issuing_jurisdiction"))
            put(UnicodeString("elementValue"), UnicodeString("KA"))
        }
        val itemBytes = ByteArrayOutputStream().also { CborEncoder(it).encode(issuerSignedItem) }.toByteArray()
        val namespaces = CborMap().apply {
            put(
                UnicodeString("org.iso.18013.5.1"),
                CborArray().apply { add(ByteString(itemBytes)) }
            )
        }
        val certificate = io.mockk.mockk<java.security.cert.X509Certificate>()
        every { certificate.subjectX500Principal } returns javax.security.auth.x500.X500Principal(
            "C=IN,ST=MH,CN=Mock DS"
        )

        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod(
            "verifyIssuingJurisdiction",
            java.security.cert.X509Certificate::class.java,
            CborMap::class.java
        )
        method.isAccessible = true
        val invocationException = assertThrows(InvocationTargetException::class.java) {
            method.invoke(verifier, certificate, namespaces)
        }
        val validationException = invocationException.targetException as ValidationException
        assertEquals(ERROR_CODE_INVALID_ISSUING_JURISDICTION, validationException.errorCode)
    }

    @Test
    fun `should throw exception for mso_mdoc status check as its not supported`() {
        val unsupportedStatusCheckException = assertThrows(UnsupportedOperationException::class.java) {
            MsoMdocVerifiableCredential().checkStatus(validMdoc, null)
        }

        assertEquals("Credential status checking not supported for this credential format",unsupportedStatusCheckException.message)
    }

    @Test
    fun `should Reject Mdl When Ds CertificateIs Missing Mdl Eku`() {
        val credential = javaClass.classLoader
            .getResourceAsStream("mso_mdoc/valid_mdl_missing_ds_eku.b64url")!!
            .bufferedReader()
            .use { it.readText().trim() }

        val validation = MsoMdocVerifiableCredential().validate(credential)
        assertEquals("", validation.validationMessage)
        assertEquals("", validation.validationErrorCode)

        val exception = assertThrows(ValidationException::class.java) {
            MsoMdocVerifier().verify(credential)
        }
        // Certify DS cert currently lacks critical EKU 1.0.18013.5.1.2 (inji-certify#1123).
        // Disclosed claims also omit mandatory issuing_country, so country check would fail next.
        assertEquals(ERROR_CODE_INVALID_DS_CERT_EKU, exception.errorCode)
    }

    @Test
    fun `should throw when protected header is missing alg`() {
        val issuerAuth = CborArray().apply {
            add(ByteString(ByteArray(0)))
            add(CborMap())
            add(ByteString(ByteArray(0)))
            add(ByteString(ByteArray(4)))
        }

        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod("verifyProtectedHeaderAlg", CborArray::class.java)
        method.isAccessible = true

        val invocationException = assertThrows(InvocationTargetException::class.java) {
            method.invoke(verifier, issuerAuth)
        }
        val validationException = invocationException.targetException as ValidationException
        assertEquals(ERROR_MESSAGE_MISSING_ALG, validationException.errorMessage)
        assertEquals(ERROR_CODE_MISSING_ALG, validationException.errorCode)
    }

    @Test
    fun `should throw when protected header alg is unsupported EdDSA`() {
        val protectedHeaderBytes = ByteArrayOutputStream().also {
            CborEncoder(it).encode(CborMap().apply {
                // COSE EdDSA (-8) remains out of scope for mso_mdoc (#300)
                put(UnsignedInteger(1), NegativeInteger(-8))
            })
        }.toByteArray()
        val issuerAuth = CborArray().apply {
            add(ByteString(protectedHeaderBytes))
            add(CborMap())
            add(ByteString(ByteArray(0)))
            add(ByteString(ByteArray(4)))
        }

        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod("verifyProtectedHeaderAlg", CborArray::class.java)
        method.isAccessible = true

        val invocationException = assertThrows(InvocationTargetException::class.java) {
            method.invoke(verifier, issuerAuth)
        }
        val validationException = invocationException.targetException as ValidationException
        assertEquals(ERROR_MESSAGE_INVALID_MSO_ALG, validationException.errorMessage)
        assertEquals(ERROR_CODE_INVALID_ALG, validationException.errorCode)
    }

    @Test
    fun `should throw when protected header alg is unsigned wrap of ES256`() {
        // 2^64 - 7 == 18446744073709551609; toLong() would narrow this to -7.
        val wrapAroundAlg = java.math.BigInteger("18446744073709551609")
        val protectedHeaderBytes = ByteArrayOutputStream().also {
            CborEncoder(it).encode(CborMap().apply {
                put(UnsignedInteger(1), UnsignedInteger(wrapAroundAlg))
            })
        }.toByteArray()
        val issuerAuth = CborArray().apply {
            add(ByteString(protectedHeaderBytes))
            add(CborMap())
            add(ByteString(ByteArray(0)))
            add(ByteString(ByteArray(4)))
        }

        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod("verifyProtectedHeaderAlg", CborArray::class.java)
        method.isAccessible = true

        val invocationException = assertThrows(InvocationTargetException::class.java) {
            method.invoke(verifier, issuerAuth)
        }
        val validationException = invocationException.targetException as ValidationException
        assertEquals(ERROR_MESSAGE_INVALID_MSO_ALG, validationException.errorMessage)
        assertEquals(ERROR_CODE_INVALID_ALG, validationException.errorCode)
    }

    @Test
    fun `should accept protected header alg ES256`() {
        val protectedHeaderBytes = ByteArrayOutputStream().also {
            CborEncoder(it).encode(CborMap().apply {
                put(UnsignedInteger(1), NegativeInteger(-7))
            })
        }.toByteArray()
        val issuerAuth = CborArray().apply {
            add(ByteString(protectedHeaderBytes))
            add(CborMap())
            add(ByteString(ByteArray(0)))
            add(ByteString(ByteArray(4)))
        }

        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod("verifyProtectedHeaderAlg", CborArray::class.java)
        method.isAccessible = true

        assertDoesNotThrow { method.invoke(verifier, issuerAuth) }
    }

    @Test
    fun `should accept protected header alg ES384 and ES512`() {
        listOf(-35L, -36L).forEach { alg ->
            val protectedHeaderBytes = ByteArrayOutputStream().also {
                CborEncoder(it).encode(CborMap().apply {
                    put(UnsignedInteger(1), NegativeInteger(alg))
                })
            }.toByteArray()
            val issuerAuth = CborArray().apply {
                add(ByteString(protectedHeaderBytes))
                add(CborMap())
                add(ByteString(ByteArray(0)))
                add(ByteString(ByteArray(4)))
            }
            val verifier = MsoMdocVerifier()
            val method = verifier.javaClass.getDeclaredMethod("verifyProtectedHeaderAlg", CborArray::class.java)
            method.isAccessible = true
            assertDoesNotThrow { method.invoke(verifier, issuerAuth) }
        }
    }

    @Test
    fun `should throw ERR_INVALID_DIGEST_SALT when random is shorter than 16 bytes`() {
        val issuerSignedItem = CborMap().apply {
            put(UnicodeString("digestID"), UnsignedInteger(1))
            put(UnicodeString("random"), ByteString(ByteArray(8)))
            put(UnicodeString("elementIdentifier"), UnicodeString("family_name"))
            put(UnicodeString("elementValue"), UnicodeString("Doe"))
        }
        val itemBytes = ByteArrayOutputStream().also { CborEncoder(it).encode(issuerSignedItem) }.toByteArray()
        val taggedItem = ByteString(itemBytes).apply { setTag(24) }
        val encodedItem = ByteArrayOutputStream().also { CborEncoder(it).encode(taggedItem) }.toByteArray()
        val namespace = UnicodeString("org.iso.18013.5.1")
        val namespaces = CborMap().apply {
            put(namespace, CborArray().apply { add(taggedItem) })
        }
        val mso = CborMap().apply {
            put(UnicodeString("digestAlgorithm"), UnicodeString("SHA-256"))
            put(UnicodeString("valueDigests"), CborMap().apply { put(namespace, CborMap()) })
        }

        val validationException = invokeVerifyValueDigests(
            namespaces,
            mapOf("org.iso.18013.5.1" to listOf(encodedItem)),
            mso,
        )
        assertEquals(ERROR_CODE_INVALID_DIGEST_SALT, validationException.errorCode)
    }

    @Test
    fun `should throw ERR_INVALID_ISSUE_DATE for impossible calendar date`() {
        val issuerSignedItem = CborMap().apply {
            put(UnicodeString("digestID"), UnsignedInteger(1))
            put(UnicodeString("random"), ByteString(ByteArray(16)))
            put(UnicodeString("elementIdentifier"), UnicodeString("issue_date"))
            put(UnicodeString("elementValue"), UnicodeString("2024-13-45"))
        }
        val itemBytes = ByteArrayOutputStream().also { CborEncoder(it).encode(issuerSignedItem) }.toByteArray()
        val namespaces = CborMap().apply {
            put(
                UnicodeString("org.iso.18013.5.1"),
                CborArray().apply { add(ByteString(itemBytes)) }
            )
        }

        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod(
            "verifyIssueDate",
            CborMap::class.java,
            CborMap::class.java
        )
        method.isAccessible = true

        val invocationException = assertThrows(InvocationTargetException::class.java) {
            method.invoke(verifier, CborMap(), namespaces)
        }
        val validationException = invocationException.targetException as ValidationException
        assertEquals(ERROR_MESSAGE_INVALID_ISSUE_DATE_FORMAT, validationException.errorMessage)
        assertEquals(ERROR_CODE_INVALID_ISSUE_DATE, validationException.errorCode)
    }

    @Test
    fun `should throw ERR_INVALID_ISSUE_DATE when issue_date is after validFrom`() {
        val issuerSignedItem = CborMap().apply {
            put(UnicodeString("digestID"), UnsignedInteger(1))
            put(UnicodeString("random"), ByteString(ByteArray(16)))
            put(UnicodeString("elementIdentifier"), UnicodeString("issue_date"))
            put(UnicodeString("elementValue"), UnicodeString("2025-01-02"))
        }
        val itemBytes = ByteArrayOutputStream().also { CborEncoder(it).encode(issuerSignedItem) }.toByteArray()
        val namespaces = CborMap().apply {
            put(
                UnicodeString("org.iso.18013.5.1"),
                CborArray().apply { add(ByteString(itemBytes)) }
            )
        }
        val mso = CborMap().apply {
            put(
                UnicodeString("validityInfo"),
                CborMap().apply {
                    put(UnicodeString("validFrom"), UnicodeString("2025-01-01T00:00:00Z"))
                }
            )
        }

        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod(
            "verifyIssueDate",
            CborMap::class.java,
            CborMap::class.java
        )
        method.isAccessible = true

        val invocationException = assertThrows(InvocationTargetException::class.java) {
            method.invoke(verifier, mso, namespaces)
        }
        val validationException = invocationException.targetException as ValidationException
        assertEquals(ERROR_MESSAGE_INVALID_ISSUE_DATE, validationException.errorMessage)
        assertEquals(ERROR_CODE_INVALID_ISSUE_DATE, validationException.errorCode)
    }

    @Test
    fun `should throw when digestID is not less than 2 to the 31`() {
        val issuerSignedItem = CborMap().apply {
            put(UnicodeString("digestID"), UnsignedInteger(BigInteger.valueOf(1L shl 31)))
            put(UnicodeString("random"), ByteString(ByteArray(16)))
            put(UnicodeString("elementIdentifier"), UnicodeString("family_name"))
            put(UnicodeString("elementValue"), UnicodeString("Doe"))
        }
        val itemBytes = ByteArrayOutputStream().also { CborEncoder(it).encode(issuerSignedItem) }.toByteArray()
        val taggedItem = ByteString(itemBytes).apply { setTag(24) }
        val encodedItem = ByteArrayOutputStream().also { CborEncoder(it).encode(taggedItem) }.toByteArray()
        val namespace = UnicodeString("org.iso.18013.5.1")
        val namespaces = CborMap().apply {
            put(namespace, CborArray().apply { add(taggedItem) })
        }
        val mso = CborMap().apply {
            put(UnicodeString("digestAlgorithm"), UnicodeString("SHA-256"))
            put(UnicodeString("valueDigests"), CborMap().apply { put(namespace, CborMap()) })
        }

        val validationException = invokeVerifyValueDigests(
            namespaces,
            mapOf("org.iso.18013.5.1" to listOf(encodedItem)),
            mso,
        )
        assertEquals(ERROR_MESSAGE_DIGEST_ID_OUT_OF_RANGE, validationException.errorMessage)
        assertEquals(ERROR_CODE_INVALID_DIGEST_ID, validationException.errorCode)
    }

    @Test
    fun `should throw when nameSpaces record is not tag-24`() {
        val namespace = UnicodeString("org.iso.18013.5.1")
        val plainItem = ByteString(byteArrayOf(1, 2, 3))
        val namespaces = CborMap().apply {
            put(namespace, CborArray().apply { add(plainItem) })
        }
        val encodedItems = mapOf(
            "org.iso.18013.5.1" to listOf(
                ByteArrayOutputStream().also { CborEncoder(it).encode(plainItem) }.toByteArray()
            )
        )
        val mso = CborMap().apply {
            put(UnicodeString("digestAlgorithm"), UnicodeString("SHA-256"))
            put(UnicodeString("valueDigests"), CborMap().apply { put(namespace, CborMap()) })
        }

        val validationException = invokeVerifyValueDigests(namespaces, encodedItems, mso)
        assertEquals(ERROR_MESSAGE_INVALID_ISSUER_SIGNED_ITEM, validationException.errorMessage)
        assertEquals(ERROR_CODE_INVALID_ISSUER_SIGNED_ITEM, validationException.errorCode)
    }

    @Test
    fun `should throw when duplicate digestID is present in a namespace`() {
        val issuerSignedItem = CborMap().apply {
            put(UnicodeString("digestID"), UnsignedInteger(1))
            put(UnicodeString("random"), ByteString(ByteArray(16)))
            put(UnicodeString("elementIdentifier"), UnicodeString("family_name"))
            put(UnicodeString("elementValue"), UnicodeString("Doe"))
        }
        val itemBytes = ByteArrayOutputStream().also { CborEncoder(it).encode(issuerSignedItem) }.toByteArray()
        val taggedItem = ByteString(itemBytes).apply { setTag(24) }
        val encodedItem = ByteArrayOutputStream().also { CborEncoder(it).encode(taggedItem) }.toByteArray()

        val namespace = UnicodeString("org.iso.18013.5.1")
        val namespaces = CborMap().apply {
            put(namespace, CborArray().apply {
                add(taggedItem)
                add(taggedItem)
            })
        }
        val encodedItems = mapOf(
            "org.iso.18013.5.1" to listOf(encodedItem, encodedItem)
        )
        val mso = CborMap().apply {
            put(UnicodeString("digestAlgorithm"), UnicodeString("SHA-256"))
            put(UnicodeString("valueDigests"), CborMap().apply { put(namespace, CborMap()) })
        }

        val validationException = invokeVerifyValueDigests(namespaces, encodedItems, mso)
        assertEquals(ERROR_MESSAGE_INVALID_DIGEST_ID, validationException.errorMessage)
        assertEquals(ERROR_CODE_INVALID_DIGEST_ID, validationException.errorCode)
    }

    @Test
    fun `should hash as-received tag-24 wrapper bytes not a re-encoded DataItem`() {
        // Manually craft IssuerSignedItemBytes with a non-canonical bstr length header
        // (2-byte length form) that CborEncoder would not emit for this size.
        val innerMap = CborMap().apply {
            put(UnicodeString("digestID"), UnsignedInteger(7))
            put(UnicodeString("random"), ByteString(ByteArray(16) { 1 }))
            put(UnicodeString("elementIdentifier"), UnicodeString("family_name"))
            put(UnicodeString("elementValue"), UnicodeString("Doe"))
        }
        val innerBytes = ByteArrayOutputStream().also { CborEncoder(it).encode(innerMap) }.toByteArray()
        require(innerBytes.size < 256) { "test fixture assumes single-byte length is enough" }

        // d818 59 00 NN <inner...>  — tag 24 + bstr with 16-bit length (non-canonical for small NN)
        val nonCanonicalTagged = ByteArray(3 + 2 + innerBytes.size)
        nonCanonicalTagged[0] = 0xd8.toByte()
        nonCanonicalTagged[1] = 0x18
        nonCanonicalTagged[2] = 0x59 // bstr, 2-byte length
        nonCanonicalTagged[3] = 0x00
        nonCanonicalTagged[4] = innerBytes.size.toByte()
        System.arraycopy(innerBytes, 0, nonCanonicalTagged, 5, innerBytes.size)

        val decodedTagged = co.nstant.`in`.cbor.CborDecoder(
            java.io.ByteArrayInputStream(nonCanonicalTagged)
        ).decode()[0] as ByteString
        val canonicalReencoded = ByteArrayOutputStream().also { CborEncoder(it).encode(decodedTagged) }.toByteArray()
        assertFalse(
            canonicalReencoded.contentEquals(nonCanonicalTagged),
            "precondition: re-encode must differ from non-canonical as-received bytes"
        )

        val expectedDigest = java.security.MessageDigest.getInstance("SHA-256").digest(nonCanonicalTagged)
        val namespace = UnicodeString("org.iso.18013.5.1")
        val namespaces = CborMap().apply {
            put(namespace, CborArray().apply { add(decodedTagged) })
        }
        val encodedItems = mapOf("org.iso.18013.5.1" to listOf(nonCanonicalTagged))
        val mso = CborMap().apply {
            put(UnicodeString("digestAlgorithm"), UnicodeString("SHA-256"))
            put(
                UnicodeString("valueDigests"),
                CborMap().apply {
                    put(
                        namespace,
                        CborMap().apply { put(UnsignedInteger(7), ByteString(expectedDigest)) }
                    )
                }
            )
        }

        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod(
            "verifyValueDigests",
            CborMap::class.java,
            Map::class.java,
            CborMap::class.java
        )
        method.isAccessible = true
        assertDoesNotThrow { method.invoke(verifier, namespaces, encodedItems, mso) }
    }

    private fun invokeVerifyValueDigests(
        namespaces: CborMap,
        encodedItems: Map<String, List<ByteArray>>,
        mso: CborMap,
    ): ValidationException {
        val verifier = MsoMdocVerifier()
        val method = verifier.javaClass.getDeclaredMethod(
            "verifyValueDigests",
            CborMap::class.java,
            Map::class.java,
            CborMap::class.java
        )
        method.isAccessible = true
        val invocationException = assertThrows(InvocationTargetException::class.java) {
            method.invoke(verifier, namespaces, encodedItems, mso)
        }
        return invocationException.targetException as ValidationException
    }
}