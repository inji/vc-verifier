package io.mosip.vercred.vcverifier.networkManager

import io.mosip.vercred.vcverifier.exception.NetworkManagerClientExceptions
import io.mosip.vercred.vcverifier.utils.Util
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.ResponseBody
import java.io.InterruptedIOException


class NetworkManagerClient {
    companion object {
        private fun <T> execute(request: Request, readBody: (ResponseBody?) -> T): T {
            try {
                val client = OkHttpClient.Builder().build()
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) throw Exception(response.toString())
                    return readBody(response.body)
                }
            } catch (exception: InterruptedIOException) {
                throw NetworkManagerClientExceptions.NetworkRequestTimeout()
            } catch (exception: Exception) {
                throw NetworkManagerClientExceptions.NetworkRequestFailed(exception.message ?: "unknown error")
            }
        }
        fun sendHTTPRequestForBytes(url: String): ByteArray {
            val request = Request.Builder().url(url).get().build()
            return execute(request) { body ->
                body?.bytes() ?: throw Exception("Empty response body")
            }
        }

        fun sendHTTPRequest(
            url: String,
            method: HttpMethod,
            bodyParams: Map<String, String>? = null,
            headers: Map<String, String>? = null
        ): Map<String, Any>? {
            val request: Request
            when (method) {
                HttpMethod.POST -> {
                    val requestBodyBuilder = FormBody.Builder()
                    bodyParams?.forEach { (key, value) ->
                        requestBodyBuilder.add(key, value)
                    }
                    val requestBody = requestBodyBuilder.build()
                    val requestBuilder = Request.Builder().url(url).post(requestBody)
                    headers?.forEach { (key, value) ->
                        requestBuilder.addHeader(key, value)
                    }
                    request = requestBuilder.build()
                }

                HttpMethod.GET -> request = Request.Builder().url(url).get().build()
            }
            return execute(request) { body ->
                body?.let {
                    Util.convertJsonToMap(it.byteStream().bufferedReader().use { reader -> reader.readText() })
                }
            }
        }
    }
}

enum class HttpMethod {
    POST, GET
}