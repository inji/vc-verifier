package io.mosip.vercred.vcverifier.networkManager

import io.mosip.vercred.vcverifier.exception.NetworkManagerClientExceptions
import io.mosip.vercred.vcverifier.utils.Util
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.InterruptedIOException


class NetworkManagerClient {
    companion object {
        fun sendHTTPRequest(
            url: String,
            method: HttpMethod,
            bodyParams: Map<String, String>? = null,
            headers: Map<String, String>? = null
        ): Map<String, Any>? {
            try {
                val response = executeRequest(url, method, bodyParams, headers)
                return response.body?.let { body ->
                    Util.convertJsonToMap(
                        body.byteStream().bufferedReader().use { it.readText() }
                    )
                }
            } catch (exception: InterruptedIOException) {
                throw NetworkManagerClientExceptions.NetworkRequestTimeout()
            } catch (exception: Exception) {
                throw NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
            }
        }

        fun sendHTTPRequestBytes(
            url: String,
            method: HttpMethod,
            headers: Map<String, String>? = null
        ): ByteArray {
            try {
                val response = executeRequest(url, method, headers = headers)
                return response.body?.bytes()
                    ?: throw Exception("Empty response body")
            } catch (exception: InterruptedIOException) {
                throw NetworkManagerClientExceptions.NetworkRequestTimeout()
            } catch (exception: Exception) {
                throw NetworkManagerClientExceptions.NetworkRequestFailed(exception.message!!)
            }
        }

        private fun executeRequest(
            url: String,
            method: HttpMethod,
            bodyParams: Map<String, String>? = null,
            headers: Map<String, String>? = null
        ): Response {
            val client = OkHttpClient.Builder().build()
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

                HttpMethod.GET -> {
                    val requestBuilder = Request.Builder().url(url).get()
                    headers?.forEach { (key, value) ->
                        requestBuilder.addHeader(key, value)
                    }
                    request = requestBuilder.build()
                }
            }
            val response: Response = client.newCall(request).execute()
            if (response.isSuccessful) {
                return response
            }
            throw Exception(response.toString())
        }
    }
}

enum class HttpMethod {
    POST, GET
}
