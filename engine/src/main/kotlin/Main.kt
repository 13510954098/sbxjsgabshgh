// SPDX-License-Identifier: AGPL-3.0-only
// A bounded, network-free adapter for extracted Animeko parsers. Not a player.
package bridge

import kotlinx.serialization.json.*
import io.ktor.http.URLBuilder
import me.him188.ani.app.domain.mediasource.web.*
import me.him188.ani.app.domain.mediasource.web.format.*
import me.him188.ani.datasources.api.matcher.WebVideoMatcher
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import java.io.BufferedReader
import java.io.InputStreamReader

private val json = Json { ignoreUnknownKeys = true }
private fun JsonObject.text(key: String, fallback: String = "") = (get(key) as? JsonPrimitive)?.content ?: fallback
private fun JsonObject.obj(key: String) = get(key) as? JsonObject ?: JsonObject(emptyMap())
private fun subjects(c: JsonObject, page: String, base: String): JsonArray {
    // App wraps JSON as text in a document; never HTML-parse JSON (would corrupt < / &).
    val id = c.text("subjectFormatId", "a")
    val doc = if (id == "json-path-indexed") Document("").apply { body().text(page) } else Jsoup.parse(page, base)
    val finalBase = c.text("rawBaseUrl").ifBlank {
        URLBuilder(c.text("searchUrl", base)).apply { pathSegments = emptyList(); parameters.clear() }.buildString()
    }
    val rows = when (id) {
        "a" -> SelectorSubjectFormatA.select(doc, finalBase, json.decodeFromJsonElement<SelectorSubjectFormatA.Config>(c.obj("selectorSubjectFormatA")))
        "indexed" -> SelectorSubjectFormatIndexed.select(doc, finalBase, json.decodeFromJsonElement<SelectorSubjectFormatIndexed.Config>(c.obj("selectorSubjectFormatIndexed")))
        "json-path-indexed" -> SelectorSubjectFormatJsonPathIndexed.select(doc, finalBase, json.decodeFromJsonElement<SelectorSubjectFormatJsonPathIndexed.Config>(c.obj("selectorSubjectFormatJsonPathIndexed")))
        else -> error("unsupported subject format")
    } ?: error("invalid subject configuration")
    return buildJsonArray { rows.take(40).forEach { r -> add(buildJsonObject { put("name", r.name); put("url", r.fullUrl) }) } }
}
private fun episodes(c: JsonObject, page: String, base: String): JsonArray {
    val doc = Jsoup.parse(page, base)
    // Same base construction as selectEpisodesImpl in the client.
    val finalBase = URLBuilder(base).apply { pathSegments = pathSegments.dropLast(1) }.buildString()
    val rows = when(c.text("channelFormatId", "index-grouped")) {
        "index-grouped" -> SelectorChannelFormatIndexGrouped.select(doc, finalBase, json.decodeFromJsonElement<SelectorChannelFormatIndexGrouped.Config>(c.obj("selectorChannelFormatFlattened")))
        "no-channel" -> SelectorChannelFormatNoChannel.select(doc, finalBase, json.decodeFromJsonElement<SelectorChannelFormatNoChannel.Config>(c.obj("selectorChannelFormatNoChannel")))
        else -> error("unsupported channel format")
    } ?: error("invalid channel configuration")
    return buildJsonArray { rows.episodes.take(100).forEach { r -> add(buildJsonObject {
        put("name", r.name); put("url", r.playUrl); put("channel", r.channel ?: "默认线路"); put("episodeSort", r.episodeSortOrEp?.toString())
    }) } }
}
private fun match(c: JsonObject, urls: JsonArray): JsonArray {
    val config = json.decodeFromJsonElement<SelectorSearchConfig.MatchVideoConfig>(c.obj("matchVideo"))
    require(config.matchVideoUrlRegex != null && (!config.enableNestedUrl || config.matchNestedUrlRegex != null))
    val matcher = ExtractedVideoMatcher()
    return buildJsonArray { urls.take(100).forEach { raw ->
        val url = raw.jsonPrimitive.content
        require(url.length <= 8192)
        add(buildJsonObject {
            put("input", url)
            when(val result = matcher.matchWebVideo(url, config)) {
                WebVideoMatcher.MatchResult.Continue -> put("kind", "ignore")
                WebVideoMatcher.MatchResult.LoadPage -> { put("kind", "nested"); put("url", url) }
                is WebVideoMatcher.MatchResult.Matched -> {
                    put("kind", "video"); put("url", result.video.m3u8Url)
                    put("headers", buildJsonObject { result.video.headers.forEach { (k,v) -> put(k,v) } })
                }
            }
        })
    } }
}
private fun handle(input: JsonObject): JsonElement {
    val config = input.obj("config")
    val page = input.text("body")
    val base = input.text("baseUrl")
    return when(input.text("op")) {
        "subjects" -> subjects(config, page, base)
        "episodes" -> episodes(config, page, base)
        "match" -> match(config, input["urls"] as? JsonArray ?: JsonArray(emptyList()))
        "health" -> buildJsonObject { put("upstream", "cd0ad5ca8dc501fb06426d83870f49e7e3b0adef"); put("network", false) }
        else -> error("unknown operation")
    }
}
fun main() {
    // One bounded request per process. Parent enforces wall-clock and memory limits;
    // hostile regex cannot occupy a shared long-lived JVM indefinitely.
    val reader = BufferedReader(InputStreamReader(System.`in`, Charsets.UTF_8))
    val text = StringBuilder()
    val buffer = CharArray(8192)
    while(true) {
        val n = reader.read(buffer)
        if(n < 0) break
        require(text.length + n <= 2 * 1024 * 1024) { "request too large" }
        text.append(buffer, 0, n)
    }
    val result = try {
        val value = handle(json.parseToJsonElement(text.toString()).jsonObject)
        buildJsonObject { put("ok", true); put("result", value) }
    } catch(e: Exception) {
        // Never echo HTML, credentials, extracted URLs, or raw parser errors to logs.
        buildJsonObject { put("ok", false); put("error", e.javaClass.simpleName) }
    }
    println(result.toString())
}
