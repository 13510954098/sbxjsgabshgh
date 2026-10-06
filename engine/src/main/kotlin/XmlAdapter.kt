// JVM-only adapter: same Jsoup aliases and QueryParser used by Animeko's utils/xml.
package me.him188.ani.utils.xml

typealias Element = org.jsoup.nodes.Element
typealias Evaluator = org.jsoup.select.Evaluator
object QueryParser {
    fun parseSelector(selector: String): Evaluator = org.jsoup.select.QueryParser.parse(selector)
}
fun QueryParser.parseSelectorOrNull(selector: String): Evaluator? {
    if (selector.isBlank()) return null
    return try { parseSelector(selector) } catch (_: IllegalStateException) { null }
}
