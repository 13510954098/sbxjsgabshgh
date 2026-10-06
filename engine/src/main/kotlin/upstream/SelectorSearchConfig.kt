/*
 * Copyright (C) 2024-2026 OpenAni and contributors.
 *
 * 此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 * Use of this source code is governed by the GNU AGPLv3 license, which can be found at the following link.
 *
 * https://github.com/open-ani/ani/blob/main/LICENSE
 */

package me.him188.ani.app.domain.mediasource.web

import kotlinx.serialization.Serializable
import org.intellij.lang.annotations.Language
import me.him188.ani.app.domain.mediasource.web.format.parseOrNull

class SelectorSearchConfig {
    @Serializable
    @Suppress("RegExpRedundantEscape")
    data class MatchVideoConfig(
        val enableNestedUrl: Boolean = true,
        @param:Language("regexp")
        val matchNestedUrl: String = """^.+(m3u8|vip|xigua\.php).+\?""",
        @param:Language("regexp")
        val matchVideoUrl: String = """(^http(s)?:\/\/(?!.*http(s)?:\/\/).+((\.mp4)|(\.mkv)|(m3u8)).*(\?.+)?)|(akamaized)|(bilivideo.com)""",
        val cookies: String = """quality=1080""",
        val addHeadersToVideo: VideoHeaders = VideoHeaders(),
    ) {
        val matchNestedUrlRegex by lazy {
            Regex.parseOrNull(matchNestedUrl)
        }
        val matchVideoUrlRegex by lazy {
            Regex.parseOrNull(matchVideoUrl)
        }
    }

    @Serializable
    data class VideoHeaders(
        val referer: String = "",
        val userAgent: String = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    )

}
