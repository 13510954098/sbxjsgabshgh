/*
 * Copyright (C) 2024-2025 OpenAni and contributors.
 *
 * 此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 * Use of this source code is governed by the GNU AGPLv3 license, which can be found at the following link.
 *
 * https://github.com/open-ani/ani/blob/main/LICENSE
 */

package me.him188.ani.app.domain.mediasource.web

import me.him188.ani.datasources.api.matcher.WebVideo
import me.him188.ani.datasources.api.matcher.WebVideoMatcher

class ExtractedVideoMatcher {
    fun shouldLoadPage(url: String, config: SelectorSearchConfig.MatchVideoConfig): Boolean {
        if (config.enableNestedUrl) {
            config.matchNestedUrlRegex?.find(url)?.let {
                return true
            }
        }
        return false
    }

    fun matchWebVideo(url: String, searchConfig: SelectorSearchConfig.MatchVideoConfig): WebVideoMatcher.MatchResult {
        if (shouldLoadPage(url, searchConfig)) {
            return WebVideoMatcher.MatchResult.LoadPage
        }

        val result = searchConfig.matchVideoUrlRegex?.find(url) ?: return WebVideoMatcher.MatchResult.Continue
        val videoUrl = try {
            result.groups["v"]?.value ?: url
        } catch (_: IllegalArgumentException) { // no group
            url
        }

        return WebVideoMatcher.MatchResult.Matched(
            WebVideo(
                videoUrl,
                mapOf(
                    "User-Agent" to searchConfig.addHeadersToVideo.userAgent,
                    "Referer" to searchConfig.addHeadersToVideo.referer,
                    "Sec-Ch-Ua-Mobile" to "?0",
                    "Sec-Ch-Ua-Platform" to "macOS",
                    "Sec-Fetch-Dest" to "video",
                    "Sec-Fetch-Mode" to "no-cors",
                    "Sec-Fetch-Site" to "cross-site",
                ),
            ),
        )
    }

}
