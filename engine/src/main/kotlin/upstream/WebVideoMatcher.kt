/*
 * Copyright (C) 2024 OpenAni and contributors.
 *
 * 此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 * Use of this source code is governed by the GNU AGPLv3 license, which can be found at the following link.
 *
 * https://github.com/open-ani/ani/blob/main/LICENSE
 */

package me.him188.ani.datasources.api.matcher

interface WebVideoMatcher { // SPI service load
    sealed class MatchResult {
        data class Matched(
            val video: WebVideo
        ) : MatchResult()

        data object Continue : MatchResult()
        data object LoadPage : MatchResult()
    }

}

data class WebVideo(
    /**
     * 视频数据地址
     */
    val m3u8Url: String,
    /**
     * 请求视频数据时需要的 headers
     *
     * 建议提供:
     *
     * - `User-Agent`
     * - `Referer`
     */
    val headers: Map<String, String>
)
