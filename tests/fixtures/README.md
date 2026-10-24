# Animeko subscription regression fixtures

`animeko-css1-schema-v2.json` and `animeko-bt1-schema-v2.json` are complete generated subscription documents from the upstream `creamycake-anime/ani-subs` repository at commit `9b56792df4a1ec92611f342c96936da768f6be66` (2026-10-24). They were generated with that repository's `scripts/build-subs.js`, matching the layout and schema of its published `v1/css1.json` and `v1/bt1.json` outputs. The css1 source list includes the `json-api` source; its exported compatible list intentionally omits it.

The selftest validates both exported payloads and, for css1, the full `mediaSources` list to cover `linkTemplate` parsing and the deferred `json-api` policy.
