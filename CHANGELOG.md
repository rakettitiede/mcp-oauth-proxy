# Changelog

## [1.2.0](https://github.com/rakettitiede/mcp-oauth-proxy/compare/v1.1.0...v1.2.0) (2026-05-18)


### Features

* add skill/SKILL.md — Claude usage guide for mcp-oauth-proxy ([dbd7af6](https://github.com/rakettitiede/mcp-oauth-proxy/commit/dbd7af6dcff7df50dc3a24189982d6f18ac7f608))
* add skill/SKILL.md — mcp-oauth-proxy Claude usage guide ([e07746c](https://github.com/rakettitiede/mcp-oauth-proxy/commit/e07746c11a9b7e32ba6ad9cc2c3fab3731eadd1c))

## [1.1.0](https://github.com/rakettitiede/mcp-oauth-proxy/compare/v1.0.0...v1.1.0) (2026-04-30)


### Features

* make googleClientId optional in createRequireAuth ([ba28031](https://github.com/rakettitiede/mcp-oauth-proxy/commit/ba28031d3b2947ebcaf2e9b0afea561c0c1fa76e))
* make googleClientId optional in createRequireAuth ([1f8921d](https://github.com/rakettitiede/mcp-oauth-proxy/commit/1f8921dfc0989dbc260bb72ae03d9c274ff8199a))

## [1.0.0](https://github.com/rakettitiede/mcp-oauth-proxy/compare/v0.1.0...v1.0.0) (2026-04-27)


### ⚠ BREAKING CHANGES

* createOAuthRouter now returns an object with two keys instead of a bare Express Router.

### Features

* return { oauthRouter, oauthMeta } from createOAuthRouter ([14a09cd](https://github.com/rakettitiede/mcp-oauth-proxy/commit/14a09cdcfc513b73641ca552de96bd4760843b32))
