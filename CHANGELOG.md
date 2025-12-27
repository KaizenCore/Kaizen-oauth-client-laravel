# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-27

### Added
- Initial release
- Socialite driver for Kaizen OAuth2 authentication
- Auto-discovery for Laravel 11+
- `KaizenProvider` with token refresh and revocation
- `KaizenUser` with Minecraft account helper methods
- `EnsureKaizenToken` middleware for route protection
- `HasKaizenAuth` trait for controllers
- Support for all Kaizen OAuth scopes:
  - User scopes: `user:read`, `user:email`, `user:profile`
  - Minecraft scopes: `minecraft:read`, `minecraft:verify`
  - Skins API scopes: `skins:read`, `skins:create`, `skins:delete`, `skins:manage`
  - API Keys scopes: `api-keys:read`, `api-keys:create`, `api-keys:delete`, `api-keys:manage`
  - Other scopes: `plugins:favorites`
