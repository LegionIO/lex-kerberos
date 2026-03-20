# Changelog

## [Unreleased]

## [0.1.3] - 2026-03-19

### Added
- `Hooks::Negotiate` hook class for Kerberos SPNEGO authentication via expanded hooks system
- `Runners::Authenticate#negotiate` method handling full HTTP Negotiate flow with custom response
- RBAC role mapping and JWT token issuance (guarded, requires LegionIO framework)
- Negotiate endpoint now routes through `Ingress.run` for RBAC and audit support

### Changed
- Kerberos negotiate endpoint moves from hardcoded `/api/auth/negotiate` in LegionIO to `/api/hooks/lex/kerberos/negotiate`

## [0.1.2] - 2026-03-18

### Added
- Organizational LDAP attributes: `title`, `department`, `company`, `co`, `c`, `l`, `st`, `cn`, `whenCreated`
- `PROFILE_MAP` constant maps LDAP attribute names to readable Ruby symbols

### Changed
- `USER_ATTRIBUTES` expanded to include organizational fields
- `extract_profile` uses `PROFILE_MAP` for declarative attribute mapping

## [0.1.1] - 2026-03-18

### Added
- LDAP user profile fetching: `givenName`, `sn`, `mail`, `displayName` attributes returned from `lookup_groups`
- `first_name`, `last_name`, `email`, `display_name` fields in authenticate runner result

### Changed
- LDAP search now fetches `USER_ATTRIBUTES` constant (memberOf + profile fields) instead of just group attribute

## [0.1.0] - 2026-03-17

### Added
- SPNEGO/GSSAPI token validation via `gssapi` gem (`Helpers::Spnego#accept_spnego_token`)
- LDAP group resolution via `net-ldap` gem (`Helpers::Ldap#lookup_groups`) with configurable filter and attribute
- Keytab management with Vault-primary, file-fallback resolution (`Helpers::Keytab#resolve_keytab`); supports `vault://` URIs, file paths, and Base64 blobs written to `~/.legionio/kerberos/legion.keytab`
- Standalone `Client` class with `authenticate(token:)` and `resolve_groups(username:)` for framework-independent usage
- `Runners::Authenticate#validate_spnego`: full pipeline combining keytab resolution, GSSAPI acceptance, and optional LDAP group lookup
- `Actor::KeytabRefresh`: interval actor (hourly) that re-fetches and caches the keytab from configured sources
- 43 specs, 91.67% coverage
