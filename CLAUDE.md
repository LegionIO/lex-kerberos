# lex-kerberos: Kerberos/SPNEGO Authentication for LegionIO

**Repository Level 3 Documentation**
- **Parent (Level 2)**: `/Users/miverso2/rubymine/legion/extensions/CLAUDE.md`
- **Parent (Level 1)**: `/Users/miverso2/rubymine/legion/CLAUDE.md`

## Purpose

Legion Extension that provides Kerberos/SPNEGO authentication. Validates SPNEGO tokens via GSSAPI, resolves LDAP group membership against Active Directory, and manages keytab files with Vault-primary, file-fallback sourcing. Designed for services that accept HTTP Negotiate authentication from AD-joined clients.

**GitHub**: https://github.com/LegionIO/lex-kerberos
**License**: MIT
**Version**: 0.1.2

## Architecture

```
Legion::Extensions::Kerberos
├── Runners/
│   └── Authenticate      # validate_spnego: keytab resolve + GSSAPI accept + LDAP groups
├── Actors/
│   └── KeytabRefresh     # Every actor (1hr): re-fetch keytab from Vault/sources
├── Helpers/
│   ├── Spnego            # GSSAPI token validation, principal/realm extraction
│   ├── Ldap              # Net::LDAP group lookup via sAMAccountName filter
│   ├── Keytab            # Multi-source keytab resolution (vault://, file path, Base64)
│   └── Client            # Settings defaults and Legion::Settings merge
└── Client                # Standalone client class (includes all helpers)
```

## File Map

| File | Purpose |
|------|---------|
| `lib/legion/extensions/kerberos.rb` | Entry point, requires all helpers/runners/actors, extends Core |
| `lib/legion/extensions/kerberos/helpers/spnego.rb` | GSSAPI token acceptance via `gssapi` gem; `accept_spnego_token`, `extract_username`, `extract_realm` |
| `lib/legion/extensions/kerberos/helpers/ldap.rb` | LDAP group lookup + profile via `net-ldap`; `lookup_groups` returns groups + org attributes via `PROFILE_MAP` |
| `lib/legion/extensions/kerberos/helpers/keytab.rb` | Multi-source keytab resolution; vault:// URI, file path, Base64 blob; writes to `~/.legionio/kerberos/legion.keytab` |
| `lib/legion/extensions/kerberos/helpers/client.rb` | `DEFAULTS` constant and `settings` method that merges with `Legion::Settings[:kerberos]` |
| `lib/legion/extensions/kerberos/runners/authenticate.rb` | `validate_spnego` runner: orchestrates keytab resolve → SPNEGO accept → optional LDAP lookup |
| `lib/legion/extensions/kerberos/actors/keytab_refresh.rb` | Hourly actor that calls `resolve_keytab` to re-cache from Vault; `run_now? false` (no immediate run at boot) |
| `lib/legion/extensions/kerberos/client.rb` | Standalone `Client` class with `authenticate(token:)` and `resolve_groups(username:)` |
| `lib/legion/extensions/kerberos/version.rb` | `VERSION = '0.1.2'` |

## Key Patterns

### GSSAPI Token Acceptance

`Helpers::Spnego#accept_spnego_token` decodes the Base64 SPNEGO token from the HTTP `Authorization: Negotiate` header, sets `KRB5_KTNAME` env var to the keytab path, then uses `GSSAPI::Simple.new(host, service)` to accept the security context. Returns `{ success:, principal:, username:, realm:, output_token: }`.

The service principal must be split as `service/host` (e.g., `HTTP/myapp.example.com`) — `GSSAPI::Simple` takes host and service name separately.

### Keytab Resolution

`Helpers::Keytab#resolve_keytab(sources:)` tries each source in order:
1. `vault://` URI — resolved via `Legion::Settings::Resolver.resolve_value`, then written as Base64 to cache
2. File path — used as-is if `File.exist?`
3. Base64 blob — decoded and written to `~/.legionio/kerberos/legion.keytab` (mode `0600`)

Returns `{ success: true, path:, source: (:file | :base64) }` or `{ success: false, error: }`.

### LDAP Group Lookup

`Helpers::Ldap#lookup_groups` builds a `Net::LDAP` client with TLS, binds with the service account, and searches by `sAMAccountName` filter (format string `%<username>s`). Returns the full DN strings from the `memberOf` attribute (configurable via `group_attribute:`).

Requires `host:` in the ldap opts; if absent, `Runners::Authenticate` skips group lookup and returns an empty array.

### Standalone Client Pattern

`Client.new` accepts `realm:`, `service_principal:`, `keytab:`, and `**opts` (where `opts[:ldap]` is passed to group lookup). Falls back to `settings[:kerberos]` defaults when kwargs are nil. Includes all four helpers. `authenticate(token:)` and `resolve_groups(username:)` are the primary interface methods.

## Settings Reference

```json
{
  "kerberos": {
    "enabled": true,
    "realm": "EXAMPLE.COM",
    "service_principal": "HTTP/myapp.example.com",
    "keytab": ["vault://secret/kerberos#keytab", "/etc/legion/krb5.keytab"],
    "mutual_auth": true,
    "ldap": {
      "host": "dc.example.com",
      "port": 636,
      "encryption": "simple_tls",
      "base_dn": "DC=example,DC=com",
      "bind_dn": "CN=svc-legion,OU=Service Accounts,DC=example,DC=com",
      "bind_password": "vault://secret/kerberos/ldap_bind#password",
      "user_filter": "(sAMAccountName=%<username>s)",
      "group_attribute": "memberOf"
    },
    "role_map": {},
    "fallback": "entra",
    "cache_groups_ttl": 300
  }
}
```

Defaults defined in `Helpers::Client::DEFAULTS`. `settings` method merges `Legion::Settings[:kerberos]` on top when available, returning the full merged hash under `:kerberos`.

## Dependencies

| Gem | Purpose |
|-----|---------|
| `gssapi` (~> 1.3) | GSSAPI/SPNEGO token validation; requires system MIT Kerberos libraries (`krb5`) |
| `net-ldap` (~> 0.19) | LDAP group lookup against Active Directory |

Optional framework dependencies (guarded with `defined?`, not in gemspec):
- `legion-settings` — `Legion::Settings::Resolver` for `vault://` keytab URI resolution
- `legion-logging` — logging in `KeytabRefresh` actor

## Testing

```bash
bundle install
bundle exec rspec     # 43 specs, 91.67% coverage
bundle exec rubocop   # Clean
```

---

**Maintained By**: Matthew Iverson (@Esity)
