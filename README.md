# lex-kerberos

Kerberos/SPNEGO authentication integration for [LegionIO](https://github.com/LegionIO/LegionIO). Validates SPNEGO tokens via GSSAPI, resolves LDAP group membership, and manages keytab files with Vault-primary, file-fallback sourcing.

## Installation

```ruby
gem 'lex-kerberos'
```

Or install directly:

```bash
gem install lex-kerberos
```

## Prerequisites

- MIT Kerberos libraries (`krb5`) installed on the host (`brew install krb5` / `apt install libkrb5-dev`)
- A keytab file for the service principal (see [Keytab Provisioning](#keytab-provisioning))
- Active Directory / Kerberos realm reachable from the host
- For LDAP group resolution: an LDAP bind account with read access to the directory

## Configuration

Settings live under `Legion::Settings[:kerberos]`:

```json
{
  "kerberos": {
    "enabled": true,
    "realm": "EXAMPLE.COM",
    "service_principal": "HTTP/myapp.example.com",
    "keytab": [
      "vault://secret/kerberos/keytab#data",
      "/etc/legion/krb5.keytab"
    ],
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

The `keytab` value is an array of sources tried in order. Each source can be:
- A `vault://` URI resolved via `Legion::Settings::Resolver`
- An absolute file path (used as-is if the file exists)
- A Base64-encoded keytab blob written to `~/.legionio/kerberos/legion.keytab`

## Standalone Usage

Use the gem outside the LegionIO framework:

```ruby
require 'legion/extensions/kerberos'

client = Legion::Extensions::Kerberos::Client.new(
  realm:             'EXAMPLE.COM',
  service_principal: 'HTTP/myapp.example.com',
  keytab:            ['/etc/legion/krb5.keytab'],
  ldap: {
    host:          'dc.example.com',
    port:          636,
    encryption:    :simple_tls,
    base_dn:       'DC=example,DC=com',
    bind_dn:       'CN=svc-legion,OU=Service Accounts,DC=example,DC=com',
    bind_password: 'password'
  }
)

# Validate a SPNEGO token from an HTTP Negotiate header
authorization_header = request.env['HTTP_AUTHORIZATION']
token = authorization_header.delete_prefix('Negotiate ')
result = client.authenticate(token: token)
# => { success: true, principal: "user@EXAMPLE.COM", username: "user",
#      realm: "EXAMPLE.COM", output_token: "...", ... }

# Resolve LDAP groups and profile for a username
groups = client.resolve_groups(username: 'user')
# => { success: true, groups: ["CN=Domain Users,..."], username: "user",
#      first_name: "Jane", last_name: "Doe", email: "jane.doe@example.com",
#      title: "Senior Engineer", department: "Platform Engineering",
#      company: "Example Corp", city: "Minneapolis", state: "MN", country: "USA" }
```

### Using helpers directly

```ruby
helper = Object.new.extend(Legion::Extensions::Kerberos::Helpers::Spnego)
result = helper.accept_spnego_token(
  token:             token,
  keytab:            '/etc/legion/krb5.keytab',
  service_principal: 'HTTP/myapp.example.com'
)

keytab_helper = Object.new.extend(Legion::Extensions::Kerberos::Helpers::Keytab)
kt = keytab_helper.resolve_keytab(sources: ['/etc/legion/krb5.keytab'])
# => { success: true, path: "/etc/legion/krb5.keytab", source: :file }
```

## CLI Usage

When running within LegionIO with the `legion-crypt` Vault Kerberos auth integration:

```bash
legion auth kerberos
```

This uses the configured service principal and keytab to authenticate via Vault's Kerberos auth method.

## API Usage

When the LegionIO REST API is running, the Negotiate challenge/response endpoint is available via the auto-discovered hook:

```
GET /api/hooks/lex/kerberos/negotiate
Authorization: Negotiate <base64-spnego-token>
```

Successful response:

```json
{
  "success": true,
  "principal": "user@EXAMPLE.COM",
  "username": "user",
  "realm": "EXAMPLE.COM",
  "groups": ["CN=Domain Users,DC=example,DC=com"],
  "auth_method": "kerberos"
}
```

## Vault Integration

Store the keytab as a Base64-encoded secret in Vault:

```bash
base64 -i /etc/legion/krb5.keytab | vault kv put secret/kerberos keytab=-
```

Configure lex-kerberos to resolve it:

```json
{
  "kerberos": {
    "keytab": ["vault://secret/kerberos#keytab", "/etc/legion/krb5.keytab"]
  }
}
```

The Vault URI is resolved via `Legion::Settings::Resolver`. The keytab bytes are written to `~/.legionio/kerberos/legion.keytab` with permissions `0600` and used for the current session. The `KeytabRefresh` actor runs hourly to re-fetch the keytab from Vault, ensuring the cached file stays current when Vault secrets are rotated.

## Keytab Provisioning

Create a keytab for a Windows AD service principal using `ktpass` on a domain controller:

```cmd
ktpass -princ HTTP/myapp.example.com@EXAMPLE.COM ^
       -mapuser svc-legion@EXAMPLE.COM ^
       -crypto AES256-SHA1 ^
       -ptype KRB5_NT_PRINCIPAL ^
       -pass * ^
       -out legion.keytab
```

Verify the keytab:

```bash
klist -k -t /etc/legion/krb5.keytab
```

Ensure `/etc/krb5.conf` references the correct realm and KDC:

```ini
[libdefaults]
  default_realm = EXAMPLE.COM

[realms]
  EXAMPLE.COM = {
    kdc = kdc.example.com
    admin_server = kdc.example.com
  }
```

## Requirements

- Ruby >= 3.4
- [LegionIO](https://github.com/LegionIO/LegionIO) framework (optional for standalone client usage)
- `gssapi` ~> 1.3 (MIT Kerberos system libraries required)
- `net-ldap` ~> 0.19

## License

MIT
