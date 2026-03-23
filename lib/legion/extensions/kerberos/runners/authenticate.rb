# frozen_string_literal: true

require 'legion/extensions/kerberos/helpers/spnego'
require 'legion/extensions/kerberos/helpers/ldap'
require 'legion/extensions/kerberos/helpers/keytab'
require 'legion/extensions/kerberos/helpers/client'

module Legion
  module Extensions
    module Kerberos
      module Runners
        module Authenticate
          include Helpers::Spnego
          include Helpers::Ldap
          include Helpers::Keytab
          include Helpers::Client

          def validate_spnego(token:, keytab: nil, service_principal: nil, ldap: nil, **)
            s = kerberos_defaults[:kerberos]
            keytab ||= s[:keytab]
            service_principal ||= s[:service_principal]

            kt = resolve_keytab(sources: keytab)
            return { result: kt } unless kt[:success]

            spnego = accept_spnego_token(token: token, keytab: kt[:path],
                                         service_principal: service_principal)
            return { result: spnego } unless spnego[:success]

            groups, ldap_error, profile = resolve_groups(ldap: ldap, cfg: s, username: spnego[:username])

            { result: build_result(spnego: spnego, groups: groups, ldap_error: ldap_error, profile: profile) }
          end

          def negotiate(headers: {}, **)
            auth_header = headers['HTTP_AUTHORIZATION']
            unless auth_header&.match?(/\ANegotiate\s+/i)
              return negotiate_error('negotiate_required', 'Negotiate token required')
            end

            auth_result = negotiate_authenticate(auth_header.sub(/\ANegotiate\s+/i, ''))
            unless auth_result&.dig(:success)
              return negotiate_error('kerberos_auth_failed', 'Kerberos authentication failed')
            end

            negotiate_success(auth_result)
          end

          private

          def resolve_groups(ldap:, cfg:, username:)
            ldap_opts = ldap || cfg[:ldap] || {}
            return [[], nil, {}] unless ldap_opts[:host]

            result = lookup_groups(username: username, **ldap_opts)
            if result[:success]
              profile = result.slice(:first_name, :last_name, :email, :display_name)
              [result[:groups], nil, profile]
            else
              [[], result[:error], {}]
            end
          end

          def build_result(spnego:, groups:, ldap_error:, profile: {})
            spnego_fields = spnego.slice(:principal, :username, :realm, :output_token)
            { success: true, groups: groups, auth_method: 'kerberos',
              ldap_error: ldap_error, **spnego_fields, **profile }.compact
          end

          def negotiate_authenticate(token)
            Client.new.authenticate(token: token)
          rescue StandardError
            nil
          end

          def negotiate_error(code, message)
            body = negotiate_json({ error: { code: code, message: message },
                                    meta: { timestamp: Time.now.utc.iso8601 } })
            {
              result: { error: code },
              response: { status: 401, content_type: 'application/json',
                          headers: { 'WWW-Authenticate' => 'Negotiate' }, body: body }
            }
          end

          def negotiate_success(auth_result)
            profile = auth_result.slice(:first_name, :last_name, :email, :display_name)
            token, roles = issue_negotiate_token(auth_result, profile)
            data = { token: token, principal: auth_result[:principal],
                     roles: roles, auth_method: 'kerberos', **profile }.compact
            negotiate_success_response(auth_result, data)
          end

          def negotiate_success_response(auth_result, data)
            hdrs = ({ 'WWW-Authenticate' => "Negotiate #{auth_result[:output_token]}" } if auth_result[:output_token])
            body = negotiate_json({ data: data, meta: { timestamp: Time.now.utc.iso8601 } })
            { result: data,
              response: { status: 200, content_type: 'application/json',
                          headers: hdrs, body: body }.compact }
          end

          def issue_negotiate_token(auth_result, profile)
            return [nil, []] unless defined?(Legion::Rbac::KerberosClaimsMapper) && defined?(Legion::API::Token)

            mapped = map_negotiate_claims(auth_result, profile)
            display = mapped[:display_name] || mapped[:first_name]
            token = Legion::API::Token.issue_human_token(
              msid: mapped[:sub], name: display, roles: mapped[:roles], ttl: 28_800
            )
            [token, mapped[:roles]]
          rescue StandardError
            [nil, []]
          end

          def map_negotiate_claims(auth_result, profile)
            role_map = defined?(Legion::Settings) ? (Legion::Settings.dig(:kerberos, :role_map) || {}) : {}
            Legion::Rbac::KerberosClaimsMapper.map_with_fallback(
              principal: auth_result[:principal], groups: auth_result[:groups] || [],
              role_map: role_map, **profile
            )
          end

          def negotiate_json(hash)
            return Legion::JSON.dump(hash) if defined?(Legion::JSON)

            require 'json'
            ::JSON.generate(hash)
          end

          include Legion::Extensions::Helpers::Lex if Legion::Extensions.const_defined?(:Helpers) &&
                                                      Legion::Extensions::Helpers.const_defined?(:Lex)
        end
      end
    end
  end
end
