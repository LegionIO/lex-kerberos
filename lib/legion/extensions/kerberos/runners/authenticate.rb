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
            s = settings[:kerberos]
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

          include Legion::Extensions::Helpers::Lex if Legion::Extensions.const_defined?(:Helpers) &&
                                                      Legion::Extensions::Helpers.const_defined?(:Lex)
        end
      end
    end
  end
end
