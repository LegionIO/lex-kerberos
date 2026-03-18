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

            groups, ldap_error = resolve_groups(ldap: ldap, cfg: s, username: spnego[:username])

            { result: build_result(spnego: spnego, groups: groups, ldap_error: ldap_error) }
          end

          private

          def resolve_groups(ldap:, cfg:, username:)
            ldap_opts = ldap || cfg[:ldap] || {}
            if ldap_opts[:host]
              groups_result = lookup_groups(username: username, **ldap_opts)
              groups = groups_result[:success] ? groups_result[:groups] : []
              ldap_error = groups_result[:success] ? nil : groups_result[:error]
            else
              groups = []
              ldap_error = nil
            end
            [groups, ldap_error]
          end

          def build_result(spnego:, groups:, ldap_error:)
            {
              success: true,
              principal: spnego[:principal],
              username: spnego[:username],
              realm: spnego[:realm],
              groups: groups,
              output_token: spnego[:output_token],
              auth_method: 'kerberos',
              ldap_error: ldap_error
            }.compact
          end

          include Legion::Extensions::Helpers::Lex if Legion::Extensions.const_defined?(:Helpers) &&
                                                      Legion::Extensions::Helpers.const_defined?(:Lex)
        end
      end
    end
  end
end
