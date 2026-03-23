# frozen_string_literal: true

module Legion
  module Extensions
    module Kerberos
      module Helpers
        module Client
          DEFAULTS = {
            kerberos: {
              enabled: true,
              realm: 'MS.DS.UHC.COM',
              service_principal: 'HTTP/legion.uhg.com',
              keytab: ['/etc/legion/krb5.keytab'],
              mutual_auth: true,
              ldap: {
                port: 636, encryption: :simple_tls,
                group_attribute: 'memberOf',
                user_filter: '(sAMAccountName=%<username>s)'
              },
              role_map: {},
              fallback: :entra,
              cache_groups_ttl: 300
            }
          }.freeze

          def kerberos_defaults
            if defined?(Legion::Settings) && Legion::Settings.respond_to?(:dig)
              krb = Legion::Settings[:kerberos] || {}
              { kerberos: DEFAULTS[:kerberos].merge(krb) }
            else
              DEFAULTS
            end
          end
        end
      end
    end
  end
end
