# frozen_string_literal: true

require 'net-ldap'

module Legion
  module Extensions
    module Kerberos
      module Helpers
        module Ldap
          USER_ATTRIBUTES = %w[memberOf givenName sn mail displayName].freeze

          def lookup_groups(username:, host:, base_dn:, bind_dn:, bind_password:,
                            port: 636, encryption: :simple_tls,
                            user_filter: '(sAMAccountName=%<username>s)',
                            group_attribute: 'memberOf', **)
            ldap = build_ldap_client(host: host, port: port, encryption: encryption,
                                     bind_dn: bind_dn, bind_password: bind_password)
            return { success: false, error: 'LDAP bind failed' } unless ldap.bind

            search_user(ldap: ldap, username: username, base_dn: base_dn,
                        user_filter: user_filter, group_attribute: group_attribute)
          rescue Net::LDAP::Error => e
            { success: false, error: "LDAP error: #{e.message}" }
          end

          private

          def build_ldap_client(host:, port:, encryption:, bind_dn:, bind_password:)
            Net::LDAP.new(
              host: host, port: port,
              encryption: { method: encryption },
              auth: { method: :simple, username: bind_dn, password: bind_password }
            )
          end

          def search_user(ldap:, username:, base_dn:, user_filter:, group_attribute:)
            filter = Net::LDAP::Filter.construct(format(user_filter, username: username))
            groups = []
            profile = {}
            ldap.search(base: base_dn, filter: filter, attributes: USER_ATTRIBUTES) do |entry|
              groups.concat(Array(entry[group_attribute]).map(&:to_s))
              profile = extract_profile(entry)
            end
            { success: true, groups: groups, username: username, **profile }
          end

          def extract_profile(entry)
            { first_name: :givenname, last_name: :sn, email: :mail, display_name: :displayname }
              .transform_values { |attr| entry[attr]&.first&.to_s }
              .compact
          end
        end
      end
    end
  end
end
