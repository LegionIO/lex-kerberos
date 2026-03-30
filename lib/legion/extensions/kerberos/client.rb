# frozen_string_literal: true

require 'legion/extensions/kerberos/helpers/client'
require 'legion/extensions/kerberos/helpers/spnego'
require 'legion/extensions/kerberos/helpers/ldap'
require 'legion/extensions/kerberos/helpers/keytab'

module Legion
  module Extensions
    module Kerberos
      class Client
        include Helpers::Client
        include Helpers::Spnego
        include Helpers::Ldap
        include Helpers::Keytab

        attr_reader :realm, :service_principal, :keytab_sources, :opts

        def initialize(realm: nil, service_principal: nil, keytab: nil, **opts)
          defaults = kerberos_defaults[:kerberos]
          @realm = realm || defaults[:realm]
          @service_principal = service_principal || defaults[:service_principal]
          @keytab_sources = keytab || defaults[:keytab]
          @opts = opts
        end

        def authenticate(token:)
          kt = resolve_keytab(sources: @keytab_sources)
          return kt unless kt[:success]

          accept_spnego_token(
            token:             token,
            keytab:            kt[:path],
            service_principal: @service_principal
          )
        end

        def resolve_groups(username:)
          ldap_opts = @opts[:ldap] || kerberos_defaults[:kerberos][:ldap] || {}
          lookup_groups(username: username, **ldap_opts)
        end
      end
    end
  end
end
