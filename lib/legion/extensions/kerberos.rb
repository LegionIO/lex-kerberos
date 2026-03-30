# frozen_string_literal: true

require 'legion/extensions/kerberos/version'
require 'legion/extensions/kerberos/helpers/spnego'
require 'legion/extensions/kerberos/helpers/ldap'
require 'legion/extensions/kerberos/helpers/keytab'
require 'legion/extensions/kerberos/helpers/client'
require 'legion/extensions/kerberos/runners/authenticate'
require 'legion/extensions/kerberos/actors/keytab_refresh'
require 'legion/extensions/kerberos/client'

module Legion
  module Extensions
    module Kerberos
      extend Legion::Extensions::Core if Legion::Extensions.const_defined? :Core, false
    end
  end
end
