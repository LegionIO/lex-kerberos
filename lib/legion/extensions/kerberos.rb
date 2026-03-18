# frozen_string_literal: true

require 'legion/extensions/kerberos/version'
require 'legion/extensions/kerberos/helpers/ldap'
require 'legion/extensions/kerberos/helpers/keytab'
require 'legion/extensions/kerberos/helpers/spnego'

module Legion
  module Extensions
    module Kerberos
      extend Legion::Extensions::Core if Legion::Extensions.const_defined? :Core
    end
  end
end
