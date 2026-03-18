# frozen_string_literal: true

require 'legion/extensions/kerberos/version'

module Legion
  module Extensions
    module Kerberos
      extend Legion::Extensions::Core if Legion::Extensions.const_defined? :Core
    end
  end
end
