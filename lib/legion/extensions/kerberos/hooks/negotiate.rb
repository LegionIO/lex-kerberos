# frozen_string_literal: true

module Legion
  module Extensions
    module Kerberos
      module Hooks
        class Negotiate < Legion::Extensions::Hooks::Base
          def route(_headers, _payload)
            :negotiate
          end

          def runner_class
            'Legion::Extensions::Kerberos::Runners::Authenticate'
          end
        end
      end
    end
  end
end
