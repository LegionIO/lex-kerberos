# frozen_string_literal: true

require 'legion/extensions/actors/every' if defined?(Legion::Extensions::Actors)

module Legion
  module Extensions
    module Kerberos
      module Actor
        class KeytabRefresh < Legion::Extensions::Actors::Every
          def initialize(**opts)
            return unless enabled?

            super
          end

          def time = 3600
          def run_now? = false
          def use_runner? = false
          def check_subtask? = false
          def generate_task? = false

          def enabled?
            defined?(Legion::Extensions::Kerberos::Helpers::Keytab)
          rescue StandardError
            false
          end

          def manual
            result = keytab_helper.resolve_keytab(sources: keytab_sources)
            log_result(result)
          rescue StandardError => e
            log_error(e)
          end

          private

          def keytab_helper
            Object.new.extend(Legion::Extensions::Kerberos::Helpers::Keytab)
          end

          def keytab_sources
            return [] unless defined?(Legion::Settings)

            Legion::Settings.dig(:kerberos, :keytab) || []
          end

          def log_result(result)
            return unless defined?(Legion::Logging)

            if result[:success]
              Legion::Logging.debug("KeytabRefresh: refreshed keytab from #{result[:source]}")
            else
              Legion::Logging.warn("KeytabRefresh: #{result[:error]}")
            end
          end

          def log_error(err)
            Legion::Logging.error("KeytabRefresh: #{err.message}") if defined?(Legion::Logging)
          end
        end
      end
    end
  end
end
