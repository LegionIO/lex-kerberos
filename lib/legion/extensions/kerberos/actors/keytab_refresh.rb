# frozen_string_literal: true

require 'legion/extensions/actors/every'

module Legion
  module Extensions
    module Kerberos
      module Actor
        class KeytabRefresh < Legion::Extensions::Actors::Every # rubocop:disable Legion/Extension/SelfContainedActorRunnerClass, Legion/Extension/EveryActorRequiresTime
          def initialize(**opts)
            return unless enabled?

            super
          end

          def time = 3600
          def run_now? = false
          def use_runner? = false
          def check_subtask? = false
          def generate_task? = false

          def enabled? # rubocop:disable Legion/Extension/ActorEnabledSideEffects
            defined?(Legion::Extensions::Kerberos::Helpers::Keytab)
          rescue StandardError => _e
            false
          end

          def manual
            result = keytab_helper.resolve_keytab(sources: keytab_sources)
            log_result(result)
          rescue StandardError => e
            log.error(e)
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
            if result[:success]
              log.debug("KeytabRefresh: refreshed keytab from #{result[:source]}")
            else
              log.warn("KeytabRefresh: #{result[:error]}")
            end
          end

          def log_error(err)
            log.error("KeytabRefresh: #{err.message}")
          end
        end
      end
    end
  end
end
