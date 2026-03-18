# frozen_string_literal: true

require 'base64'
require 'fileutils'

module Legion
  module Extensions
    module Kerberos
      module Helpers
        module Keytab
          DEFAULT_CACHE_DIR = File.join(Dir.home, '.legionio', 'kerberos')

          def resolve_keytab(sources:, cache_dir: DEFAULT_CACHE_DIR, **)
            Array(sources).each do |source|
              next if source.nil? || source.to_s.empty?

              result = resolve_source(source, cache_dir)
              return result if result
            end

            { success: false, error: 'no valid keytab source found' }
          end

          private

          def resolve_source(source, cache_dir)
            return resolve_vault_source(source, cache_dir) if vault_uri?(source)
            return { success: true, path: source, source: :file } if File.exist?(source)
            return write_keytab_cache(source, cache_dir) if base64?(source)

            nil
          end

          def vault_uri?(source)
            source.start_with?('vault://') &&
              defined?(Legion::Settings) &&
              defined?(Legion::Settings::Resolver)
          end

          def resolve_vault_source(source, cache_dir)
            resolved = Legion::Settings::Resolver.resolve_value(source)
            return nil unless resolved

            write_keytab_cache(resolved, cache_dir)
          end

          def base64?(str)
            str.match?(%r{\A[A-Za-z0-9+/\n]+=*\n?\z}) && str.length > 20
          end

          def write_keytab_cache(base64_data, cache_dir)
            FileUtils.mkdir_p(cache_dir)
            path = File.join(cache_dir, 'legion.keytab')
            File.binwrite(path, Base64.strict_decode64(base64_data.strip))
            File.chmod(0o600, path)
            { success: true, path: path, source: :base64 }
          rescue ArgumentError => e
            { success: false, error: "keytab decode failed: #{e.message}" }
          end
        end
      end
    end
  end
end
