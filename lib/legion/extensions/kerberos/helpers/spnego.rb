# frozen_string_literal: true

require 'gssapi'
require 'base64'

module Legion
  module Extensions
    module Kerberos
      module Helpers
        module Spnego
          def accept_spnego_token(token:, keytab:, service_principal:, _mutual_auth: true, **)
            ENV['KRB5_KTNAME'] = keytab if keytab

            input_bytes = Base64.strict_decode64(token)
            principal, output_bytes = negotiate(input_bytes, service_principal)
            build_token_result(principal, output_bytes)
          rescue GSSAPI::GssApiError => e
            { success: false, error: e.message }
          rescue ArgumentError => e
            { success: false, error: "token decode failed: #{e.message}" }
          end

          def extract_username(principal)
            principal.split('@', 2).first
          end

          def extract_realm(principal)
            parts = principal.split('@', 2)
            parts.length > 1 ? parts.last : nil
          end

          def obtain_spnego_token(service_principal:)
            unless service_principal.include?('/')
              return { success: false, error: "service_principal must contain '/'" }
            end

            token_bytes = init_spnego_context(service_principal)
            { success: true, token: Base64.strict_encode64(token_bytes) }
          rescue GSSAPI::GssApiError => e
            { success: false, error: e.message }
          end

          private

          def init_spnego_context(service_principal)
            service, host = service_principal.split('/', 2)
            ctx = GSSAPI::Simple.new(host, service)
            token_bytes = ctx.init_context
            raise GSSAPI::GssApiError, 'init_context returned nil token' if token_bytes.nil?

            # Prevent macOS Heimdal segfault in gss_release_name during GC (FFI autopointer finalizer).
            disable_gssapi_finalizers(ctx) if RUBY_PLATFORM.include?('darwin')
            token_bytes
          end

          def disable_gssapi_finalizers(ctx)
            %i[@int_svc_name @context @scred].each do |ivar|
              ptr = ctx.instance_variable_get(ivar)
              ptr.autorelease = false if ptr.respond_to?(:autorelease=)
            end
          rescue StandardError # rubocop:disable Lint/SuppressedException
          end

          def negotiate(input_bytes, service_principal)
            service, host = service_principal.split('/', 2)
            ctx = GSSAPI::Simple.new(host, service)
            ctx.acquire_credentials
            output_bytes = ctx.accept_context(input_bytes)
            [ctx.display_name, output_bytes]
          end

          def build_token_result(principal, output_bytes)
            {
              success: true,
              principal: principal,
              output_token: output_bytes ? Base64.strict_encode64(output_bytes) : nil,
              username: extract_username(principal),
              realm: extract_realm(principal)
            }
          end
        end
      end
    end
  end
end
