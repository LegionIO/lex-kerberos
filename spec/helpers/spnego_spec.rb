# frozen_string_literal: true

require 'spec_helper'
require 'legion/extensions/kerberos/helpers/spnego'

RSpec.describe Legion::Extensions::Kerberos::Helpers::Spnego do
  let(:dummy) { Object.new.extend(described_class) }
  let(:mock_context) { instance_double('GSSAPI::Simple') }

  before do
    allow(GSSAPI::Simple).to receive(:new).and_return(mock_context)
  end

  describe '#accept_spnego_token' do
    context 'with a valid SPNEGO token' do
      let(:input_token) { Base64.strict_encode64('fake-spnego-token') }

      before do
        allow(mock_context).to receive(:acquire_credentials).and_return(true)
        allow(mock_context).to receive(:accept_context).and_return('output-token-bytes')
        allow(mock_context).to receive(:display_name).and_return('miverso2@MS.DS.UHC.COM')
      end

      it 'returns the principal and output token' do
        result = dummy.accept_spnego_token(token: input_token, keytab: '/etc/krb5.keytab',
                                           service_principal: 'HTTP/legion.uhg.com')
        expect(result[:principal]).to eq('miverso2@MS.DS.UHC.COM')
        expect(result[:output_token]).to be_a(String)
        expect(result[:success]).to be true
        expect(result[:username]).to eq('miverso2')
        expect(result[:realm]).to eq('MS.DS.UHC.COM')
      end
    end

    context 'with an invalid token' do
      before do
        allow(mock_context).to receive(:acquire_credentials).and_return(true)
        allow(mock_context).to receive(:accept_context)
          .and_raise(GSSAPI::GssApiError.new('Invalid token'))
      end

      it 'returns failure' do
        result = dummy.accept_spnego_token(token: Base64.strict_encode64('bad'), keytab: '/etc/krb5.keytab',
                                           service_principal: 'HTTP/legion.uhg.com')
        expect(result[:success]).to be false
        expect(result[:error]).to include('Invalid token')
      end
    end

    context 'with malformed base64' do
      it 'returns decode failure' do
        result = dummy.accept_spnego_token(token: '!!!not-base64!!!', keytab: '/etc/krb5.keytab',
                                           service_principal: 'HTTP/legion.uhg.com')
        expect(result[:success]).to be false
        expect(result[:error]).to include('token decode failed')
      end
    end
  end

  describe '#extract_username' do
    it 'strips the realm from a principal' do
      expect(dummy.extract_username('miverso2@MS.DS.UHC.COM')).to eq('miverso2')
    end

    it 'returns the full string if no realm' do
      expect(dummy.extract_username('miverso2')).to eq('miverso2')
    end
  end

  describe '#extract_realm' do
    it 'returns the realm from a principal' do
      expect(dummy.extract_realm('miverso2@MS.DS.UHC.COM')).to eq('MS.DS.UHC.COM')
    end

    it 'returns nil if no realm' do
      expect(dummy.extract_realm('miverso2')).to be_nil
    end
  end

  describe '#obtain_spnego_token' do
    context 'with a valid service principal' do
      before do
        allow(mock_context).to receive(:init_context).and_return('spnego-output-bytes')
      end

      it 'returns success with a base64-encoded token' do
        result = dummy.obtain_spnego_token(service_principal: 'HTTP/vault.example.com')
        expect(result[:success]).to be true
        expect(result[:token]).to eq(Base64.strict_encode64('spnego-output-bytes'))
      end

      it 'splits service_principal and passes host and service to GSSAPI::Simple' do
        expect(GSSAPI::Simple).to receive(:new).with('vault.example.com', 'HTTP').and_return(mock_context)
        dummy.obtain_spnego_token(service_principal: 'HTTP/vault.example.com')
      end
    end

    context 'when GSSAPI raises an error' do
      before do
        allow(mock_context).to receive(:init_context).and_raise(GSSAPI::GssApiError.new('No credentials cache'))
      end

      it 'returns failure with the error message' do
        result = dummy.obtain_spnego_token(service_principal: 'HTTP/vault.example.com')
        expect(result[:success]).to be false
        expect(result[:error]).to include('No credentials cache')
      end
    end

    context 'with a malformed service principal missing /' do
      it 'returns failure without calling GSSAPI' do
        result = dummy.obtain_spnego_token(service_principal: 'HTTP-vault.example.com')
        expect(result[:success]).to be false
        expect(result[:error]).to include("must contain '/'")
        expect(GSSAPI::Simple).not_to have_received(:new)
      end
    end

    context 'when init_context returns nil' do
      before do
        allow(mock_context).to receive(:init_context).and_return(nil)
      end

      it 'returns failure with nil token error' do
        result = dummy.obtain_spnego_token(service_principal: 'HTTP/vault.example.com')
        expect(result[:success]).to be false
        expect(result[:error]).to include('init_context returned nil token')
      end
    end
  end
end
