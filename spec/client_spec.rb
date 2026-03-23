# frozen_string_literal: true

require 'spec_helper'
require 'legion/extensions/kerberos/client'

RSpec.describe Legion::Extensions::Kerberos::Client do
  describe '#initialize' do
    it 'uses default realm when none provided' do
      client = described_class.new
      expect(client.realm).to eq('MS.DS.UHC.COM')
    end

    it 'accepts custom realm' do
      client = described_class.new(realm: 'TEST.REALM')
      expect(client.realm).to eq('TEST.REALM')
    end

    it 'accepts custom service principal' do
      client = described_class.new(service_principal: 'HTTP/test.example.com')
      expect(client.service_principal).to eq('HTTP/test.example.com')
    end

    it 'accepts custom keytab sources' do
      client = described_class.new(keytab: ['/tmp/test.keytab'])
      expect(client.keytab_sources).to eq(['/tmp/test.keytab'])
    end
  end

  describe '#authenticate' do
    let(:client) { described_class.new(keytab: ['/tmp/test.keytab']) }

    context 'when keytab resolution fails' do
      before do
        allow(client).to receive(:resolve_keytab)
          .and_return({ success: false, error: 'no valid keytab source found' })
      end

      it 'returns the keytab error' do
        result = client.authenticate(token: 'fake')
        expect(result[:success]).to be false
        expect(result[:error]).to include('keytab')
      end
    end

    context 'when keytab resolves and SPNEGO succeeds' do
      before do
        allow(client).to receive(:resolve_keytab)
          .and_return({ success: true, path: '/tmp/test.keytab', source: :file })
        allow(client).to receive(:accept_spnego_token)
          .and_return({ success: true, principal: 'miverso2@MS.DS.UHC.COM',
                        username: 'miverso2', realm: 'MS.DS.UHC.COM',
                        output_token: 'resp' })
      end

      it 'returns the SPNEGO result' do
        result = client.authenticate(token: 'fake-token')
        expect(result[:success]).to be true
        expect(result[:principal]).to eq('miverso2@MS.DS.UHC.COM')
      end
    end
  end

  describe 'includes all helpers' do
    let(:client) { described_class.new }

    it { expect(client).to respond_to(:accept_spnego_token) }
    it { expect(client).to respond_to(:lookup_groups) }
    it { expect(client).to respond_to(:resolve_keytab) }
    it { expect(client).to respond_to(:kerberos_defaults) }
  end
end
