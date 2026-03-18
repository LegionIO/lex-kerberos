# frozen_string_literal: true

require 'spec_helper'
require 'legion/extensions/kerberos/runners/authenticate'

RSpec.describe Legion::Extensions::Kerberos::Runners::Authenticate do
  let(:dummy) { Object.new.extend(described_class) }

  let(:spnego_result) do
    { success: true, principal: 'miverso2@MS.DS.UHC.COM',
      username: 'miverso2', realm: 'MS.DS.UHC.COM',
      output_token: 'base64output' }
  end

  let(:ldap_result) do
    { success: true, groups: ['CN=Legion-Admins,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com'],
      username: 'miverso2' }
  end

  before do
    allow(dummy).to receive(:resolve_keytab)
      .and_return({ success: true, path: '/tmp/test.keytab', source: :file })
    allow(dummy).to receive(:accept_spnego_token).and_return(spnego_result)
    allow(dummy).to receive(:lookup_groups).and_return(ldap_result)
  end

  describe '#validate_spnego' do
    it 'validates a SPNEGO token and returns principal with groups' do
      result = dummy.validate_spnego(
        token: 'fake-token',
        keytab: ['/tmp/test.keytab'],
        service_principal: 'HTTP/legion.uhg.com',
        ldap: { host: 'ldap.example.com', base_dn: 'DC=example,DC=com',
                bind_dn: 'CN=svc', bind_password: 'secret' }
      )
      expect(result[:result][:principal]).to eq('miverso2@MS.DS.UHC.COM')
      expect(result[:result][:username]).to eq('miverso2')
      expect(result[:result][:groups]).to include('CN=Legion-Admins,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com')
      expect(result[:result][:auth_method]).to eq('kerberos')
      expect(result[:result][:success]).to be true
    end

    context 'when keytab resolution fails' do
      before do
        allow(dummy).to receive(:resolve_keytab)
          .and_return({ success: false, error: 'no valid keytab source found' })
      end

      it 'returns the keytab error' do
        result = dummy.validate_spnego(token: 'x', keytab: ['/bad'])
        expect(result[:result][:success]).to be false
      end
    end

    context 'when SPNEGO validation fails' do
      before do
        allow(dummy).to receive(:accept_spnego_token)
          .and_return({ success: false, error: 'bad token' })
      end

      it 'returns the SPNEGO error' do
        result = dummy.validate_spnego(token: 'bad', keytab: ['/tmp/k'],
                                       service_principal: 'HTTP/h')
        expect(result[:result][:success]).to be false
        expect(result[:result][:error]).to include('bad token')
      end
    end

    context 'when LDAP lookup fails' do
      before do
        allow(dummy).to receive(:lookup_groups)
          .and_return({ success: false, error: 'LDAP unreachable' })
      end

      it 'returns principal with empty groups and ldap_error' do
        result = dummy.validate_spnego(
          token: 'fake-token',
          keytab: ['/tmp/test.keytab'],
          service_principal: 'HTTP/legion.uhg.com',
          ldap: { host: 'ldap.example.com', base_dn: 'DC=example,DC=com',
                  bind_dn: 'CN=svc', bind_password: 'secret' }
        )
        expect(result[:result][:principal]).to eq('miverso2@MS.DS.UHC.COM')
        expect(result[:result][:groups]).to be_empty
        expect(result[:result][:ldap_error]).to include('LDAP unreachable')
      end
    end

    context 'when no LDAP host configured' do
      it 'skips LDAP and returns empty groups' do
        result = dummy.validate_spnego(
          token: 'fake-token',
          keytab: ['/tmp/test.keytab'],
          service_principal: 'HTTP/legion.uhg.com',
          ldap: {}
        )
        expect(result[:result][:groups]).to be_empty
        expect(result[:result][:success]).to be true
      end
    end
  end
end
