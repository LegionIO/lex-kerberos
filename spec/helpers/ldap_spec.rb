# frozen_string_literal: true

require 'spec_helper'
require 'net-ldap'
require 'legion/extensions/kerberos/helpers/ldap'

RSpec.describe Legion::Extensions::Kerberos::Helpers::Ldap do
  let(:dummy) { Object.new.extend(described_class) }
  let(:mock_ldap) { instance_double(Net::LDAP) }

  before do
    allow(Net::LDAP).to receive(:new).and_return(mock_ldap)
    allow(mock_ldap).to receive(:bind).and_return(true)
  end

  let(:default_opts) do
    {
      username: 'miverso2',
      host: 'ldap.ms.ds.uhc.com', port: 636, encryption: :simple_tls,
      base_dn: 'DC=ms,DC=ds,DC=uhc,DC=com',
      bind_dn: 'CN=svc,DC=ms,DC=ds,DC=uhc,DC=com',
      bind_password: 'secret'
    }
  end

  describe '#lookup_groups' do
    context 'when user has groups' do
      let(:ldap_entry) do
        entry = Net::LDAP::Entry.new('CN=miverso2,OU=Users,DC=ms,DC=ds,DC=uhc,DC=com')
        entry['memberOf'] = [
          'CN=Legion-Admins,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com',
          'CN=All-Users,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com'
        ]
        entry
      end

      before { allow(mock_ldap).to receive(:search).and_yield(ldap_entry) }

      it 'returns group DNs for a username' do
        result = dummy.lookup_groups(**default_opts)
        expect(result[:success]).to be true
        expect(result[:groups]).to include('CN=Legion-Admins,OU=Groups,DC=ms,DC=ds,DC=uhc,DC=com')
        expect(result[:groups].length).to eq(2)
        expect(result[:username]).to eq('miverso2')
      end
    end

    context 'when LDAP bind fails' do
      before { allow(mock_ldap).to receive(:bind).and_return(false) }

      it 'returns failure' do
        result = dummy.lookup_groups(**default_opts)
        expect(result[:success]).to be false
        expect(result[:error]).to include('bind failed')
      end
    end

    context 'when user not found' do
      before { allow(mock_ldap).to receive(:search) }

      it 'returns empty groups' do
        result = dummy.lookup_groups(**default_opts, username: 'nobody')
        expect(result[:success]).to be true
        expect(result[:groups]).to be_empty
      end
    end

    context 'when LDAP raises an error' do
      before { allow(mock_ldap).to receive(:bind).and_raise(Net::LDAP::Error, 'connection refused') }

      it 'returns failure with error message' do
        result = dummy.lookup_groups(**default_opts)
        expect(result[:success]).to be false
        expect(result[:error]).to include('connection refused')
      end
    end
  end
end
