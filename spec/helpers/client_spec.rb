# frozen_string_literal: true

require 'spec_helper'
require 'legion/extensions/kerberos/helpers/client'

RSpec.describe Legion::Extensions::Kerberos::Helpers::Client do
  let(:dummy) { Object.new.extend(described_class) }

  describe '#kerberos_defaults' do
    it 'returns default settings with kerberos key' do
      s = dummy.kerberos_defaults
      expect(s[:kerberos]).to be_a(Hash)
      expect(s[:kerberos][:realm]).to eq('MS.DS.UHC.COM')
      expect(s[:kerberos][:mutual_auth]).to be true
      expect(s[:kerberos][:service_principal]).to eq('HTTP/legion.uhg.com')
    end

    it 'includes LDAP defaults' do
      ldap = dummy.kerberos_defaults[:kerberos][:ldap]
      expect(ldap[:port]).to eq(636)
      expect(ldap[:encryption]).to eq(:simple_tls)
      expect(ldap[:group_attribute]).to eq('memberOf')
    end
  end
end
