# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'legion/extensions/kerberos/runners/authenticate'

RSpec.describe 'Runners::Authenticate#negotiate' do
  let(:dummy) { Object.new.extend(Legion::Extensions::Kerberos::Runners::Authenticate) }

  let(:mock_client) { instance_double(Legion::Extensions::Kerberos::Client) }

  let(:successful_auth) do
    { success: true, principal: 'user@EXAMPLE.COM', username: 'user',
      realm: 'EXAMPLE.COM', output_token: 'server-output-base64' }
  end

  before do
    allow(Legion::Extensions::Kerberos::Client).to receive(:new).and_return(mock_client)
  end

  context 'without Authorization header' do
    it 'returns 401 with negotiate_required error' do
      result = dummy.negotiate(headers: {})
      expect(result[:response][:status]).to eq(401)
      expect(result[:result][:error]).to eq('negotiate_required')
    end

    it 'includes WWW-Authenticate: Negotiate header' do
      result = dummy.negotiate(headers: {})
      expect(result[:response][:headers]['WWW-Authenticate']).to eq('Negotiate')
    end
  end

  context 'with non-Negotiate Authorization header' do
    it 'returns 401' do
      result = dummy.negotiate(headers: { 'HTTP_AUTHORIZATION' => 'Bearer some-jwt' })
      expect(result[:response][:status]).to eq(401)
      expect(result[:result][:error]).to eq('negotiate_required')
    end
  end

  context 'with valid Negotiate token' do
    before do
      allow(mock_client).to receive(:authenticate).and_return(successful_auth)
    end

    it 'returns 200 with principal and auth_method' do
      result = dummy.negotiate(headers: { 'HTTP_AUTHORIZATION' => 'Negotiate valid-token' })
      expect(result[:response][:status]).to eq(200)
      expect(result[:result][:principal]).to eq('user@EXAMPLE.COM')
      expect(result[:result][:auth_method]).to eq('kerberos')
    end

    it 'passes the extracted token to Client#authenticate' do
      expect(mock_client).to receive(:authenticate).with(token: 'valid-token')
                                                   .and_return(successful_auth)
      dummy.negotiate(headers: { 'HTTP_AUTHORIZATION' => 'Negotiate valid-token' })
    end

    it 'includes output_token in WWW-Authenticate response header' do
      result = dummy.negotiate(headers: { 'HTTP_AUTHORIZATION' => 'Negotiate valid-token' })
      expect(result[:response][:headers]['WWW-Authenticate']).to eq('Negotiate server-output-base64')
    end

    it 'returns JSON body' do
      result = dummy.negotiate(headers: { 'HTTP_AUTHORIZATION' => 'Negotiate valid-token' })
      body = JSON.parse(result[:response][:body], symbolize_names: true)
      expect(body[:data][:principal]).to eq('user@EXAMPLE.COM')
      expect(body[:data][:auth_method]).to eq('kerberos')
    end
  end

  context 'with invalid Negotiate token' do
    before do
      allow(mock_client).to receive(:authenticate).and_return({ success: false })
    end

    it 'returns 401 with kerberos_auth_failed error' do
      result = dummy.negotiate(headers: { 'HTTP_AUTHORIZATION' => 'Negotiate bad-token' })
      expect(result[:response][:status]).to eq(401)
      expect(result[:result][:error]).to eq('kerberos_auth_failed')
    end
  end

  context 'when Client#authenticate raises an exception' do
    before do
      allow(mock_client).to receive(:authenticate).and_raise(StandardError, 'GSSAPI error')
    end

    it 'returns 401' do
      result = dummy.negotiate(headers: { 'HTTP_AUTHORIZATION' => 'Negotiate bad-token' })
      expect(result[:response][:status]).to eq(401)
    end
  end

  context 'when output_token is nil' do
    before do
      allow(mock_client).to receive(:authenticate)
        .and_return(successful_auth.merge(output_token: nil))
    end

    it 'omits WWW-Authenticate from response headers' do
      result = dummy.negotiate(headers: { 'HTTP_AUTHORIZATION' => 'Negotiate valid-token' })
      expect(result[:response][:headers]).to be_nil
    end
  end
end
