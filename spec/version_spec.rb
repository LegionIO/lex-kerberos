# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Extensions::Kerberos do
  it 'has a version number' do
    expect(Legion::Extensions::Kerberos::VERSION).to eq('0.3.0')
  end
end
