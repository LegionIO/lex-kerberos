# frozen_string_literal: true

require 'spec_helper'

# Stub the base class for standalone spec loading
unless defined?(Legion::Extensions::Actors::Every)
  module Legion
    module Extensions
      module Actors
        class Every
          def initialize(**); end
        end
      end
    end
  end
  $LOADED_FEATURES << 'legion/extensions/actors/every.rb'
end

require 'legion/extensions/kerberos/actors/keytab_refresh'

RSpec.describe Legion::Extensions::Kerberos::Actor::KeytabRefresh do
  subject(:actor) { described_class.allocate }

  describe 'configuration' do
    it 'has a 1-hour refresh interval' do
      expect(actor.time).to eq(3600)
    end

    it 'does not run immediately' do
      expect(actor.run_now?).to be false
    end

    it 'does not use the framework runner dispatch' do
      expect(actor.use_runner?).to be false
    end

    it 'does not check subtasks' do
      expect(actor.check_subtask?).to be false
    end

    it 'does not generate tasks' do
      expect(actor.generate_task?).to be false
    end
  end

  describe '#enabled?' do
    it 'returns truthy when Keytab helper is defined' do
      expect(actor.enabled?).to be_truthy
    end
  end

  describe '#manual' do
    it 'does not raise with no configured sources' do
      expect { actor.manual }.not_to raise_error
    end

    it 'does not raise when resolve_keytab returns a failure hash' do
      helper = Object.new.extend(Legion::Extensions::Kerberos::Helpers::Keytab)
      allow(helper).to receive(:resolve_keytab)
        .and_return({ success: false, error: 'no valid keytab source found' })
      allow(actor).to receive(:manual).and_call_original
      expect { actor.manual }.not_to raise_error
    end
  end
end
