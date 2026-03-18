# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'legion/extensions/kerberos/helpers/keytab'

RSpec.describe Legion::Extensions::Kerberos::Helpers::Keytab do
  let(:dummy) { Object.new.extend(described_class) }
  let(:tmpdir) { Dir.mktmpdir }

  after { FileUtils.remove_entry(tmpdir) }

  describe '#resolve_keytab' do
    context 'with a file path that exists' do
      let(:keytab_path) { File.join(tmpdir, 'test.keytab') }

      before { File.write(keytab_path, 'keytab-data') }

      it 'returns the file path' do
        result = dummy.resolve_keytab(sources: [keytab_path])
        expect(result[:success]).to be true
        expect(result[:path]).to eq(keytab_path)
        expect(result[:source]).to eq(:file)
      end
    end

    context 'with a base64 vault value' do
      it 'decodes and writes to a temp file' do
        encoded = Base64.strict_encode64('keytab-binary-data-here')
        result = dummy.resolve_keytab(sources: [encoded], cache_dir: tmpdir)
        expect(result[:success]).to be true
        expect(File.read(result[:path])).to eq('keytab-binary-data-here')
        expect(result[:source]).to eq(:base64)
      end

      it 'sets file permissions to 0600' do
        encoded = Base64.strict_encode64('keytab-binary-data-here')
        result = dummy.resolve_keytab(sources: [encoded], cache_dir: tmpdir)
        mode = File.stat(result[:path]).mode & 0o777
        expect(mode).to eq(0o600)
      end
    end

    context 'with no valid sources' do
      it 'returns failure' do
        result = dummy.resolve_keytab(sources: ['/nonexistent/path.keytab'])
        expect(result[:success]).to be false
        expect(result[:error]).to include('no valid keytab source')
      end
    end

    context 'with nil and empty sources' do
      it 'skips them and returns failure' do
        result = dummy.resolve_keytab(sources: [nil, '', '/nonexistent'])
        expect(result[:success]).to be false
      end
    end

    context 'with mixed sources (file first)' do
      let(:keytab_path) { File.join(tmpdir, 'test.keytab') }

      before { File.write(keytab_path, 'keytab-data') }

      it 'returns the first valid source' do
        encoded = Base64.strict_encode64('other-keytab')
        result = dummy.resolve_keytab(sources: [keytab_path, encoded])
        expect(result[:source]).to eq(:file)
        expect(result[:path]).to eq(keytab_path)
      end
    end
  end
end
