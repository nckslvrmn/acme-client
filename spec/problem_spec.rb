# frozen_string_literal: true

$LOAD_PATH.unshift File.join(__dir__, '../lib')

require 'csv'
require 'net/http'
require 'uri'

require 'acme/client'

RSpec.describe Acme::Client::Problem do
  let(:raw_problem) do
    {
      'type' => 'urn:ietf:params:acme:error:unauthorized',
      'title' => 'Unauthorized',
      'detail' => 'The client lacks sufficient authorization',
      'status' => 403,
      'instance' => 'https://ca.example.test/problems/1',
      'identifier' => { 'type' => 'dns', 'value' => 'example.test' },
      'extra' => 'kept'
    }
  end

  describe '.from' do
    it 'wraps hashes' do
      problem = described_class.from(raw_problem)
      expect(problem).to be_a(described_class)
      expect(problem.to_h).to eq(raw_problem)
    end

    it 'returns existing problems unchanged' do
      problem = described_class.new(raw_problem)
      expect(described_class.from(problem)).to equal(problem)
    end

    it 'returns nil for nil' do
      expect(described_class.from(nil)).to be_nil
    end
  end

  describe 'problem document fields' do
    subject(:problem) { described_class.new(raw_problem) }

    it 'exposes RFC 7807 fields' do
      expect(problem.type).to eq('urn:ietf:params:acme:error:unauthorized')
      expect(problem.title).to eq('Unauthorized')
      expect(problem.detail).to eq('The client lacks sufficient authorization')
      expect(problem.status).to eq(403)
      expect(problem.instance).to eq('https://ca.example.test/problems/1')
    end

    it 'exposes ACME extension fields' do
      expect(problem.identifier).to eq({ 'type' => 'dns', 'value' => 'example.test' })
    end

    it 'keeps the raw problem document for extension fields' do
      expect(problem.raw['extra']).to eq('kept')
    end
  end

  describe '#code' do
    it 'strips the ACME error prefix for registered ACME problem types' do
      problem = described_class.new(raw_problem)
      expect(problem.code).to eq('unauthorized')
    end

    it 'returns nil for non-ACME problem types' do
      problem = described_class.new('type' => 'https://ca.example.test/errors/account-blocked')
      expect(problem.code).to be_nil
    end
  end

  describe '#registered?' do
    it 'returns true for IANA registered ACME error types' do
      problem = described_class.new('type' => 'urn:ietf:params:acme:error:onionCAARequired')
      expect(problem).to be_registered
      expect(problem).to be_standard
    end

    it 'returns false for unknown ACME error types' do
      problem = described_class.new('type' => 'urn:ietf:params:acme:error:futureError')
      expect(problem).not_to be_registered
      expect(problem).not_to be_standard
    end
  end

  describe '#description' do
    it 'returns the registered description for known ACME error types' do
      problem = described_class.new('type' => 'urn:ietf:params:acme:error:rateLimited')
      expect(problem.description).to eq('The request exceeds a rate limit')
    end
  end

  describe '#matches?' do
    subject(:problem) { described_class.new(raw_problem) }

    it 'matches full URNs' do
      expect(problem.matches?('urn:ietf:params:acme:error:unauthorized')).to be(true)
    end

    it 'matches short codes' do
      expect(problem.matches?('unauthorized')).to be(true)
    end

    it 'does not match other problem types' do
      expect(problem.matches?('rateLimited')).to be(false)
    end
  end

  describe '#subproblems' do
    it 'parses subproblems as problem objects' do
      problem = described_class.new(
        'type' => 'urn:ietf:params:acme:error:compound',
        'subproblems' => [
          {
            'type' => 'urn:ietf:params:acme:error:caa',
            'detail' => 'CAA forbids issuance',
            'identifier' => { 'type' => 'dns', 'value' => 'example.test' }
          }
        ]
      )

      expect(problem.subproblems.length).to eq(1)
      expect(problem.subproblems.first).to be_a(described_class)
      expect(problem.subproblems.first.code).to eq('caa')
      expect(problem.subproblems.first.identifier).to eq({ 'type' => 'dns', 'value' => 'example.test' })
    end

    it 'returns an empty array when subproblems is missing' do
      expect(described_class.new(raw_problem).subproblems).to eq([])
    end
  end

  describe '#message' do
    it 'prefers detail over title and type' do
      problem = described_class.new(raw_problem)
      expect(problem.message).to eq('The client lacks sufficient authorization')
    end

    it 'falls back to title and type' do
      expect(described_class.new('title' => 'A title', 'type' => 'about:blank').message).to eq('A title')
      expect(described_class.new('type' => 'about:blank').message).to eq('about:blank')
    end
  end

  describe 'IANA registered ACME error types' do
    let(:iana_registry) { fetch_iana_acme_error_type_registry }

    def fetch_iana_acme_error_type_registry
      uri = URI('https://www.iana.org/assignments/acme/acme-error-types.csv')

      response = with_real_http do
        Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 5, read_timeout: 10) do |http|
          http.get(uri.request_uri)
        end
      end

      expect(response).to be_a(Net::HTTPSuccess)

      CSV.parse(response.body, headers: true).each_with_object({}) do |row, registry|
        registry[row['Type']] = normalize_iana_description(row['Description'])
      end
    end

    def with_real_http
      return VCR.turned_off { with_webmock_net_connect { yield } } if defined?(VCR)

      with_webmock_net_connect { yield }
    end

    def with_webmock_net_connect
      return yield unless defined?(WebMock)

      webmock_enabled = true
      WebMock.allow_net_connect!
      yield
    ensure
      WebMock.disable_net_connect! if webmock_enabled
    end

    def normalize_iana_description(description)
      description.to_s.gsub(/\s+/, ' ').strip
    end

    it 'has problem descriptions for each mapped ACME error class' do
      Acme::Client::Error::ACME_ERRORS.each_key do |type|
        problem = described_class.new('type' => type)
        expect(problem.description).not_to be_nil
      end
    end

    it 'matches the live IANA ACME error type registry' do
      registered_descriptions = described_class::REGISTERED_ERROR_TYPE_DESCRIPTIONS
      registered_types = registered_descriptions.keys
      iana_types = iana_registry.keys
      missing_types = iana_types - registered_types
      extra_types = registered_types - iana_types
      mismatched_descriptions = iana_registry.each_with_object({}) do |(type, description), mismatches|
        next unless registered_descriptions.key?(type)
        next if normalize_iana_description(registered_descriptions[type]) == description

        mismatches[type] = {
          iana: description,
          registered: normalize_iana_description(registered_descriptions[type])
        }
      end
      missing_error_classes = iana_types.map { |type| "#{described_class::ERROR_PREFIX}#{type}" } - Acme::Client::Error::ACME_ERRORS.keys

      expect(missing_types).to be_empty, "missing registered ACME problem descriptions: #{missing_types.join(', ')}"
      expect(extra_types).to be_empty, "extra registered ACME problem descriptions: #{extra_types.join(', ')}"
      expect(mismatched_descriptions).to be_empty, "mismatched IANA ACME problem descriptions: #{mismatched_descriptions.inspect}"
      expect(missing_error_classes).to be_empty, "missing ACME error classes: #{missing_error_classes.join(', ')}"
    end

    it 'maps registered extension error types to typed errors' do
      expect(Acme::Client::Error::ACME_ERRORS['urn:ietf:params:acme:error:compound']).to eq(Acme::Client::Error::Compound)
      expect(Acme::Client::Error::ACME_ERRORS['urn:ietf:params:acme:error:autoRenewalCanceled']).to eq(Acme::Client::Error::AutoRenewalCanceled)
      expect(Acme::Client::Error::ACME_ERRORS['urn:ietf:params:acme:error:unknownDelegation']).to eq(Acme::Client::Error::UnknownDelegation)
      expect(Acme::Client::Error::ACME_ERRORS['urn:ietf:params:acme:error:onionCAARequired']).to eq(Acme::Client::Error::OnionCAARequired)
    end
  end
end
