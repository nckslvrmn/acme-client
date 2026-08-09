# frozen_string_literal: true

module Acme; end
class Acme::Client; end

class Acme::Client::Problem
  ERROR_PREFIX = 'urn:ietf:params:acme:error:'.freeze

  # Registry descriptions for problem types, not fallback values for problem details.
  REGISTERED_ERROR_TYPE_DESCRIPTIONS = {
    'accountDoesNotExist' => 'The request specified an account that does not exist',
    'alreadyRevoked' => 'The request specified a certificate to be revoked that has already been revoked',
    'badCSR' => 'The CSR is unacceptable (e.g., due to a short key)',
    'badNonce' => 'The client sent an unacceptable anti-replay nonce',
    'badPublicKey' => 'The JWS was signed by a public key the server does not support',
    'badRevocationReason' => 'The revocation reason provided is not allowed by the server',
    'badSignatureAlgorithm' => 'The JWS was signed with an algorithm the server does not support',
    'caa' => 'Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate',
    'compound' => 'Specific error conditions are indicated in the "subproblems" array',
    'connection' => 'The server could not connect to validation target',
    'dns' => 'There was a problem with a DNS query during identifier validation',
    'externalAccountRequired' => 'The request must include a value for the "externalAccountBinding" field',
    'incorrectResponse' => "Response received didn't match the challenge's requirements",
    'invalidContact' => 'A contact URL for an account was invalid',
    'malformed' => 'The request message was malformed',
    'orderNotReady' => 'The request attempted to finalize an order that is not ready to be finalized',
    'rateLimited' => 'The request exceeds a rate limit',
    'rejectedIdentifier' => 'The server will not issue certificates for the identifier',
    'serverInternal' => 'The server experienced an internal error',
    'tls' => 'The server received a TLS error during validation',
    'unauthorized' => 'The client lacks sufficient authorization',
    'unsupportedContact' => 'A contact URL for an account used an unsupported protocol scheme',
    'unsupportedIdentifier' => 'An identifier is of an unsupported type',
    'userActionRequired' => 'Visit the "instance" URL and take actions specified there',
    'autoRenewalCanceled' => 'The short-term certificate is no longer available because the auto-renewal Order has been explicitly canceled by the IdO',
    'autoRenewalExpired' => 'The short-term certificate is no longer available because the auto-renewal Order has expired',
    'autoRenewalCancellationInvalid' => 'A request to cancel an auto-renewal Order that is not in state "valid" has been received',
    'autoRenewalRevocationNotSupported' => 'A request to revoke an auto-renewal Order has been received',
    'unknownDelegation' => 'An unknown configuration is listed in the delegation attribute of the order request',
    'onionCAARequired' => 'The CA only supports checking the CAA for Hidden Services in-band, but the client has not provided an in-band CAA',
    'alreadyReplaced' => 'The request specified a predecessor certificate that has already been marked as replaced',
    'badAttestationStatement' => 'The attestation statement is unacceptable (e.g. not signed by an attestation authority trusted by the CA)'
  }.freeze

  def self.from(value)
    case value
    when nil
      nil
    when Acme::Client::Problem
      value
    when Hash
      new(value)
    end
  end

  attr_reader :raw

  def initialize(raw = {})
    @raw = raw || {}
  end

  def type
    fetch('type')
  end

  def code
    return unless type
    return unless type.start_with?(ERROR_PREFIX)

    type[ERROR_PREFIX.length..-1]
  end

  def title
    fetch('title')
  end

  def detail
    fetch('detail')
  end

  def status
    fetch('status')
  end

  def instance
    fetch('instance')
  end

  def identifier
    fetch('identifier')
  end

  def subproblems
    return [] unless raw_subproblems.is_a?(Array)

    raw_subproblems.map { |subproblem| self.class.new(subproblem) }
  end

  def raw_subproblems
    fetch('subproblems')
  end

  def registered?
    REGISTERED_ERROR_TYPE_DESCRIPTIONS.key?(code)
  end

  alias standard? registered?

  def description
    REGISTERED_ERROR_TYPE_DESCRIPTIONS[code]
  end

  def matches?(type_or_code)
    candidate = type_or_code.to_s
    candidate == type || candidate == code || "#{ERROR_PREFIX}#{candidate}" == type
  end

  def message
    detail || title || type
  end

  def to_h
    raw
  end

  def as_json(*_arguments)
    to_h
  end

  private

  def fetch(key)
    raw[key] || raw[key.to_sym]
  end
end
