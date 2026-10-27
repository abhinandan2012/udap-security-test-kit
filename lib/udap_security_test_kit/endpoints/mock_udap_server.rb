require 'jwt'
require 'faraday'
require 'time'
require 'rack/utils'
require_relative '../urls'
require_relative '../tags'
require_relative '../udap_jwt_builder'

module UDAPSecurityTestKit
  module MockUDAPServer
    SUPPORTED_SCOPES = ['openid', 'system/*.read', 'user/*.read', 'patient/*.read'].freeze

    module_function

    def udap_server_metadata(suite_id)
      base_url = "#{Inferno::Application['base_url']}/custom/#{suite_id}"
      response_body = {
        udap_versions_supported: ['1'],
        udap_profiles_supported: ['udap_dcr', 'udap_authn', 'udap_authz'],
        udap_authorization_extensions_supported: ['hl7-b2b'],
        udap_authorization_extensions_required: [],
        udap_certifications_supported: [],
        udap_certifications_required: [],
        grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
        scopes_supported: SUPPORTED_SCOPES,
        registration_endpoint: base_url + REGISTRATION_PATH,
        registration_endpoint_jwt_signing_alg_values_supported: ['RS256', 'RS384', 'ES384'],
        authorization_endpoint: base_url + AUTHORIZATION_PATH,
        token_endpoint: base_url + TOKEN_PATH,
        token_endpoint_auth_methods_supported: ['private_key_jwt'],
        token_endpoint_auth_signing_alg_values_supported: ['RS256', 'RS384', 'ES384'],
        introspection_endpoint: base_url + INTROSPECTION_PATH,
        signed_metadata: udap_signed_metadata_jwt(base_url)
      }.to_json

      [200, { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, [response_body]]
    end

    def openid_connect_metadata(suite_id)
      base_url = "#{Inferno::Application['base_url']}/custom/#{suite_id}"
      response_body = {
        issuer: base_url + FHIR_PATH,
        authorization_endpoint: base_url + AUTHORIZATION_PATH,
        token_endpoint: base_url + TOKEN_PATH,
        jwks_uri: base_url + OIDC_JWKS_PATH,
        response_types_supported: ['code', 'id_token', 'token id_token'],
        subject_types_supported: ['pairwise', 'public'],
        id_token_signing_alg_values_supported: ['RS256']
      }.to_json

      [200, { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, [response_body]]
    end

    def udap_signed_metadata_jwt(base_url)
      jwt_claim_hash = {
        iss: base_url + FHIR_PATH,
        sub: base_url + FHIR_PATH,
        exp: 5.minutes.from_now.to_i,
        iat: Time.now.to_i,
        jti: SecureRandom.hex(32),
        token_endpoint: base_url + TOKEN_PATH,
        authorization_endpoint: base_url + AUTHORIZATION_PATH,
        registration_endpoint: base_url + REGISTRATION_PATH
      }.compact

      UDAPJWTBuilder.encode_jwt_with_x5c_header(
        jwt_claim_hash,
        test_kit_private_key,
        'RS256',
        [test_kit_cert]
      )
    end

    def root_ca_cert
      File.read(
        ENV.fetch('UDAP_ROOT_CA_CERT_FILE',
                  File.join(__dir__, '..',
                            'certs', 'infernoCA.pem'))
      )
    end

    def root_ca_private_key
      File.read(
        ENV.fetch('UDAP_CA_PRIVATE_KEY_FILE',
                  File.join(__dir__, '..',
                            'certs', 'infernoCA.key'))
      )
    end

    def test_kit_cert
      File.read(
        ENV.fetch('UDAP_TEST_KIT_CERT_FILE',
                  File.join(__dir__, '..',
                            'certs', 'TestClient.pem'))
      )
    end

    def test_kit_private_key
      File.read(
        ENV.fetch('UDAP_TEST_KIT_PRIVATE_KEY_FILE',
                  File.join(__dir__, '..',
                            'certs', 'TestClientPrivateKey.key'))
      )
    end

    def parsed_request_body(request)
      JSON.parse(request.request_body)
    rescue JSON::ParserError
      nil
    end

    def parsed_io_body(request)
      parsed_body = begin
        JSON.parse(request.body.read)
      rescue JSON::ParserError
        nil
      end
      request.body.rewind

      parsed_body
    end

    def jwt_claims(encoded_jwt)
      JWT.decode(encoded_jwt, nil, false)[0]
    end

    def udap_client_uri_from_registration_payload(reg_body)
      udap_claim_from_registration_payload(reg_body, 'iss')
    end

    def udap_claim_from_registration_payload(reg_body, claim_key)
      software_statement_jwt = udap_software_statement_jwt(reg_body)
      return unless software_statement_jwt.present?

      jwt_claims(software_statement_jwt)&.dig(claim_key)
    end

    def udap_software_statement_jwt(reg_body)
      reg_body&.dig('software_statement')
    end

    def client_uri_to_client_id(client_uri)
      Base64.urlsafe_encode64(client_uri, padding: false)
    end

    def client_id_to_client_uri(client_id)
      Base64.urlsafe_decode64(client_id)
    end

    def client_id_to_token(client_id, exp_min)
      token_structure = {
        client_id:,
        expiration: exp_min.minutes.from_now.to_i,
        nonce: SecureRandom.hex(8)
      }.to_json

      Base64.urlsafe_encode64(token_structure, padding: false)
    end

    def decode_token(token)
      token_to_decode =
        if issued_token_is_refresh_token?(token)
          refresh_token_to_authorization_code(token)
        else
          token
        end
      return unless token_to_decode.present?

      JSON.parse(Base64.urlsafe_decode64(token_to_decode))
    rescue StandardError
      nil
    end

    def issued_token_to_client_id(token)
      decode_token(token)&.dig('client_id')
    end

    def issued_token_is_refresh_token?(token)
      token.end_with?('_rt')
    end

    def authorization_code_to_refresh_token(code)
      "#{code}_rt"
    end

    def refresh_token_to_authorization_code(refresh_token)
      refresh_token[..-4]
    end

    def request_has_expired_token?(request)
      return false if request.params[:session_path].present?

      token = request.headers['authorization']&.delete_prefix('Bearer ')
      token_expired?(token)
    end

    def token_expired?(token, check_time = nil)
      decoded_token = decode_token(token)
      return false unless decoded_token&.dig('expiration').present?

      check_time = Time.now.to_i unless check_time.present?
      decoded_token['expiration'] < check_time
    end

    def update_response_for_expired_token(response, type)
      response.status = 401
      response.format = :json
      response.body = FHIR::OperationOutcome.new(
        issue: FHIR::OperationOutcome::Issue.new(severity: 'fatal', code: 'expired',
                                                 details: FHIR::CodeableConcept.new(text: "#{type} has expired"))
      ).to_json
    end

    def udap_reg_signature_verification(assertion_jwt)
      assertion_body, assertion_header = JWT.decode(assertion_jwt, nil, false)
      return 'missing `x5c` header' if assertion_header['x5c'].blank?

      leaf_cert_der = Base64.decode64(assertion_header['x5c'].first)
      leaf_cert = OpenSSL::X509::Certificate.new(leaf_cert_der)

      signature_error = udap_assertion_signature_verification(assertion_jwt, leaf_cert, assertion_header['alg'])
      return signature_error if signature_error.present?

      # check the certificate's SAN extension for the issuer name
      issuer = assertion_body['iss']
      begin
        alt_names =
          leaf_cert.extensions
            .find { |extension| extension.oid == 'subjectAltName' }.value
      rescue NoMethodError
        return 'Could not find Subject Alternative Name extension in leaf certificate'
      end
      return if alt_names.include?("URI:#{issuer}")

      "`iss` claim `#{issuer}` not found in Subject Alternative Name extension " \
        "from the `x5c` JWT header: `#{alt_names}`"
    end

    def udap_token_signature_verification(assertion_jwt, registration_jwt)
      _assertion_body, assertion_header = JWT.decode(assertion_jwt, nil, false)
      return 'missing `x5c` header' if assertion_header['x5c'].blank?

      leaf_cert_der = Base64.decode64(assertion_header['x5c'].first)
      leaf_cert = OpenSSL::X509::Certificate.new(leaf_cert_der)

      signature_error = udap_assertion_signature_verification(assertion_jwt, leaf_cert, assertion_header['alg'])
      return signature_error if signature_error.present?
      return unless registration_jwt.present?

      # check trust
      _registration_body, registration_header = JWT.decode(registration_jwt, nil, false)
      return if assertion_header['x5c'].first == registration_header['x5c'].first

      'signing cert does not match registration cert'
    end

    def udap_assertion_signature_verification(assertion_jwt, signing_cert, algorithm)
      return 'missing `alg` header' unless algorithm.present?

      signature_validation_result = UDAPSecurityTestKit::UDAPJWTValidator.validate_signature(
        assertion_jwt,
        algorithm,
        signing_cert
      )
      return if signature_validation_result[:success]

      signature_validation_result[:error_message]
    end

    def udap_registration_software_statement(test_session_id)
      registration_requests =
        Inferno::Repositories::Requests.new.tagged_requests(test_session_id, [UDAP_TAG, REGISTRATION_TAG])
      return unless registration_requests.present?

      parsed_body = MockUDAPServer.parsed_request_body(registration_requests.last)
      parsed_body&.dig('software_statement')
    end

    def update_response_for_error(response, error_message, status: 401, error: 'invalid_client')
      response.status = status
      response.format = :json
      response.body = { error:, error_description: error_message }.to_json
    end

    def client_id_from_client_assertion(client_assertion_jwt)
      return unless client_assertion_jwt.present?

      jwt_claims(client_assertion_jwt)&.dig('iss')
    end

    def check_jwt_timing(issue_claim, expiration_claim, request_time) # rubocop:disable Metrics/CyclomaticComplexity
      add_message('error', 'Registration software statement `iat` claim is missing') unless issue_claim.present?
      add_message('error', 'Registration software statement `exp` claim is missing') unless expiration_claim.present?
      return unless issue_claim.present? && expiration_claim.present?

      unless issue_claim.is_a?(Numeric)
        add_message('error',
                    "Registration software statement `iat` claim is invalid: expected a number, got '#{issue_claim}'")
      end
      unless expiration_claim.is_a?(Numeric)
        add_message('error',
                    'Registration software statement `exp` claim is invalid: ' \
                    "expected a number, got '#{expiration_claim}'")
      end
      return unless issue_claim.is_a?(Numeric) && expiration_claim.is_a?(Numeric)

      issue_time = Time.at(issue_claim)
      expiration_time = Time.at(expiration_claim)
      unless expiration_time > issue_time
        add_message('error',
                    'Registration software statement `exp` claim is invalid: ' \
                    'cannot be before the `iat` claim.')
      end
      unless expiration_time <= issue_time + 5.minutes
        add_message('error',
                    'Registration software statement `exp` claim is invalid: ' \
                    'cannot be more than 5 minutes after the `iat` claim.')
      end
      unless issue_time <= request_time
        add_message('error',
                    'Registration software statement `iat` claim is invalid: ' \
                    'cannot be after the request time.')
      end
      unless expiration_time > request_time
        add_message('error',
                    'Registration software statement `exp` claim is invalid: ' \
                    'it has expired.')
      end

      nil
    end

    def pkce_error(verifier, challenge, method)
      if verifier.blank?
        'pkce check failed: no verifier provided'
      elsif challenge.blank?
        'pkce check failed: no challenge code provided'
      elsif method == 'S256'
        return nil unless challenge != calculate_s256_challenge(verifier)

        "invalid S256 pkce verifier: got '#{calculate_s256_challenge(verifier)}' " \
          "expected '#{challenge}'"
      else
        "invalid pkce challenge method '#{method}'"
      end
    end

    def pkce_valid?(verifier, challenge, method, response)
      pkce_error = pkce_error(verifier, challenge, method)

      if pkce_error.present?
        update_response_for_error(response, pkce_error)
        false
      else
        true
      end
    end

    def calculate_s256_challenge(verifier)
      Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
    end

    def authorization_request_for_code(code, test_session_id)
      authorization_requests = Inferno::Repositories::Requests.new.tagged_requests(test_session_id, [AUTHORIZATION_TAG])
      authorization_requests.find do |request|
        location_header = request.response_headers.find { |header| header.name.downcase == 'location' }
        if location_header.present? && location_header.value.present?
          Rack::Utils.parse_query(URI(location_header.value)&.query)&.dig('code') == code
        else
          false
        end
      end
    end

    def authorization_code_request_details(inferno_request)
      return unless inferno_request.present?

      if inferno_request.verb.downcase == 'get'
        Rack::Utils.parse_query(URI(inferno_request.url)&.query)
      elsif inferno_request.verb.downcase == 'post'
        Rack::Utils.parse_query(inferno_request.request_body)
      end
    end
  end
end
