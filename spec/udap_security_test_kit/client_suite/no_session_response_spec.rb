# Verifies the response returned by each client suite endpoint when no waiting
# test run/session can be found for an incoming request.
RSpec.describe UDAPSecurityTestKit::MockUDAPServer::RegistrationEndpoint, :request do # rubocop:disable RSpec/SpecFilePathFormat
  include UDAPSecurityTestKit::URLs

  let(:unknown_client_uri) { 'http://unknown.example.com/client' }
  let(:unknown_client_id) { UDAPSecurityTestKit::MockUDAPServer.client_uri_to_client_id(unknown_client_uri) }
  let(:certs_dir) { File.join(__dir__, '..', '..', '..', 'lib', 'udap_security_test_kit', 'certs') }
  let(:leaf_cert) { File.read(File.join(certs_dir, 'TestClient.pem')) }
  let(:leaf_key) { File.read(File.join(certs_dir, 'TestClientPrivateKey.key')) }
  let(:form_content_type) { { 'CONTENT_TYPE' => 'application/x-www-form-urlencoded' } }

  def signed_jwt(claims)
    UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header(claims, leaf_key, 'RS256', [leaf_cert])
  end

  # Asserts an OAuth-style JSON error body and returns its error_description
  def expect_json_error(status, error)
    expect(last_response.status).to eq(status)
    expect(last_response.headers['Content-Type']).to include('application/json')

    body = JSON.parse(last_response.body)
    expect(body['error']).to eq(error)
    expect(body['error_description']).to be_present
    body['error_description']
  end

  describe 'when no session is waiting for a registration request' do
    it 'returns a 400 invalid_software_statement JSON error for an unknown client' do
      software_statement = signed_jwt(iss: unknown_client_uri, sub: unknown_client_uri)
      post_json(client_registration_url, { software_statement:, udap: '1' })

      description = expect_json_error(400, 'invalid_software_statement')
      expect(description).to include('Unable to find test run')
      expect(description).to include(
        "identifier '#{unknown_client_id}', found in the 'iss' claim of the 'software_statement' JWT"
      )
      expect(description).to include('is not associated with a waiting session')
    end

    it 'returns a 400 invalid_software_statement JSON error when there is no software statement' do
      post_json(client_registration_url, { udap: '1' })

      description = expect_json_error(400, 'invalid_software_statement')
      expect(description).to include("no identifier found in the 'iss' claim of the 'software_statement' JWT")
    end

    it 'returns a 400 invalid_software_statement JSON error when the software statement is not a JWT' do
      post_json(client_registration_url, { software_statement: 'not-a-jwt', udap: '1' })

      description = expect_json_error(400, 'invalid_software_statement')
      expect(description).to include("no identifier found in the 'iss' claim of the 'software_statement' JWT")
    end

    it 'returns a 400 invalid_software_statement JSON error when the body cannot be parsed as JSON' do
      post client_registration_url, 'not json', 'CONTENT_TYPE' => 'text/plain'

      description = expect_json_error(400, 'invalid_software_statement')
      expect(description).to include('no identifier found')
    end
  end

  describe UDAPSecurityTestKit::MockUDAPServer::AuthorizationEndpoint do
    it 'returns a 400 invalid_request JSON error for an unknown client_id' do
      query = URI.encode_www_form([['response_type', 'code'],
                                   ['client_id', unknown_client_id],
                                   ['redirect_uri', 'http://example.com/redirect']])
      get "#{client_authorization_url}?#{query}"

      description = expect_json_error(400, 'invalid_request')
      expect(description).to include(
        "identifier '#{unknown_client_id}', found in the 'client_id' parameter, " \
        'is not associated with a waiting session'
      )
    end

    it 'returns a 400 invalid_request JSON error when client_id is missing' do
      post client_authorization_url, URI.encode_www_form([['response_type', 'code']]), form_content_type

      description = expect_json_error(400, 'invalid_request')
      expect(description).to include("no identifier found in the 'client_id' parameter")
    end
  end

  describe UDAPSecurityTestKit::MockUDAPServer::IntrospectionEndpoint do
    it 'returns a 400 invalid_request JSON error for a token issued to an unknown client' do
      token = UDAPSecurityTestKit::MockUDAPServer.client_id_to_token(unknown_client_id, 5)
      post client_introspection_url, URI.encode_www_form([['token', token]]), form_content_type

      description = expect_json_error(400, 'invalid_request')
      expect(description).to include(
        "identifier '#{unknown_client_id}', found in the 'token' parameter, is not associated with a waiting session"
      )
    end

    it 'returns a 400 invalid_request JSON error for a token that cannot be decoded' do
      post client_introspection_url, URI.encode_www_form([['token', 'garbage']]), form_content_type

      description = expect_json_error(400, 'invalid_request')
      expect(description).to include("no identifier found in the 'token' parameter")
    end
  end

  describe UDAPSecurityTestKit::MockUDAPServer::TokenEndpoint do
    def post_token(params)
      post client_token_url, URI.encode_www_form(params), form_content_type
    end

    it 'returns a 401 invalid_client JSON error for a client_credentials request from an unknown client' do
      client_assertion = signed_jwt(
        iss: unknown_client_id, sub: unknown_client_id, aud: client_token_url,
        exp: 5.minutes.from_now.to_i, iat: Time.now.to_i, jti: SecureRandom.hex(32)
      )
      post_token(grant_type: 'client_credentials',
                 client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                 client_assertion:,
                 udap: '1')

      description = expect_json_error(401, 'invalid_client')
      expect(description).to include(
        "identifier '#{unknown_client_id}', found in the 'iss' claim of the 'client_assertion' JWT, " \
        'is not associated with a waiting session'
      )
    end

    it 'returns a 401 invalid_client JSON error for a client_credentials request whose assertion is not a JWT' do
      post_token(grant_type: 'client_credentials', client_assertion: 'not-a-jwt')

      description = expect_json_error(401, 'invalid_client')
      expect(description).to include("no identifier found in the 'iss' claim of the 'client_assertion' JWT")
    end

    it 'returns a 401 invalid_client JSON error for a client_credentials request with no assertion' do
      post_token(grant_type: 'client_credentials')

      description = expect_json_error(401, 'invalid_client')
      expect(description).to include("no identifier found in the 'iss' claim of the 'client_assertion' JWT")
    end

    it 'returns a 400 invalid_grant JSON error for an authorization_code request with an unknown code' do
      post_token(grant_type: 'authorization_code', code: 'unknown')

      description = expect_json_error(400, 'invalid_grant')
      expect(description).to include("no identifier found in the 'code' parameter")
    end

    it 'returns a 400 invalid_grant JSON error for an authorization_code request for an unknown client' do
      code = UDAPSecurityTestKit::MockUDAPServer.client_id_to_token(unknown_client_id, 5)
      post_token(grant_type: 'authorization_code', code:)

      description = expect_json_error(400, 'invalid_grant')
      expect(description).to include(
        "identifier '#{unknown_client_id}', found in the 'code' parameter, is not associated with a waiting session"
      )
    end

    it 'returns a 400 invalid_grant JSON error for a refresh_token request with no refresh token' do
      post_token(grant_type: 'refresh_token')

      description = expect_json_error(400, 'invalid_grant')
      expect(description).to include("no identifier found in the 'refresh_token' parameter")
    end

    it 'returns a 400 invalid_grant JSON error for a refresh_token request for an unknown client' do
      code = UDAPSecurityTestKit::MockUDAPServer.client_id_to_token(unknown_client_id, 5)
      refresh_token = UDAPSecurityTestKit::MockUDAPServer.authorization_code_to_refresh_token(code)
      post_token(grant_type: 'refresh_token', refresh_token:)

      description = expect_json_error(400, 'invalid_grant')
      expect(description).to include(
        "identifier '#{unknown_client_id}', found in the 'refresh_token' parameter, " \
        'is not associated with a waiting session'
      )
    end

    it 'returns a 400 unsupported_grant_type JSON error for an unsupported grant type' do
      post_token(grant_type: 'password')

      description = expect_json_error(400, 'unsupported_grant_type')
      expect(description).to eq('unsupported grant_type: password')
    end

    it 'returns a 400 invalid_request JSON error when grant_type is missing' do
      post_token({})

      description = expect_json_error(400, 'invalid_request')
      expect(description).to eq("missing required 'grant_type' parameter")
    end
  end

  describe UDAPSecurityTestKit::EchoingFHIRResponderEndpoint do
    def expect_not_found_operation_outcome
      expect(last_response.status).to eq(500)
      expect(last_response.headers['Content-Type']).to eq('application/fhir+json')

      outcome = FHIR.from_contents(last_response.body)
      expect(outcome).to be_a(FHIR::OperationOutcome)
      expect(outcome.issue.first.severity).to eq('fatal')
      expect(outcome.issue.first.code).to eq('not-found')
      outcome.issue.first.details.text
    end

    it 'returns a 500 FHIR OperationOutcome when the bearer token was issued to an unknown client' do
      token = UDAPSecurityTestKit::MockUDAPServer.client_id_to_token(unknown_client_id, 5)
      get "#{client_fhir_base_url}/Patient/1", nil, 'HTTP_AUTHORIZATION' => "Bearer #{token}"

      details = expect_not_found_operation_outcome
      expect(details).to include('Unable to find test run')
      expect(details).to include(
        "identifier '#{unknown_client_id}', found in the bearer token in the 'Authorization' header, " \
        'is not associated with a waiting session'
      )
    end

    it 'returns a 500 FHIR OperationOutcome when there is no bearer token' do
      get "#{client_fhir_base_url}/Patient/1"

      details = expect_not_found_operation_outcome
      expect(details).to include("no identifier found in the bearer token in the 'Authorization' header")
    end
  end
end
