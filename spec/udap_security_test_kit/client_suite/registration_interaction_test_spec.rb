RSpec.describe UDAPSecurityTestKit::UDAPClientRegistrationInteraction, :request do # rubocop:disable RSpec/SpecFilePathFormat
  include UDAPSecurityTestKit::URLs

  let(:suite_id) { 'udap_security_client' }
  let(:test) { described_class }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:reg_url) { client_registration_url }
  let(:redirect_uri) { 'http://inferno.healthit.gov/redirect' }
  let(:udap_client_uri) { 'http://localhost:4567/custom/g33_test_suite/fhir' }
  let(:udap_client_id) { described_class.client_uri_to_client_id(udap_client_uri) }
  let(:root_cert) do
    File.read(File.join(__dir__, '..', '..', '..', 'lib', 'udap_security_test_kit', 'certs', 'InfernoCA.pem'))
  end
  let(:root_key) do
    File.read(File.join(__dir__, '..', '..', '..', 'lib', 'udap_security_test_kit', 'certs', 'InfernoCA.key'))
  end
  let(:leaf_cert) do
    File.read(File.join(__dir__, '..', '..', '..', 'lib', 'udap_security_test_kit', 'certs', 'TestClient.pem'))
  end
  let(:leaf_key) do
    File.read(File.join(__dir__, '..', '..', '..', 'lib', 'udap_security_test_kit', 'certs',
                        'TestClientPrivateKey.key'))
  end
  let(:reg_claims) do
    {
      iss: udap_client_uri,
      sub: udap_client_uri,
      aud: reg_url,
      exp: 5.minutes.from_now.to_i,
      iat: Time.now.to_i,
      jti: SecureRandom.hex(32),
      client_name: 'Test Client',
      grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'private_key_jwt',
      scope: 'system/*.read offline_access openid fhirUser',
      contacts: ['mailto:test@inferno.healthit.gov'],
      logo_uri: 'https://myapp.example.com/MyApp.png',
      redirect_uris: [redirect_uri],
      response_types: ['code']
    }
  end
  let(:reg_claims_wrong_client_uri) do
    {
      iss: "#{udap_client_uri}wrong",
      sub: udap_client_uri,
      aud: reg_url,
      exp: 5.minutes.from_now.to_i,
      iat: Time.now.to_i,
      jti: SecureRandom.hex(32),
      client_name: 'Test Client',
      grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'private_key_jwt',
      scope: 'system/*.read offline_access openid fhirUser',
      contacts: ['mailto:test@inferno.healthit.gov'],
      logo_uri: 'https://myapp.example.com/MyApp.png',
      redirect_uris: [redirect_uri],
      response_types: ['code']
    }
  end
  let(:reg_ss) do
    make_signed_udap_jwt(reg_claims, leaf_key, [leaf_cert])
  end
  let(:reg_ss_wrong_client_uri) do
    make_signed_udap_jwt(reg_claims_wrong_client_uri, leaf_key, [leaf_cert])
  end
  let(:reg_request_body) do
    {
      software_statement: reg_ss,
      certifications: [],
      udap: '1'
    }
  end
  let(:reg_request_body_wrong_client_uri) do
    {
      software_statement: reg_ss_wrong_client_uri,
      certifications: [],
      udap: '1'
    }
  end

  let(:reg_request_body_no_ss) do
    {
      certifications: [],
      udap: '1'
    }
  end

  def make_jwt(payload, header, alg, jwk)
    token = JWT::Token.new(payload:, header:)
    token.sign!(algorithm: alg, key: jwk.signing_key)
    token.jwt
  end

  def make_signed_udap_jwt(jwt_claim_hash, private_key, cert_list)
    UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header(
      jwt_claim_hash,
      private_key,
      'RS256',
      cert_list
    )
  end

  describe 'when responding to reg requests' do
    it 'succeeds for multiple valid requests' do
      inputs = { udap_client_uri: udap_client_uri }
      result = run(test, inputs)
      expect(result.result).to eq('wait')

      post_json(reg_url, reg_request_body)
      expect(last_response.status).to eq(201)

      # second time the same
      post_json(reg_url, reg_request_body)
      expect(last_response.status).to eq(201)
    end

    it 'returns a 400 JSON error for the wrong client uri' do
      inputs = { udap_client_uri: udap_client_uri }
      result = run(test, inputs)
      expect(result.result).to eq('wait')

      post_json(reg_url, reg_request_body_wrong_client_uri)
      expect(last_response.status).to eq(400)
      expect(JSON.parse(last_response.body)['error']).to eq('invalid_software_statement')
    end

    it 'returns a 400 JSON error when no software statement' do
      inputs = { udap_client_uri: udap_client_uri }
      result = run(test, inputs)
      expect(result.result).to eq('wait')

      post_json(reg_url, reg_request_body_no_ss)
      expect(last_response.status).to eq(400)
      expect(JSON.parse(last_response.body)['error']).to eq('invalid_software_statement')
    end
  end
end
