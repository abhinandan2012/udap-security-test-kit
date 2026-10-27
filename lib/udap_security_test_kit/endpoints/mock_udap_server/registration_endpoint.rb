# frozen_string_literal: true

require_relative '../../tags'
require_relative '../mock_udap_server'
require_relative 'udap_registration_response_creation'

module UDAPSecurityTestKit
  module MockUDAPServer
    class RegistrationEndpoint < Inferno::DSL::SuiteEndpoint
      include UDAPRegistrationResponseCreation

      def test_run_identifier
        parsed_body = MockUDAPServer.parsed_io_body(request)
        client_uri = MockUDAPServer.udap_client_uri_from_registration_payload(parsed_body)
        return if client_uri.blank?

        MockUDAPServer.client_uri_to_client_id(client_uri)
      rescue JWT::DecodeError
        nil # a software statement that is not a decodable JWT cannot identify a session
      end

      def test_run_identifier_location_description
        "the 'iss' claim of the 'software_statement' JWT (base64url-encoded to form the client id)"
      end

      # Return a UDAP / RFC 7591 registration error response as JSON when the
      # request cannot be matched to a waiting test session.
      def no_session_response
        MockUDAPServer.update_response_for_error(
          response, no_session_message, status: 400, error: 'invalid_software_statement'
        )
      end

      def make_response
        make_udap_registration_response
      end

      def update_result
        nil # never update for now
      end

      def tags
        [REGISTRATION_TAG, UDAP_TAG]
      end
    end
  end
end
