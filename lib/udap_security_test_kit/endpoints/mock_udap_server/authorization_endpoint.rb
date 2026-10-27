# frozen_string_literal: true

require_relative '../../tags'
require_relative '../mock_udap_server'
require_relative 'udap_authorization_response_creation'

module UDAPSecurityTestKit
  module MockUDAPServer
    class AuthorizationEndpoint < Inferno::DSL::SuiteEndpoint
      include UDAPAuthorizationResponseCreation

      def test_run_identifier
        request.params[:client_id]
      end

      def test_run_identifier_location_description
        "the 'client_id' parameter"
      end

      # Return an OAuth 2.0 error response as JSON when the request cannot be
      # matched to a waiting test session. The user agent is not redirected
      # because the client cannot be identified (RFC 6749 section 4.1.2.1).
      def no_session_response
        MockUDAPServer.update_response_for_error(response, no_session_message, status: 400, error: 'invalid_request')
      end

      def make_response
        make_udap_authorization_response
      end

      def update_result
        nil # never update for now
      end

      def tags
        [AUTHORIZATION_TAG, AUTHORIZATION_CODE_TAG, UDAP_TAG]
      end
    end
  end
end
