# frozen_string_literal: true

require_relative '../../tags'
require_relative '../../urls'
require_relative '../mock_udap_server'
require_relative 'udap_token_response_creation'

module UDAPSecurityTestKit
  module MockUDAPServer
    class TokenEndpoint < Inferno::DSL::SuiteEndpoint
      include UDAPTokenResponseCreation
      include URLs

      def test_run_identifier
        case request.params[:grant_type]
        when CLIENT_CREDENTIALS_TAG
          MockUDAPServer.client_id_from_client_assertion(request.params[:client_assertion])
        when AUTHORIZATION_CODE_TAG
          MockUDAPServer.issued_token_to_client_id(request.params[:code])
        when REFRESH_TOKEN_TAG
          refresh_token = request.params[:refresh_token]
          return if refresh_token.blank?

          MockUDAPServer.issued_token_to_client_id(MockUDAPServer.refresh_token_to_authorization_code(refresh_token))
        end
      rescue JWT::DecodeError
        nil # a client assertion that is not a decodable JWT cannot identify a session
      end

      def test_run_identifier_location_description
        case request.params[:grant_type]
        when CLIENT_CREDENTIALS_TAG
          "the 'iss' claim of the 'client_assertion' JWT"
        when AUTHORIZATION_CODE_TAG
          "the 'code' parameter"
        when REFRESH_TOKEN_TAG
          "the 'refresh_token' parameter"
        end
      end

      # Return an OAuth 2.0 token error response (RFC 6749 section 5.2) as JSON
      # when the request cannot be matched to a waiting test session.
      def no_session_response
        status, error, message = no_session_error_details
        MockUDAPServer.update_response_for_error(response, message, status:, error:)
      end

      def no_session_error_details
        grant_type = request.params[:grant_type]
        case grant_type
        when CLIENT_CREDENTIALS_TAG
          [401, 'invalid_client', no_session_message]
        when AUTHORIZATION_CODE_TAG, REFRESH_TOKEN_TAG
          [400, 'invalid_grant', no_session_message]
        else
          if grant_type.blank?
            [400, 'invalid_request', "missing required 'grant_type' parameter"]
          else
            [400, 'unsupported_grant_type', "unsupported grant_type: #{grant_type}"]
          end
        end
      end

      def make_response
        case request.params[:grant_type]
        when CLIENT_CREDENTIALS_TAG
          make_udap_client_credential_token_response
        when AUTHORIZATION_CODE_TAG
          make_udap_authorization_code_token_response
        when REFRESH_TOKEN_TAG
          make_udap_refresh_token_response
        else
          MockUDAPServer.update_response_for_error(
            response,
            "unsupported grant_type: #{request.params[:grant_type]}"
          )
        end
      end

      def update_result
        nil # never update for now
      end

      def tags
        tags = [TOKEN_TAG, UDAP_TAG]
        if [CLIENT_CREDENTIALS_TAG, AUTHORIZATION_CODE_TAG, REFRESH_TOKEN_TAG].include?(request.params[:grant_type])
          tags << request.params[:grant_type]
        end
        tags
      end
    end
  end
end
