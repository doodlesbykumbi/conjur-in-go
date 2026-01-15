Feature: Status and Info Endpoints
  As a Conjur user
  I want to check the server status
  So that I can verify the server is running correctly

  Scenario: Status page returns HTML
    Given a Conjur server is running
    When I request the status page
    Then the response status should be 200
    And the response content type should be "text/html"
    And the response body should contain "Your Conjur server is running!"

  Scenario: Status page returns JSON when requested
    Given a Conjur server is running
    When I request the status page with JSON format
    Then the response status should be 200
    And the response content type should be "application/json"
    And the response should contain version info

  Scenario: Authenticators endpoint returns JSON
    Given a Conjur server is running
    When I request the authenticators list
    Then the response status should be 200
    And the response content type should be "application/json"
    And the response should contain authenticator "authn"
