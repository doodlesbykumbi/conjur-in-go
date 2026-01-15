Feature: Authentication
  As a Conjur user
  I want to authenticate with my API key
  So that I can access protected resources

  Background:
    Given a Conjur server is running
    And an account "myorg" exists with admin user

  Scenario: Successful authentication with API key
    When I authenticate as "admin" in account "myorg" with the correct API key
    Then the response status should be 200
    And I should receive a valid JWT token

  Scenario: Failed authentication with wrong API key
    When I authenticate as "admin" in account "myorg" with API key "wrong-key"
    Then the response status should be 401

  Scenario: Authentication with non-existent user
    When I authenticate as "nonexistent" in account "myorg" with API key "any-key"
    Then the response status should be 401

  Scenario: Host authentication
    Given I am authenticated as "admin" in account "myorg"
    And I load the following policy to "root":
      """
      - !host myapp
      """
    When I authenticate as "host/myapp" in account "myorg" with the correct API key
    Then the response status should be 200
    And I should receive a valid JWT token
