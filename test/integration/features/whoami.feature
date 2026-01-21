Feature: Whoami Endpoint
  As a Conjur user
  I want to check my identity
  So that I can verify my authentication

  Background:
    Given a Conjur server is running
    And an account "myorg" exists with admin user

  Scenario: Whoami with valid user token
    Given I am authenticated as "admin" in account "myorg"
    When I request whoami
    Then the response status should be 200
    And the whoami response should show account "myorg"
    And the whoami response should show username "admin"

  Scenario: Whoami with host token
    Given I am authenticated as "admin" in account "myorg"
    And I load the following policy to "root":
      """
      - !host myapp
      """
    And I authenticate as "host/myapp" in account "myorg" with the correct API key
    When I request whoami
    Then the response status should be 200
    And the whoami response should show account "myorg"
    And the whoami response should show username "host/myapp"

  Scenario: Whoami without token
    When I request whoami without authentication
    Then the response status should be 401

  Scenario: Whoami with invalid token
    When I request whoami with invalid token
    Then the response status should be 401
