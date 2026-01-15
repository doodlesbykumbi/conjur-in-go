Feature: Health Checks
  As a Conjur administrator
  I want to check the health of authenticators
  So that I can verify they are properly configured

  Background:
    Given a Conjur server is running

  Scenario: Authn status returns ok when enabled
    When I check the status of "authn" for account "myorg"
    Then the response status should be 200
    And the response should indicate status "ok"

  Scenario: Authn-jwt status returns error when not enabled
    When I check the status of "authn-jwt/unconfigured" for account "myorg"
    Then the response status should be 501
    And the response should indicate status "error"
