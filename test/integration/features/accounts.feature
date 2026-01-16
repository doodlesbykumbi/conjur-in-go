Feature: Account Management
  As a Conjur administrator
  I want to manage accounts via API
  So that I can create and manage organization accounts

  Background:
    Given a Conjur server is running

  Scenario: List accounts returns empty initially
    When I request the accounts list
    Then the response status should be 200

  Scenario: Create a new account
    When I create an account "testaccount"
    Then the response status should be 201
    And the response should contain an API key
    When I request the accounts list
    Then the response should contain account "testaccount"

  Scenario: Delete an account
    When I create an account "deleteme"
    Then the response status should be 201
    When I delete the account "deleteme"
    Then the response status should be 204
    When I request the accounts list
    Then the response should not contain account "deleteme"

  Scenario: Cannot create duplicate account
    When I create an account "duplicate"
    Then the response status should be 201
    When I create an account "duplicate"
    Then the response status should be 409

  Scenario: Cannot delete non-existent account
    When I delete the account "nonexistent"
    Then the response status should be 404

  Scenario: Retrieve API key for admin role
    When I create an account "keytest"
    Then the response status should be 201
    And the response should contain an API key
    When I retrieve the key for role "keytest:user:admin"
    Then the retrieved key should match the original API key
