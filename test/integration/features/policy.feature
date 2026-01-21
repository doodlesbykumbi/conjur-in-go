Feature: Policy Management
  As a Conjur administrator
  I want to load and manage policies
  So that I can define access control rules

  Background:
    Given a Conjur server is running
    And an account "myorg" exists with admin user
    And I am authenticated as "admin" in account "myorg"

  Scenario: Load a simple policy
    When I load the following policy to "root":
      """yaml
      - !user alice
      - !user bob
      - !group developers
      - !grant
        role: !group developers
        member: !user alice
      """
    Then the response status should be 201
    And the policy version should be greater than 0
    And user "alice" should exist in account "myorg"
    And user "bob" should exist in account "myorg"
    And group "developers" should exist in account "myorg"

  Scenario: Load policy with variables
    When I load the following policy to "root":
      """yaml
      - !policy
        id: app
        body:
          - !variable db-password
          - !variable api-key
      """
    Then the response status should be 201
    And variable "app/db-password" should exist in account "myorg"
    And variable "app/api-key" should exist in account "myorg"

  Scenario: Policy dry-run validation
    When I validate the following policy for "root":
      """yaml
      - !user testuser
      - !variable test/secret
      """
    Then the response status should be 200
    And the response should indicate dry-run mode
    And user "testuser" should not exist in account "myorg"

  Scenario: Empty policy body returns error
    When I load an empty policy to "root"
    Then the response status should be 400

  Scenario: Invalid YAML returns error
    When I attempt to load the following policy to "root":
      """
      this is not valid yaml: [[[
      """
    Then the response status should be 422

  Scenario: PUT method replaces policy
    When I replace the policy "root" with:
      """yaml
      - !user charlie
      """
    Then the response status should be 201
    And user "charlie" should exist in account "myorg"

  Scenario: PATCH method updates policy
    When I update the policy "root" with:
      """yaml
      - !user dave
      """
    Then the response status should be 201
    And user "dave" should exist in account "myorg"
