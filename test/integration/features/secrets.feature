Feature: Secrets Management
  As a Conjur user
  I want to store and retrieve secrets
  So that I can manage sensitive data securely

  Background:
    Given a Conjur server is running
    And an account "myorg" exists with admin user
    And I am authenticated as "admin" in account "myorg"

  Scenario: Store and retrieve a secret
    Given I load the following policy to "root":
      """
      - !variable db/password
      """
    When I store the value "super-secret-123" in variable "db/password"
    Then the response status should be 201
    When I retrieve the variable "db/password"
    Then the response status should be 200
    And the response body should be "super-secret-123"

  Scenario: Retrieve non-existent secret
    Given I load the following policy to "root":
      """
      - !variable empty/var
      """
    When I retrieve the variable "empty/var"
    Then the response status should be 404

  Scenario: Store secret without permission
    Given I load the following policy to "root":
      """
      - !user limited-user
      - !variable restricted/secret
      - !permit
        role: !user limited-user
        privilege: [ execute ]
        resource: !variable restricted/secret
      """
    And I authenticate as "limited-user" in account "myorg" with the correct API key
    When I store the value "should-fail" in variable "restricted/secret"
    Then the response status should be 403

  Scenario: Batch retrieve secrets
    Given I load the following policy to "root":
      """
      - !variable app/db-host
      - !variable app/db-port
      """
    And the variable "app/db-host" has value "localhost"
    And the variable "app/db-port" has value "5432"
    When I batch retrieve variables "myorg:variable:app/db-host,myorg:variable:app/db-port"
    Then the response status should be 200
    And the response should contain secret "myorg:variable:app/db-host" with value "localhost"
    And the response should contain secret "myorg:variable:app/db-port" with value "5432"

  Scenario: Expired secret returns 404
    Given I load the following policy to "root":
      """
      - !variable rotating/secret
      """
    And the variable "rotating/secret" has value "rotating-value"
    And the variable "rotating/secret" has expired
    When I retrieve the variable "rotating/secret"
    Then the response status should be 404

  Scenario: Expire endpoint clears expiration
    Given I load the following policy to "root":
      """
      - !variable expirable/secret
      """
    And the variable "expirable/secret" has value "expirable-value"
    And the variable "expirable/secret" has expired
    When I expire the variable "expirable/secret"
    Then the response status should be 201
    When I retrieve the variable "expirable/secret"
    Then the response status should be 200
    And the response body should be "expirable-value"

  Scenario: Retrieve latest version of secret with multiple versions
    Given I load the following policy to "root":
      """
      - !variable versioned/secret
      """
    When I store the value "version-1" in variable "versioned/secret"
    And I store the value "version-2" in variable "versioned/secret"
    And I store the value "version-3" in variable "versioned/secret"
    And I retrieve the variable "versioned/secret"
    Then the response status should be 200
    And the response body should be "version-3"

  Scenario: Expire non-variable kind returns 422
    Given I load the following policy to "root":
      """
      - !group test-group
      """
    When I attempt to expire the resource "group" "test-group"
    Then the response status should be 422
