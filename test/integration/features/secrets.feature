Feature: Secrets Management
  As a Conjur user
  I want to store and retrieve secrets
  So that I can manage sensitive data securely

  Background:
    Given a Conjur server is running
    And an account "myorg" exists with admin user
    And I am authenticated as "admin" in account "myorg"

  Scenario: Store and retrieve a secret
    Given a variable "db/password" exists in account "myorg"
    And I have "update" permission on "myorg:variable:db/password"
    And I have "execute" permission on "myorg:variable:db/password"
    When I store the value "super-secret-123" in variable "db/password"
    Then the response status should be 201
    When I retrieve the variable "db/password"
    Then the response status should be 200
    And the response body should be "super-secret-123"

  Scenario: Retrieve non-existent secret
    Given a variable "empty/var" exists in account "myorg"
    And I have "execute" permission on "myorg:variable:empty/var"
    When I retrieve the variable "empty/var"
    Then the response status should be 404

  Scenario: Store secret without permission
    Given a variable "restricted/secret" exists in account "myorg"
    When I store the value "should-fail" in variable "restricted/secret"
    Then the response status should be 403

  Scenario: Batch retrieve secrets
    Given a variable "app/db-host" exists in account "myorg"
    And a variable "app/db-port" exists in account "myorg"
    And I have "execute" permission on "myorg:variable:app/db-host"
    And I have "execute" permission on "myorg:variable:app/db-port"
    And the variable "app/db-host" has value "localhost"
    And the variable "app/db-port" has value "5432"
    When I batch retrieve variables "myorg:variable:app/db-host,myorg:variable:app/db-port"
    Then the response status should be 200
    And the response should contain secret "myorg:variable:app/db-host" with value "localhost"
    And the response should contain secret "myorg:variable:app/db-port" with value "5432"
