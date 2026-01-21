Feature: Authorization (RBAC)
  As a Conjur administrator
  I want to control access to resources
  So that only authorized users can access sensitive data

  Background:
    Given a Conjur server is running
    And an account "myorg" exists with admin user
    And I am authenticated as "admin" in account "myorg"

  Scenario: User with permission can read secret via group membership
    Given I load the following policy to "root":
      """
      - !user alice
      - !group secret-readers
      - !variable protected/secret
      - !grant
        role: !group secret-readers
        member: !user alice
      - !permit
        role: !group secret-readers
        privileges: [read, execute]
        resource: !variable protected/secret
      """
    And the variable "protected/secret" has value "group-accessible-secret"
    And I authenticate as "alice" in account "myorg" with the correct API key
    When I retrieve the variable "protected/secret"
    Then the response status should be 200
    And the response body should be "group-accessible-secret"

  Scenario: User without permission cannot read secret
    Given I load the following policy to "root":
      """
      - !user bob
      - !variable private/secret
      """
    And the variable "private/secret" has value "private-value"
    And I authenticate as "bob" in account "myorg" with the correct API key
    When I retrieve the variable "private/secret"
    Then the response status should be 403

  Scenario: Owner has implicit access to owned resources
    Given I load the following policy to "root":
      """
      - !variable admin-owned/secret
      """
    And the variable "admin-owned/secret" has value "owner-accessible"
    When I retrieve the variable "admin-owned/secret"
    Then the response status should be 200
    And the response body should be "owner-accessible"
