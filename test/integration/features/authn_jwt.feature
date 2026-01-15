Feature: JWT Authentication
  As a Conjur user
  I want to authenticate using JWT tokens
  So that I can use external identity providers

  Background:
    Given a Conjur server is running
    And an account "myorg" exists with admin user

  Scenario: Successful JWT authentication with inline public keys
    Given I am authenticated as "admin" in account "myorg"
    And I load the following policy to "root":
      """
      - !policy
        id: conjur/authn-jwt/raw
        body:
        - !webservice

        - !variable
          id: public-keys

        - !variable
          id: issuer

        - !variable
          id: token-app-property

        - !group hosts

        - !permit
          role: !group hosts
          privilege: [ read, authenticate ]
          resource: !webservice

      - !host
        id: myapp

      - !grant
        role: !group conjur/authn-jwt/raw/hosts
        member: !host myapp
      """
    And I set authn-jwt "raw" variable "public-keys" with test JWKS
    And I set authn-jwt "raw" variable "issuer" to "test-issuer"
    And I set authn-jwt "raw" variable "token-app-property" to "sub"
    And the authn-jwt "raw" authenticator is enabled
    When I authenticate via authn-jwt with a valid JWT token for host "myapp"
    Then the response status should be 200
    And the response should contain a Conjur access token

  Scenario: JWT authentication fails with invalid signature
    Given I am authenticated as "admin" in account "myorg"
    And I load the following policy to "root":
      """
      - !policy
        id: conjur/authn-jwt/raw
        body:
        - !webservice

        - !variable
          id: public-keys

        - !variable
          id: issuer

        - !group hosts

        - !permit
          role: !group hosts
          privilege: [ read, authenticate ]
          resource: !webservice

      - !host
        id: myapp

      - !grant
        role: !group conjur/authn-jwt/raw/hosts
        member: !host myapp
      """
    And I set authn-jwt "raw" variable "public-keys" with test JWKS
    And I set authn-jwt "raw" variable "issuer" to "test-issuer"
    And the authn-jwt "raw" authenticator is enabled
    When I authenticate via authn-jwt with an invalid JWT token for host "myapp"
    Then the response status should be 401

  Scenario: JWT authentication fails when authenticator not enabled
    Given a JWT authenticator "disabled" is configured but not enabled
    When I authenticate via authn-jwt with service "disabled"
    Then the response status should be 403

  Scenario: JWT authentication fails when authenticator not configured
    When I authenticate via authn-jwt with service "nonexistent"
    Then the response status should be 404
