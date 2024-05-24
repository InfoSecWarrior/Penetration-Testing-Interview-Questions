# Q. What is an API?

Application Programming Interface (API) is a **software
interface** that allows two applications to interact with
each other without any user intervention. 

**`API is a collection of software functions and procedures.`**

In simple terms, API means a software code that can be
accessed or executed.**API is defined as a code that
helps two different software's to communicate and
exchange data with each other.**

# OWASP TOP 10 API

### OWASP API Security Top 10 explained using the ACWTM framework:

**API1: Broken Object Level Authorization**

**1. Attack Type:** Unauthorized access to resources

**2. Conditions Required:**

- Access to API endpoints that use object identifiers (e.g., user IDs, file paths) without proper authorization checks.
- Ability to manipulate these object identifiers in requests.

**3. Where to Look:**

- API documentation for endpoints that accept object identifiers.
- API request and response structures.
- Source code responsible for access control logic.

**4. Tools/Script:**

- Burp Suite: Intercept and modify API requests to test access control with different object identifiers.
- API fuzzing tools to automatically generate requests with various identifier values.

**5. Mitigation:**

- Implement robust access control mechanisms that verify user permissions before granting access to resources based on the object identifier.
- Avoid exposing internal identifiers directly in URLs or responses.
- Use access tokens or other opaque identifiers with limited lifespans.

**API2: Broken Authentication**

**1. Attack Type:** Unauthorized access to the API

**2. Conditions Required:**

- Weak authentication mechanisms (basic auth, lack of multi-factor authentication).
- Vulnerabilities in authentication implementation (e.g., predictable session IDs).

**3. Where to Look:**

- API authentication documentation.
- Network traffic analysis to identify authentication protocols and potential weaknesses.
- Source code responsible for authentication logic.

**4. Tools/Script:**

- Burp Suite: Analyze authentication mechanisms and attempt brute-force attacks against login endpoints.
- Security scanners to identify common authentication vulnerabilities.

**5. Mitigation:**

- Enforce strong password policies.
- Implement multi-factor authentication.
- Regularly update authentication protocols and libraries.
- Consider token-based authentication with short lifespans.

**API3: Broken Object Property Level Authorization**

**1. Attack Type:** Unauthorized access to specific data properties within an object

**2. Conditions Required:**

- API endpoints that expose objects with multiple data properties.
- Lack of fine-grained access control for individual data properties.

**3. Where to Look:**

- API documentation for data structures and access control mechanisms.
- API request and response structures to identify exposed data properties.
- Source code responsible for access control logic.

**4. Tools/Script:**

- Burp Suite: Craft requests to access specific data properties and analyze access control behavior.
- API fuzzing tools to test access to various data properties within objects.

**5. Mitigation:**

- Implement granular access control mechanisms that verify user permissions for individual data properties within objects.
- Avoid exposing unnecessary data properties in API responses.
- Consider using data masking techniques to protect sensitive information.

**API4: Unrestricted Resource Consumption**

**1. Attack Type:** Denial-of-Service (DoS) attacks

**2. Conditions Required:**

- API endpoints that lack mechanisms to limit resource usage (CPU, memory, network bandwidth).
- Ability to send a large volume of requests to the API.

**3. Where to Look:**

- API documentation for rate limiting or resource quotas.
- Server-side logs to identify resource usage patterns.
- Source code responsible for resource management.

**4. Tools/Script:**

- Load testing tools to simulate DoS attacks by sending a high volume of requests.
- Security scanners to identify potential resource exhaustion vulnerabilities.

**5. Mitigation:**

- Implement rate limiting to restrict the number of requests per user or timeframe.
- Enforce resource quotas to limit resource consumption per request.
- Monitor API usage for suspicious activity and implement throttling mechanisms if needed.

**The remaining OWASP API Security Top 10 vulnerabilities can be explained similarly using the ACWTM framework. Here's a brief overview:**

**API5: Broken Function Level Authorization:**

- Attackers can execute unauthorized API functionalities due to lack of proper authorization checks.
- Look for API documentation, access control mechanisms, and source code responsible for authorization logic.
- Use Burp Suite and API testing tools to test access to different functionalities with various user roles.
- Implement function-level authorization checks based on user permissions.

**API6: Unrestricted Access to Sensitive Business Flows:**

- Sensitive business logic or data is exposed through APIs without proper access control.
- Analyze API functionalities and data flows to identify sensitive areas.
- Implement access control and authorization mechanisms for sensitive business logic and data.

**API7: Server-Side Request Forgery (SSRF):**

- API vulnerabilities allow attackers to craft requests that the server executes on its behalf.
- Test API functionality for potential SSRF vulnerabilities through crafted requests.
- Sanitize user input to prevent malicious code injection.
- Restrict outbound communication to authorized domains.

**API8: Security Misconfigurations:**

- Insecure CORS settings, outdated software, or disabled security features create vulnerabilities.
- Security scanning and manual review of API configurations.
- Review and correct API configurations according to security best practices.
- Update software regularly.

**API9: Improper Inventory Management:**

- APIs are not properly inventoried, documented, or monitored, increasing the attack surface.
- Manual review of documentation, network traffic analysis, API discovery tools.
- Maintain an accurate inventory of all APIs, document functionalities and access controls, implement API monitoring.

**API10: Unsafe Consumption of APIs:**

- Client applications consume APIs without proper input validation and security controls.
- Security testing of the consuming application, analyzing API consumption practices.
- Implement input validation and security controls within the consuming application.
- Consume APIs from trusted sources.

**Business Logic and Attack Scenarios:**

- **Analyzing Business Logic:** I analyze the API's business logic by:
    - Reviewing API documentation and design specifications.
    - Studying data flows and interactions between different functionalities.
    - Observing the API's behavior through testing and fuzzing.
- **Broken Object Level Authorization Example:** An attacker could exploit this by modifying user IDs in API requests. For example, if an API retrieves user data based on a simple user ID in the URL, an attacker could change their own user ID to another user's ID and potentially access their information.
- **Chaining Vulnerabilities:** Attackers can chain vulnerabilities to achieve a more significant impact. For instance, an attacker might exploit broken authentication to gain access, then leverage IDOR to access unauthorized data


# Question
**Question**
Explain the top 5 `Owasp top 10` Vulnerabilities in API and their mitigation
**Answers**
1. BOLA:
APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues. Object level authorization checks should be considered in every function that accesses a data source using an ID from the user.
**Solution**: Use an API gateway and implement object-level authorization checks. Require access tokens to permit access, and only allow access to those with the proper authorization credentials.
2. Broken User Authentication (BUA)
Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or to exploit implementation flaws to assume other user's identities temporarily or permanently. Compromising a system's ability to identify the client/user, compromises API security overall.
**Solution**: Secure user authentication, and only ensure trusted users are authenticated. Go beyond simple API keys with [OAuth flows](https://curity.io/resources/oauth/). Always consider the type of access. If it’s machine to machine access, consider adding additional layers of security such as Mutual TLS together with OAuth MTLS Sender Constrained Tokens to ensure that clients don’t misbehave and pass tokens to the wrong party.

3. Broken Object Property Level Authorization (BOPLA)
This category combines [API3:2019 Excessive Data Exposure](https://github.com/OWASP/API-Security/blob/master/editions/2019/en/0xa3-excessive-data-exposure.md) and [API6:2019 - Mass Assignment](https://github.com/OWASP/API-Security/blob/master/editions/2019/en/0xa6-mass-assignment.md), focusing on the root cause: the lack of or improper authorization validation at the object property level. This leads to information exposure or manipulation by unauthorized parties.
**Solution**: As a rule of thumb, limit data exposure to only trusted parties who need it. Ensure what is returned is only accessible by those with correct privileges. Limit API response payloads to reduce exposure. By using [OAuth Scopes and Claims](https://curity.io/resources/claims/), developers can delineate exactly who is eligible to access what. Claims can contain details about what parts of the data should be allowed to access. As an added benefit, the API code becomes simpler and more maintainable when access control is structured the same way in all APIs.
4. Broken Function Level Authorization (BFLA)
Complex access control policies with different hierarchies, groups, and roles, and an unclear separation between administrative and regular functions, tend to lead to authorization flaws. By exploiting these issues, attackers can gain access to other users’ resources and/or administrative functions
**Solutions**: Adopt OpenID Connect to help standardize user identity creation and maintenance. Avoid in-house development, and [outsource access management systems](https://curity.io/product/) to specialized tooling. Developers can also mitigate this vulnerability by adopting Scopes and Claims. By baking such criteria into an OAuth process, API providers create more user-specific access restrictions that tie identity to the requesting party. This enables more confirmed validated assertions. Also, Claims simplify the implementation of the API. Since the token carries more data, the API simply has to look and see, is Alice allowed to do Action 1?

5. Server Side Request Forgery
Server-Side Request Forgery (SSRF) flaws can occur when an API is fetching a remote resource without validating the user-supplied URI. This enables an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or a VPN.
**Solutions**: Base solutions on OAuth and OpenID Connect designs, where most URIs are configured in backend components. When user-supplied URIs such as callback endpoints are supplied, they are validated against a whitelist.

---
# Question
**Question**
What is OAuth 2.0 , explain in details what are it's scopes and grant types
- Refer for more:
	- [Article 1](https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1#:~:text=In%20essence%2C%20OAuth%20provides%20developers,application%20(the%20authorization%20server).&text=client%20application%3A%20The%20client%20application,authorization%20from%20the%20resource%20owner%20.)
	- [Article 2](https://cyberw1ng.medium.com/oauth-2-0-authentication-vulnerabilities-in-web-app-penetration-testing-2023-2895c3991bde)
	- 
**Answers**
### 1. Oauth
OAuth 2.0 is an authorization framework that allows user’s information to be accessed by third party services without revealing their credentials. Using the OAuth 2.0 the client tries to fetch resources hosted by the resource server. The Authorization server provides access tokens to the third-party services to fetch the protected resources
These are some terms that are needed to be studied first
**resource owner**: The `resource owner` is the user/entity granting access to their protected resource, such as their Twitter account Tweets

**resource server**: The `resource server` is the server handling authenticated requests after the application has obtained an `access token` on behalf of the `resource owner` . Let's say, this would be https://twitter.com

**client application**: The `client application` is the application requesting authorization from the `resource owner`. In this example, this would be https://yourtweetreader.com.

**authorization server**: The `authorization server` is the server issuing `access tokens` to the `client application` after successfully authenticating the `resource owner` and obtaining authorization. In the above example, this would be [https://twitter.com](https://twitter.com/)

**client_id**: The `client_id` is the identifier for the application. This is a public, non-secret unique identifier.

**client_secret:** The `client_secret` is a secret known only to the application and the authorization server. This is used to generate `access_tokens`

**response_type**: The `response_type` is a value to detail which type of token is being requested, such as `code`

**scope**: The `scope` is the requested level of access the `client application` is requesting from the `resource owner`

**redirect_uri**: The `redirect_uri` is the URL the user is redirected to after the authorization is complete. This usually must match the redirect URL that you have previously registered with the service

**state**: The `state` parameter can persist data between the user being directed to the authorization server and back again. It’s important that this is a unique value as it serves as a CSRF protection mechanism if it contains a unique or random value per request

**grant_type**: The `grant_type` parameter explains what the grant type is, and which token is going to be returned

**code**: This `code` is the authorization code received from the `authorization server` which will be in the query string parameter “code” in this request. This code is used in conjunction with the `client_id` and `client_secret` by the client application to fetch an `access_token`

**access_token**: The `access_token` is the token that the client application uses to make API requests on behalf of a `resource owner`

**refresh_token**: The `refresh_token` allows an application to obtain a new `access_token` without prompting the user
### 2. Scopes 
- For any OAuth grant type, the client application has to specify which data it wants to access and what kind of operations it wants to perform.
- It does this using the `scope` parameter of the authorization request it sends to the OAuth service.
- For basic OAuth, the scopes for which a client application can request access are unique to each OAuth service.
- As the name of the scope is just an arbitrary text string, the format can vary dramatically between providers.
- Some even use a full URI as the scope name, similar to a REST API endpoint.
### 3. Grant types
The OAuth grant type determines the exact sequence of steps that are involved in the OAuth process. The grant type also affects how the client application communicates with the OAuth service at each stage, including how the access token itself is sent. For this reason, grant types are often referred to as “OAuth flows”.

An OAuth service must be configured to support a particular grant type before a client application can initiate the corresponding flow. The client application specifies which grant type it wants to use in the initial authorization request it sends to the OAuth service.

There are several different grant types, each with varying levels of complexity and security considerations. We’ll focus on the “authorization code” and “implicit” grant types as these are by far the most common.

---
# Question
**Question**
Define API testing and what are the steps covered in API testing
**Answer**
API testing is a software testing strategy that ensures APIs are **stable, functional, reliable, and secure.**

API testing works by analyzing the business logic, security, application, and data responses.  
An API test is generally performed by sending requests to one or more API endpoints and weighing them with expected results.  
Some steps include:

- Validation
- Security testing
- UI testing
- Functional testing
- Load testing
- Penetration testing for security purposes
- Runtime/error detection testing
- Integration testing
- Fuzz and interoperability
- Unit testing
---
# Question
**Question**
Define different types of API , their architecture , their major security flaws and how to mitigate them in short:
**Answer**
### 1. REST (Representational State Transfer) APIs

#### Technical Characteristics:

- **Architecture**: Stateless, client-server communication, usually over HTTP.
- **Data Format**: Typically JSON or XML.
- **HTTP Methods**: CRUD operations are mapped to GET (read), POST (create), PUT/PATCH (update), and DELETE (delete).
- **Endpoints**: Resources are identified by URLs.
- **Scalability**: Highly scalable due to stateless nature.

#### Security Flaws:

- **Lack of Encryption**: Without HTTPS, data can be intercepted (Man-in-the-Middle attacks).
- **Improper Authentication**: Weak authentication methods can lead to unauthorized access.
- **Insufficient Authorization**: Failing to enforce proper access controls can allow users to perform actions they shouldn't.
- **Input Validation**: Poor input validation can lead to SQL injection, XSS, and other injection attacks.
- **Exposure of Sensitive Data**: APIs might inadvertently expose sensitive data in responses.

### 2. SOAP (Simple Object Access Protocol) APIs

#### Technical Characteristics:

- **Protocol**: XML-based protocol that uses HTTP, SMTP, or other transport protocols.
- **Data Format**: XML.
- **WS-Security**: Built-in security features like encryption, digital signatures, and more.
- **Stateful Operations**: Can maintain state between requests if necessary.

#### Security Flaws:

- **Complexity**: Complexity in parsing XML can lead to security vulnerabilities.
- **XML Attacks**: Vulnerable to XML injection, XML external entity (XXE) attacks.
- **SOAP Action Spoofing**: Attackers can spoof SOAP actions to perform unauthorized operations.
- **Transport Security**: Relies heavily on transport layer security (TLS) to protect data in transit.

### 3. GraphQL APIs

#### Technical Characteristics:

- **Query Language**: Clients request exactly the data they need using a query language.
- **Single Endpoint**: All requests are sent to a single endpoint.
- **Real-time Data**: Supports real-time data fetching through subscriptions.
- **Flexibility**: Highly flexible in terms of the data clients can request.

#### Security Flaws:

- **Complex Queries**: Can be susceptible to Denial of Service (DoS) through complex, deeply nested queries.
- **Introspection**: Introspection can expose details about the API schema that could be exploited.
- **Authorization**: Granular access control is challenging to implement and enforce.
- **Data Exposure**: Over-fetching can lead to the exposure of sensitive data if not properly controlled.

### 4. RPC (Remote Procedure Call) APIs
Example: GRPC 
#### Technical Characteristics:

- **Protocol**: Can use various protocols like JSON-RPC, XML-RPC, or gRPC.
- **Function Calls**: Mimics local procedure calls over a network.
- **Data Format**: JSON for JSON-RPC, XML for XML-RPC, and Protocol Buffers for gRPC.
- **Binary Protocol (gRPC)**: gRPC uses HTTP/2 and binary encoding for efficient communication.

#### Security Flaws:

- **Unencrypted Traffic**: Without TLS, data can be intercepted and modified.
- **Authentication**: Weak or absent authentication mechanisms can lead to unauthorized access.
- **Data Integrity**: Lack of integrity checks can lead to data tampering.
- **Injection Attacks**: Vulnerable to injection attacks if input is not properly sanitized.

### 5. WebSockets

#### Technical Characteristics:

- **Protocol**: Full-duplex communication channel over a single TCP connection.
- **Real-time Communication**: Used for real-time applications like chat, live updates, etc.
- **Data Format**: Can transmit text or binary data.

#### Security Flaws:

- **No Built-in Security**: Relies on underlying transport (TLS) for security.
- **Cross-Site WebSocket Hijacking**: Vulnerable to CSRF-like attacks.
- **Data Exposure**: Unencrypted communication can expose data to interception.
- **Rate Limiting**: Without proper rate limiting, can be vulnerable to DoS attacks.




The next questions require a scenario:
***

**Scenario:**

You are working as a security consultant for a fintech startup that has developed a RESTful API for managing user accounts and transactions. The API includes the following endpoints:

1. **Create Account**: `POST /api/accounts`
2. **Read Account**: `GET /api/accounts/{account_id}`
3. **Update Account**: `PUT /api/accounts/{account_id}`
4. **Delete Account**: `DELETE /api/accounts/{account_id}`
5. **Create Transaction**: `POST /api/accounts/{account_id}/transactions`
6. **Read Transaction**: `GET /api/accounts/{account_id}/transactions/{transaction_id}`
7. **Update Transaction**: `PUT /api/accounts/{account_id}/transactions/{transaction_id}`
8. **Delete Transaction**: `DELETE /api/accounts/{account_id}/transactions/{transaction_id}`

The API uses JSON Web Tokens (JWT) for authentication and authorization. The JWTs include claims such as `user_id`, `role`, and `account_id`. The roles can be `user` or `admin`.

Your task is to identify and address potential security vulnerabilities in this API. Consider the following aspects:

1. **Authentication and Authorization**: Ensure that only authorized users can perform specific actions. For example, only an `admin` should be able to delete an account.
    
2. **Data Validation and Sanitization**: Protect against common attacks such as SQL Injection, Cross-Site Scripting (XSS), and data tampering.
    
3. **Rate Limiting and Throttling**: Prevent abuse of the API through rate limiting and throttling.
    
4. **Logging and Monitoring**: Ensure that all critical actions are logged and can be monitored for suspicious activity.
***
# Question
**API Security Challenge: Securing CRUD Operations**
**Question:**

Identify and describe in detail at least five potential security vulnerabilities in the provided API endpoints. For each vulnerability, propose a solution that enhances the security of the API. Your answer should cover aspects of authentication, authorization, data validation, rate limiting, logging, and monitoring.

**Example Answer:**

1. **Vulnerability: Insufficient Authorization Checks**
    
    - **Description**: The API allows any authenticated user to perform operations on any account or transaction without verifying their ownership or role.
    - **Solution**: Implement fine-grained authorization checks. For example, in the `PUT /api/accounts/{account_id}` endpoint, ensure that the `account_id` in the JWT matches the `account_id` in the request URL. Additionally, verify that the user has the necessary role (`admin` for deleting accounts).
2. **Vulnerability: Lack of Input Validation and Sanitization**
    
    - **Description**: The API does not validate or sanitize user input, making it vulnerable to SQL Injection and XSS attacks.
    - **Solution**: Implement input validation and sanitization using a validation library. Ensure that all user inputs are properly escaped and validated against expected formats.
3. **Vulnerability: No Rate Limiting**
    
    - **Description**: The API does not implement rate limiting, allowing an attacker to brute force or overwhelm the API with requests.
    - **Solution**: Implement rate limiting and throttling using a middleware or API gateway. For example, limit each user to a maximum of 100 requests per minute.
4. **Vulnerability: Insufficient Logging and Monitoring**
    
    - **Description**: The API does not log critical actions or monitor for suspicious activity, making it difficult to detect and respond to attacks.
    - **Solution**: Implement logging for all critical actions (e.g., account creation, deletion, and transaction operations). Use a monitoring service to alert on suspicious activities such as multiple failed login attempts or unusual API usage patterns.
5. **Vulnerability: Insecure Transmission of Data**
    
    - **Description**: The API does not enforce HTTPS, potentially exposing sensitive data to man-in-the-middle attacks.
    - **Solution**: Enforce HTTPS for all API endpoints. Use an SSL/TLS certificate to encrypt data in transit and configure the server to redirect all HTTP requests to HTTPS.

---
# Question
Identify and describe in detail at least five potential security vulnerabilities related to JWT handling and API endpoints. For each vulnerability, propose a solution that enhances the security of the API. Your answer should cover aspects of JWT handling, authentication, authorization, data validation, rate limiting, logging, and monitoring.

**Example Answer:**

1. **Vulnerability: Insecure Storage of JWTs**
    
    - **Description**: Storing JWTs in local storage or session storage can expose them to XSS attacks.
    - **Solution**: Store JWTs in HTTP-only secure cookies to mitigate the risk of XSS attacks. Ensure that cookies are marked as `Secure` and `HttpOnly`.
2. **Vulnerability: Insufficient JWT Expiration Handling**
    
    - **Description**: JWTs with long expiration times increase the risk if a token is compromised.
    - **Solution**: Set a short expiration time for JWTs and implement refresh tokens to obtain new JWTs. This reduces the risk window in case a JWT is compromised.
3. **Vulnerability: Lack of Role-Based Access Control (RBAC)**
    
    - **Description**: The API does not enforce role-based access control, allowing any authenticated user to perform administrative actions.
    - **Solution**: Implement RBAC by checking the `role` claim in the JWT before performing sensitive operations. Ensure that only users with the `admin` role can delete patient records.
4. **Vulnerability: No JWT Signature Validation**
    
    - **Description**: Failing to validate the JWT signature allows attackers to forge tokens.
    - **Solution**: Always validate the JWT signature using a robust JWT library. Ensure that the token is signed using a secure algorithm (e.g., HS256, RS256) and the correct secret or public key.
5. **Vulnerability: Insecure Transmission of JWTs**
    
    - **Description**: Transmitting JWTs over unsecured channels (HTTP) exposes them to interception and replay attacks.
    - **Solution**: Enforce HTTPS for all API endpoints to ensure that JWTs are transmitted securely. Use an SSL/TLS certificate to encrypt data in transit and redirect all HTTP requests to HTTPS.
6. **Vulnerability: Insufficient Logging and Monitoring of JWT Usage**
    
    - **Description**: The API does not log JWT usage, making it difficult to detect and respond to suspicious activity.
    - **Solution**: Implement logging for all actions performed with JWTs. Monitor for unusual patterns such as multiple failed login attempts, token reuse, or access to sensitive endpoints.
7. **Vulnerability: Missing Claims Validation**
    
    - **Description**: The API does not validate the claims within the JWT, such as `exp`, `iat`, and `aud`.
    - **Solution**: Validate all relevant claims within the JWT. Ensure that the token is not expired (`exp`), was issued at a valid time (`iat`), and is intended for the correct audience (`aud`).
