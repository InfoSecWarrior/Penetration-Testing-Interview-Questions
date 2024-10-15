## What is an API?

API stands for Application Programming Interface. It provides a computer-friendly method for interacting between client and server. API acts as a bridge that enables different applications, services, or platforms to interact with each other, share information, and perform specific tasks. using web, Mobile App, Cloud Computing and more.


## What are the types of API?

1. Private APIs: Private APIs are internal to an enterprise and are only used for connecting systems and data within the business.

2. Public APIs: They are open to the public and may be used by anyone. There may not be some authorization and cast associated with these types of APIs.

3. Partner APIs: These are only accessible by authorized external developers to aid business-to-business partnerships.

4. Composite APIs: These combine two or more different APIs to address complex system requirements or behaviors.

## What are the different types of API ? 
**based on** : architectural styles or protocols used to build APIs.

- ## RESTful API

Rest stands for **Representational State Transfer**. Restful API is commonly used in web development to build scalable and efficient web services. Restful APIs provided a standardized and scalable approach building web services that can be consumed by various client access by different platforms. This is stateless and HTTP request methods used for interaction are GET,PUT,POST,DELETE. 

- ## GraphQL API

GraphQL is an API query language and runtime designed for flexible and efficient data retrieval from the server. It allows clients to specify exactly the data they need, which helps prevent over-fetching or under-fetching of data. Unlike RESTful APIs, which often require multiple endpoints to access different resources, GraphQL APIs typically have a single endpoint to handle all queries and mutations (data modifications).

A key feature of GraphQL is its schema, which is defined in a specific syntax and describes the types of data available and the relationships between them. The schema defines the structure of the API, including queries, mutations, and subscriptions. However, GraphQL does not use SQL. Instead, it uses its own language for defining the schema and querying the API.
- ## SOAP API

SOAP stands for Simple Object Access Protocol. SOAP API is commonly used in enterprise applications to build secure and reliable web services. Unlike RESTful APIs, SOAP APIs provide a more formalized and structured approach to communication between systems, especially when higher levels of security and transactional reliability are needed.

SOAP APIs rely on XML to encode their messages and use a WSDL (Web Services Description Language) to define the operations available, the format of messages, and the data types used. SOAP APIs can work over a variety of protocols like HTTP, SMTP, or TCP, not just HTTP. SOAP messages consist of an envelope that includes headers, body, and fault elements for error handling.

SOAP can be stateful or stateless, depending on the specific use case. It provides built-in features for security (via WS-Security) and transaction handling, making it suitable for complex, mission-critical applications.
## What is API Pentesting?


API penetration testing, or API pentesting, is a cybersecurity assessment that evaluates the security of an application programming interface (API). It involves simulating real-world cyber attacks to identify vulnerabilities, improper configurations, and design flaws. The goal is to strengthen the API's security and protect sensitive information from unauthorized access and data breaches since the logic for the API is a little bit different from backend due to the fact that it acts as middle man for handling data two-and-fro that's why it requires a dedicated pentest.

**To perform an API pentest effectively, organizations use a standard awareness document for developers and web application security i.e OWASP TOP 10 API.**
 
 # OWASP TOP 10 :

## Broken Object-Level Authorization 

Broken object-level authorization is a critical API security vulnerability that allows attackers to gain unauthorized access to sensitive data by bypassing authorization checks. Attackers do this by manipulating object ID values, parameters, and
authorization frameworks.
1. Verify that implement authorization checks with user policies and
hierarchy
2. Verify that API implementation does not rely on IDs sent from the client,
instead API should check IDs stored objects in the session.
3. Verify that server configuration is hardened as per the
recommendation of the application server and framework in use.
4. Verify that , API implementation checks authorization each time there
is a client request to access the database.
5. Verify that API is not using random guessable IDs ( UUIDs)

## Broken Authentication

Broken authentication and session management can enable attackers to impersonate valid users and compromise data privacy and infrastructure.
1. Verify all possible ways to authenticate all APIs
2. Verify that password reset APIs and one-time links also allow users to authenticate and should be strictly protected.
3. Verify API implements standards authentication, token generation, password storage, and Multi-factor authentication.
4. Verify that API uses stricter rate-limiting for authentication,
and implement lockout policies and weak password checks.



