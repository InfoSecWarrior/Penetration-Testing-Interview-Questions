# Q1. What is OSI model?

The OSI model, which stands for Open Systems Interconnection, is a conceptual framework that describes how data is transmitted between computer systems on a network. Developed by the International Organization for Standardization (ISO) in 1984, it serves as a universal language for network communication.

# Q2. What is Kerbroasting?

It's a post-exploitation attack. This means an attacker already has access to a compromised user account within the network. They then leverage this foothold to target a specific type of account called a Service Principal Name (SPN).

SPN stands for Service Principal Name. It's a unique identifier used in Kerberos authentication, a security protocol within Microsoft Active Directory environments.

SPN are used in the network but if the user we are logged into don’t have SPN assigned then you cant perform kerbroasting attack.

## Impact:

- **Elevated access:** They can bypass user limitations and access sensitive data or systems.
- **Lateral movement:** They can use compromised accounts to pivot across the network, expanding their reach.

## Mitigation:

- **Strong Password Hygiene:** Enforce complex and lengthy passwords (at least 25 characters) for both user and service accounts. Regularly rotate service account passwords (ideally every 30 days) and avoid weak encryption like RC4.
- **Least Privilege Principle:** Grant SPNs only to necessary services and restrict access privileges for service accounts. This minimizes potential damage if an account is compromised.

# Q3. What is asreproasting?

**ASREP Roasting is a sophisticated password-cracking technique that exploits a vulnerability within the Kerberos authentication protocol.** It specifically targets the **Authentication Service Response (AS-REP) message** exchanged during the authentication process.

How it works?

- **Initiate Connection (User A -> KDC):** An arrow points from the Compromised User Account (User A) towards the Kerberos KDC. This signifies User A initiating a connection with the KDC to request an authentication ticket (typically done by applications when they need to access a service).
- **AS-REQ Message (User A -> KDC):** Another arrow points from User A to the KDC labeled "AS-REQ." This represents the Authentication Service Request message sent by User A to the KDC. This message typically contains the user's username and might include a timestamp (depending on pre-authentication settings).
- **Vulnerable Configuration (KDC):** A small notation can be placed near the KDC indicating "Pre-auth Disabled" or "Weak Encryption (RC4)." This represents the vulnerability being exploited in ASREP Roasting, where pre-authentication is not required or weak encryption is used.
- **AS-REP Message (KDC -> User A):** An arrow points from the KDC back to User A labeled "AS-REP." This represents the Authentication Service Response message sent by the KDC back to User A. This message contains the encrypted ticket-granting ticket (TGT) for User A.
- **Intercepted AS-REP (Attacker -> Network):** An arrow originates from the Attacker System and intersects the AS-REP message arrow between the KDC and User A. This represents the attacker intercepting the AS-REP message traveling over the network.
- **Extracted Hash (Attacker System):** The Attacker System section can have a sub-section labeled "Hash Extraction." This represents the process where the attacker extracts the encrypted password hash from the intercepted AS-REP message (possible due to the vulnerability).
- **Offline Cracking (Attacker System):** An arrow points from the "Hash Extraction" section within the Attacker System to a separate box labeled "Offline Cracking." This represents the attacker transferring the extracted hash to a separate program for offline password cracking using brute-force or rainbow tables.
- **Cracked Password (Offline Cracking -> Attacker System):** An arrow points from the "Offline Cracking" box back to the Attacker System labeled "Cracked Password." This represents the attacker successfully cracking the password hash and obtaining the user's password.

## Impact:

ASREP Roasting, a devious Kerberos attack, targets the AS-REP message to steal password hashes. These stolen hashes are then cracked offline, allowing attackers to infiltrate user accounts and potentially escalate privileges. This can lead to compromised data, disrupted operations, and severe damage to an organization's security posture.

## Mitigation:

- **Enforce strong passwords:** Complex passwords make hash cracking much harder.
- **Enable pre-authentication:** This extra step thwarts ASREP Roasting's core method.
- **Patch Kerberos systems:** Address vulnerabilities that attackers might exploit for initial access.

# Q4. What is ldap and its attack types?

LDAP (Lightweight Directory Access Protocol)

is an industry-standard protocol for accessing and managing directory services over a network. Think of it like a giant electronic phonebook that stores information about users, groups, printers, and other resources within a network. Here's what LDAP offers:

- **Centralized Management:** LDAP provides a central location to store and manage all this directory information, making it easier to control access and keep everything organized.
- **Standardized Access:** It uses a standardized protocol that allows different applications and services to interact with the directory data in a consistent way.
- **Scalability:** LDAP can handle large directories with many entries, making it suitable for organizations of all sizes.

# Attack type:

**LDAP Injection:**

- This attack exploits vulnerabilities in applications that use user input to construct LDAP queries.
- Attackers can inject malicious code into these queries, tricking the LDAP server into performing unauthorized actions.
- These actions could include stealing sensitive data, adding new user accounts, or even taking control of the entire directory server.

## Scenario:

A website allows users to log in with a username and password. The website uses LDAP to authenticate users against a directory server. The login form has a field for username and password, and when submitted, it constructs an LDAP query to check if the username and password combination is valid.

## Impact

- **Unauthorized Access:** Attackers can gain access to user accounts, potentially including privileged accounts, compromising system security.
- **Data Breaches:** Sensitive information stored in the LDAP directory, like usernames, passwords (hashed), or user data, can be stolen and exposed.
- **Disrupted Operations:** Attackers might manipulate or delete directory information, leading to service outages and hindering critical business processes.
- **Lateral Movement:** Using compromised accounts, attackers can pivot across the network, gaining access to additional resources and escalating their privileges.
- **Reputational Damage:** Data breaches and security incidents can damage trust and lead to legal repercussions.

## Mitigation:

- **Sanitize user input:** Always validate and sanitize user input before using it to construct LDAP queries. This helps prevent malicious code injection.
- **Use prepared statements:** Utilize libraries that provide prepared statements for building LDAP queries. This helps prevent code injection by separating data from the query itself.
- **Strong password policies:** Enforce complex passwords to make brute-force attacks less effective.
- **Keep LDAP software updated:** Regularly patch LDAP servers and applications to address known vulnerabilities.

## Payloads

```jsx
*
(objectClass=*)
*))
(&(username=admin)(password=*))
(&(username=admin)(password=password))
(&(sn=*)(password=*)(sn=a*))
)(|(password=*))
(&(username=admin)(password=\\*))
*)(userPassword=newPassword
username=*'(password=*)
```

# Q5. How are Group Policy Objects (GPOs) stored in Active Directory?

- **Policy information:** Stored in the Active Directory database itself.
- **Policy settings:** Located in Group Policy Templates (GPTs) on the SYSVOL folder of domain controllers.


# Q6. **What is the difference between hub and switch?**

**Ans.** A hub is a networking device that connects multiple computers together, while a switch is a control unit that turns the flow of electricity in a circuit.

_**Must Read – [Difference Between Hub And Switch](https://www.shiksha.com/online-courses/articles/difference-between-hub-and-switch/)**_

# Q7. **What is an intranet?**

**Ans.** It is a private network based on TCP/IP protocols accessible only by the company’s members or someone authorized.

# Q8. **What are the different types of network security mechanism ?**

**Ans.** The different types of network security mechanism are:

- Access control
- Antivirus and antimalware software
- Data Loss Prevention (DLP)
- Email security
- Firewalls
- Intrusion prevention systems
- Host-based Intrusion Detection System (HIDS)
- Network Intrusion Detection System (NIDS)
- Network segmentation
- Virtual Private Network (VPN)
- Wireless security

# Q9. What is IDS/IPS?

IDS and IPS are both security systems that protect your network from malicious activity.

They can be deployed as hardware devices or software applications. Here's a breakdown of what each does:

```
Intrusion Detection System (IDS): An IDS acts like a security guard that monitors your network traffic for suspicious activity. It compares network activity to predefined rules and identifies potential threats. If it finds something fishy, it raises an alarm for a security administrator to investigate.  Think of it as a tripwire that goes off when something unexpected happens.

Intrusion Prevention System (IPS): An IPS is more like a bouncer at a club. It also monitors traffic but actively blocks any attempts to exploit vulnerabilities or gain unauthorized access to your network.  In other words, it doesn't just raise an alarm, it takes steps to stop the threat immediately.

```

# Q10.  **Explain Stateful Inspection.**

**Ans.** Also known as dynamic packet filtering, Stateful Inspection is a firewall technology that monitors the state of active network connections. It keeps track of all activities right from the opening of a connection until it is closed. It allows or blocks traffic based on state, port, and protocol by utilizing the information regarding active connections.

# Q11.**What are the different types of phishing attacks?**

Ans. The different types of phishing attacks are:

1. **Email Phishing:** This is the most common type of Phishing. The phisher will register a fake domain that looks like a genuine source and send generic requests to obtain confidential information from the victims. Phishers use the data to steal money or to launch other attacks.
2. **Spear Phishing:** It targets specific individuals instead of a wide group of people after searching the victims on social media and other sites to customize their communications and appear more authentic.
3. **Whaling:** In this, the attackers go after those working in senior positions. Attackers spend considerable time profiling the target to find the best way to steal their sensitive information.
4. **Smishing and Vishing:** In smishing, the victim is contacted through text messages, while vishing involves a telephonic conversation. Both end goals are the same as any other kind of phishing attack.

# Q12. What are the difference between encoding, encryption and hashing?

Encoding,encryption, and hashing all transform data, but they serve different purposes:

Encoding focuses on preserving usability. It converts data from one format to another that's more suitable for a particular system. Here's the breakdown:

```
** reversible process:** Encoded data can be decoded back to its original form.
** no keys involved:** Encoding algorithms are generally public knowledge.
** examples:**
    Base64 encoding for sending binary data over email.
    Unicode encoding for displaying characters from different languages.

```

Encryption prioritizes confidentiality. It scrambles data to make it unreadable for unauthorized users:

```
irreversible process (without key): Encrypted data requires a decryption key to be converted back.
uses keys: Encryption relies on secret keys to encrypt and decrypt data.
** examples:**
    Securing passwords before storing them in a database.
    Encrypting files to protect sensitive information.

```

Hashing ensures data integrity. It creates a unique mathematical fingerprint of the data:

```
irreversible process: There's no way to get the original data back from the hash.
no keys involved: Hashing algorithms are public, but the key is the original data itself.
** examples:**
    Verifying file downloads haven't been corrupted during transfer.
    Checking password authenticity during login (by comparing hashed password with stored hash).

```

# Q13. What is the Public Key Encryption?

Public key encryption,

also known as asymmetric encryption, is a cryptographic method that uses two mathematically linked keys for encryption and decryption: a public key and a private key. Here's how it works:

Imagine a secure mailbox with two special locks:

```
Public Lock (Public Key): This lock is widely distributed and known to anyone. You can give a copy to anyone you want to send you encrypted messages.
Private Lock (Private Key): This lock is top secret. You keep it safe and never share it with anyone. It's the only key that can open the mailbox once something has been locked with the public key.

```

# Q14. What are proxy servers and how do they protect computer networks?

Proxy servers act as intermediaries between your computer and the internet,

adding an extra layer of security and functionality to your network. Here's how they work and how they benefit your computer's security:

The Go-Between:

```
Imagine a proxy server as a gatekeeper or traffic director. When you request a website on your browser, the request goes to the proxy server first, instead of directly to the website.

The proxy server then fetches the website on your behalf and delivers the content to you

```

- **Content Filtering:** Organizations can configure proxy servers to block access to certain websites or types of content, promoting a safer browsing environment and potentially improving network efficiency.
- **Malware Protection:** Some proxy servers can act as a basic firewall, filtering out malicious content or websites known to harbor malware that could harm your computer.

# Q15. What is DMZ Zone ?

In the world of cybersecurity, a DMZ, which stands for Demilitarized Zone, functions as a special network that sits between an organization's trusted internal network and the untrusted external network, most commonly the internet. Imagine it as a buffer zone or a controlled access area.

# Q16. What is difference between stateful and stateless firewall ?

**Stateful Firewall**

- **Tracks Connections:** A stateful firewall maintains a record of ongoing connections, also known as sessions. It analyzes these connections to determine if traffic is legitimate.
- **Deeper Inspection:** Stateful firewalls inspect data packets beyond just header information. They can examine the content and context of communication, allowing for more sophisticated security measures.
- **Advanced Features:** Stateful firewalls often offer features like application-level inspection, which can identify and block malicious traffic based on specific protocols or applications.
- **Better Security:** Stateful firewalls provide a higher level of security compared to stateless firewalls due to their in-depth analysis and tracking of connections.

**Stateless Firewall**

- **Basic Packet Filtering:** A stateless firewall works on a packet-by-packet basis. It examines the header information of each data packet, such as source and destination IP addresses and port numbers, to make filtering decisions.
- **Limited Context:** Stateless firewalls don't maintain information about ongoing connections. Each packet is treated independently, without considering its relation to previous packets.
- **Faster Performance:** Due to the simpler inspection process, stateless firewalls generally offer faster performance than stateful firewalls.
- **Simpler Management:** Stateless firewalls are easier to set up and manage compared to stateful firewalls due to their less complex nature.

# Q17. What is active directory objects?

Active Directory (AD) objects are the fundamental building blocks of an Active Directory domain network. They represent various resources on the network, and each object has a set of attributes that define its properties and functionalities. Here's a deeper dive into what AD objects are and how they work:

**Types of Active Directory Objects**

There are numerous types of AD objects, each catering to specific resources within the network. Here are some common examples:

- **User Objects:** Represent individual user accounts within the domain. They contain attributes like username, password (hashed for security), name, email address, and group memberships.
- **Group Objects:** Define collections of users. They simplify permission management by allowing administrators to assign rights to entire groups instead of individual users.
- **Computer Objects:** Represent computers and devices joined to the domain. These objects contain information like device name, operating system, location, and security settings.
- **Organizational Unit (OU) Objects:** Help organize other AD objects hierarchically within the directory structure. Think of them as folders within AD to categorize and manage resources logically.
- **Printer Objects:** Represent printers available on the network. They contain details like printer name, model, location, and permissions for user access.

# Q18. Where is the user database stored in Active directory?

In Active Directory, the user database isn't stored in a single, traditional database file like some applications might use. Instead, the user information is distributed across a network of servers called **domain controllers (DCs)**.

Here's a breakdown of how user data is stored in Active Directory:

- **Distributed Storage:** Each domain controller within the domain holds a replica of the entire directory database, including user objects and their attributes. This ensures redundancy and availability of user information even if one domain controller goes offline.
- **NTDS.dit File:** The core of this directory database resides on each domain controller in a file called NTDS.dit. This file uses a proprietary format specifically designed for Active Directory.
- **Replication Process:** Domain controllers constantly replicate changes made to the directory database with each other. This replication ensures that all domain controllers have identical copies of the user information and other AD objects.

# Q19. Lateral escalation in Active directory?

**1. Pass-the-Hash (PtH):** Attackers steal password hashes and use them to access other systems without needing the actual password.

- **Defense:** Enforce strong password policies, enable Multi-Factor Authentication (MFA), and consider using techniques like Hash-Based Credential Signing (HBMC).

**2. Pass-the-Ticket (PtT):** Attackers steal Kerberos tickets used for authentication and use them to impersonate legitimate users.

- **Defense:** Limit service account privileges, enable Kerberos ticket lifetime policies, and monitor for suspicious ticket requests.

**3. Golden Ticket Attack:** Attackers forge a Kerberos ticket granting them access to any domain resource using a compromised Domain Controller (DC) account.

- **Defense:** Secure your domain controllers with strong passwords and monitor for unauthorized access attempts.

**4. Silver Ticket Attack:** Attackers exploit a trusted relationship between domains to forge tickets for resources in another domain.

- **Defense:** Review trust configurations between domains and implement least privilege for accounts used in trusts.

**5. Forced Authentication:** Attackers trick a user into authenticating to a malicious website or service, stealing their credentials.

- **Defense:** Educate users about phishing attempts and implement email security measures.

**6. Exploiting Privilege Escalation Vulnerabilities:** Attackers exploit software vulnerabilities to elevate their privileges within a system.

- **Defense:** Keep all software applications and operating systems patched and updated.

**7. Abusing Active Directory Delegation:** Attackers exploit overly permissive delegations of control (DoC) to gain access to unauthorized resources.

- **Defense:** Grant least privilege for DoC assignments and regularly review access controls.

**8. Kerberoasting:** Attackers steal user password hashes by requesting service tickets for non-existent services.

- **Defense:** Disable unnecessary Service Principal Names (SPNs) and consider filtering suspicious service ticket requests.

**9. Brute-Force Attacks:** Attackers systematically try different usernames and passwords to gain access to accounts.

- **Defense:** Enforce strong password policies with complexity requirements and implement account lockout mechanisms.

**10. Denial-of-Service (DoS) Attacks:** Attackers overload a system with requests, making it unavailable to legitimate users.

- **Defense:** Implement network segmentation and intrusion detection/prevention systems (IDS/IPS).

# Q20. What are router ?

A router is a networking device that connects two or more computer networks. It performs the tasks of routing data packets and allowing multiple devices to use the same internet connection. Routers are sometimes confused with network hubs and modems, but they have different functionalities.


# Q21. What is amsi ?

AMSI, standing for Antimalware Scan Interface, is a tool developed by Microsoft in Windows. It acts as an intermediary between applications and your installed security software (antivirus, anti-malware). Essentially, it's a communication channel that allows applications to send suspicious code or data to your security software for analysis.

**How Does AMSI Work?**

1. **Application Encounter:** An application on your system, like PowerShell or Office macros, might encounter some code or data (scripts, emails, etc.).
2. **AMSI Integration:** If the application is AMSI-aware (many are!), it can leverage the AMSI interface.
3. **Sending for Scanning:** The application sends the suspicious code or data to AMSI.
4. **Security Software Analysis:** AMSI then forwards the data to your installed security software (antivirus, anti-malware) for scanning.
5. **Results Back:** The security software analyzes the data and sends a report back to AMSI indicating if it's malicious or safe.
6. **Application Action:** Based on the report, the application can take action, like blocking execution, displaying warnings, or allowing it to proceed.


# Q22. How are firewall and amsi different?

**Firewalls:**

- **Function:** Act as a gatekeeper for your network. They monitor incoming and outgoing traffic based on predefined rules.
- **Focus:** Network traffic control. Firewalls determine what type of data can enter or leave your network, blocking anything suspicious or unauthorized.
- **Examples:** Allowing web browsing traffic but blocking remote access attempts.

**AMSI (Antimalware Scan Interface):**

- **Function:** Acts as a security checkpoint within an application.
- **Focus:** Code and data analysis. AMSI allows applications to send suspicious code or data to security software for scanning before execution.
- **Examples:** Scanning email attachments opened in an email client or scripts running in PowerShell.


# Q23. What is network ?

A network is a system that connects devices together so they can communicate and share resources. These devices can be computers, phones, printers, servers, or anything else with networking capabilities. Imagine it like a digital highway that allows information to flow between different devices.

# Q24. What are the types of network ?

**Types of Networks :**

- **Local Area Network (LAN):** This is a small network confined to a limited area, typically a home, office, or school. Devices are usually connected by cables (Ethernet) or Wi-Fi. Think of all the computers and printers in your office connected together to share files and the internet.
    
- **Metropolitan Area Network (MAN):** A MAN covers a larger area than a LAN, often encompassing a city or town. It can connect multiple LANs together. This might be the network infrastructure connecting all the government buildings or universities in a city.
    
- **Wide Area Network (WAN):** A WAN spans a large geographical distance, like a country or even the entire globe. The internet is the best example of a WAN. It connects billions of devices all over the world.
    
- **Personal Area Network (PAN):** This is a very small network centered around a single person, typically connecting devices like smartphones, laptops, and wearables within a short range. Your wireless headphones connecting to your phone to listen to music would be a PAN

# Q25. Explain network topology and it's type ?

Network topology refers to the way devices on a network are arranged and interconnected. It defines the physical or logical layout of the network, including how data flows between devices. Here's a breakdown of network topologies and some common types:

Types of Network Topologies:

- **Bus Topology:**
    
    - All devices are connected to a single central cable.
    - Simple to set up and inexpensive.
    - Failure of the central cable disrupts the entire network.
    - Not ideal for large networks due to performance limitations.
- **Star Topology:**
    
    - Devices are connected to a central hub or switch.
    - Offers better performance and scalability compared to bus topology.
    - Easier to troubleshoot and isolate problems.
    - Failure of the central device can affect all connected devices.
- **Mesh Topology:**
    
    - Devices connect directly to each other, creating a web-like structure.
    - Provides redundancy and fault tolerance as data can take alternate paths.
    - More complex to manage and troubleshoot compared to star topology.
    - Often used in wireless networks.
- **Ring Topology:**
    
    - Devices are connected in a closed loop, where data travels in one direction.
    - Offers good reliability as data can continue to flow even if one device fails.
    - Adding or removing devices disrupts the entire network.
    - Not commonly used today due to limitations in scalability and troubleshooting.
- **Tree Topology:**
    
    - A hierarchical structure combining characteristics of bus and star topologies.
    - Central hubs or switches connect to smaller sub-networks in a branching fashion.
    - Offers scalability and easier management for larger networks.
    - More complex to set up and maintain compared to star topology.