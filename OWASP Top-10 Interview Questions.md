# OWASP Top-10 Interview Questions - 
## What is OWASP? Also Mention OWASP TOP 10 2021? - 
    OWASP is a non-profit organization that releases the top 10 web vulnerabilities. It works as a community of cybersecurity professionals, who constantly work to build an ecosystem for awareness about secure web applications. Recently, OWASP released new top 10 vulnerabilities for 2021:

    A01 - Broken Access Control
    A02 - Cryptographic Failures
    A03 - Injection
    A04 - Insecure Design
    A05 - Security Misconfiguration
    A06 - Vulnerable and Outdated Components
    A07 - Identification and Authentication Failures
    A08 - Software and Data Integrity Failures
    A09 - Security Logging and Monitoring Failures
    A10 - Server Side Request Forgery (SSRF)
## Mention what flaw arises from session tokens having poor randomness across a range of values? - 
    Session hijacking, is the issue related to A2: 2017 - Broken Authentication. It is also called cookie hijacking. In this type of attack, there is the possibility of exploitation of a valid computer session—sometimes also called a session key—to gain unauthorized access to information or services in a system. This flaw comes when there is poor randomness in the session key.
## How to mitigate SQL Injection risks? - 
    Mitigations of SQL injection:
    * Prepared Statements with Parameterized Queries: Always ensure that your SQL interpreter can always differentiate between code and data. Never use dynamic queries which fail to find the difference between code and data. Instead, use static SQL query and then pass in the external input as a parameter to query.  The use of Prepared Statements (with Parameterized Queries) forces the developer first to define all the SQL code and then pass each parameter to the query later.
    * Use of Stored Procedures: Stored Procedure is like a function in C where the database administrator calls it whenever he/she needs it. It is not completely mitigated SQL injection but definitely helps in reducing risks of SQL injection by avoiding dynamic SQL generation inside.
    * White List Input Validation: Always use white list input validation and allow only preapproved input by the developer. Never use a blacklist approach as it is less secure than a whitelist approach.
    * Escaping All User Supplied Input
    * Enforcing the Least Privilege
## How to mitigate the risk of Weak authentication and session management? - 
    Weak Authentication and Session management can be mitigated by controls of strong authentication and session management. Such controls are as follows: 
    * Compliant with all the authentication and session management requirements defined in OWASP’s Application Security Verification Standard (ASVS) areas V2 (Authentication) and V3 (Session Management).
    * Always use a simple interface for developers. Consider the ESAPI Authenticator and User APIs as good examples to emulate, use, or build upon.
    * Use standard practices to secure session id by cross-site scripting attack.
## How to mitigate the risk of Sensitive Data Exposure? - 
    Following are the mitigation techniques employed for secure applications from Sensitive data exposure:
    * Prepare a threat model to secure data both in transit and at rest from both types of the attacker( e.g., insider attack, external user)
    * Encrypt data to protect it from any cyber attack.
    * Never store sensitive data unnecessarily. Discard it as soon as possible. Data you don’t have can’t be stolen.
    * Disable autocomplete on forms collecting sensitive data and disable caching for pages that contain sensitive data.
    * Always implement and ensure strong standard algorithms and strong keys are used, and proper key management is in place. Consider using FIPS 140 validated cryptographic modules.
    * Ensure passwords are stored with an algorithm specifically designed for password protection, such as bcrypt, PBKDF2, or scrypt.
## What is a bug bounty? - 
    Bug bounty is a program run by many big organizations which rewards those individuals who report security vulnerabilities to them. These organizations generally publish those vulnerabilities on websites after fixing those issues.
## What Is Failure to Restrict URL Access? - 
    This vulnerability has been removed from OWASP Top 10 2013. Actually, this issue is related to forced browsing where a user forcibly accesses URLs which is not supposed to access by the user. The attacker may guess links and brute force techniques to find unprotected pages through this vulnerability.
## How to Prevent Breaches Due to Failure to Restrict URL Access? - 
    This can be mitigated by using secure techniques for proper authentication and proper authorization for each page of the web application. Some mitigation techniques are described below:
    * Implement Authentication and authorization policies based on the role instead of based on the user.
    * Policies are highly configurable in favor of standard practices.
    * Deny all access by default, and allow only those controls that the user needs.
## How can we Protect Web Applications From Forced Browsing? - 
    To protect web applications from forced browsing, strictly monitor access-control settings to be accurate and up-to-date on every page and application on the site.
## Mention what is the basic design of OWASP ESAPI? - 
    OWASP ESAPI is short for OWASP Enterprise Security API which is voluntarily developed by the OWASP community to provide a free, open-source, web application security control library to web developers to help them to develop a less vulnerable web application.The basic design of OWASP ESAPI includes a set of security control interfaces. For each security control, there is a reference implementation that can be implemented as the requirement of the organization.
## Can you explain what a cross-site scripting attack is and how it works? - 
    A cross-site scripting attack is a type of attack that injects malicious code into a web page in order to execute a malicious script. This type of attack can be used to steal information from users, redirect them to malicious websites, or even take control of their computers.
##  What is the importance of security in software development life cycle? - 
    Security is important in every stage of the software development life cycle in order to ensure that the final product is secure and free of vulnerabilities. In the planning stage, security should be taken into account in order to ensure that the system being designed is secure. In the development stage, security should be implemented in order to prevent vulnerabilities from being introduced. In the testing stage, security should be tested in order to ensure that the system is secure. Finally, in the deployment stage, security should be monitored in order to ensure that the system remains secure.
## What are some common errors that lead to application vulnerabilities? -
    There are many common errors that can lead to application vulnerabilities, but some of the most common include: 
    * Insecure communications: This can occur when data is transmitted without being properly encrypted, or when encryption keys are not properly managed.
    * Insecure authentication and authorization: This can happen when authentication mechanisms are not properly implemented, or when authorization checks are not performed properly.
    * Insecure data storage: This can occur when data is stored in an insecure location, or when data is not properly encrypted when stored.
    * Insecure coding practices: This can happen when coding practices are not followed that could lead to vulnerabilities, such as not properly handling input data.
## What is a code review, why is it important, and how do you conduct one effectively? - 
    A code review is a process in which software developers examine each other’s code in order to find and fix errors. Code reviews are important because they help to ensure the quality of the code and can prevent errors from being introduced into the code base. To conduct an effective code review, developers should have a clear understanding of the code and the coding standards that are being used. They should also be familiar with the tools that are available to help them review the code, such as static analysis tools.
## What’s your understanding of threat modeling? How would you apply threat modeling to an application? - 
    Threat modeling is the process of identifying potential security risks and vulnerabilities in an application. This can be done by looking at the application from the perspective of an attacker and identifying potential entry points and ways to exploit the system. Once potential risks have been identified, they can be mitigated or eliminated through changes in the design or implementation of the application.
## Does having SSL certificates guarantee complete protection against attacks? - 
    No, SSL certificates only provide encryption for data in transit. They do not guarantee protection against all attacks, but they can help to mitigate some types of attacks.
## Why is input validation so important? - 
    Input validation is so important because it helps to ensure that the data that is being input into a system is clean and free of any malicious code. This helps to protect the system from being compromised by attackers who may try to inject malicious code into the system through its input channels.
##  What are the different ways of protecting data on mobile devices? - 
    There are a few different ways of protecting data on mobile devices. One way is to encrypt the data so that it can only be accessed by authorized users. Another way is to use a mobile device management system to control which users have access to which data. Finally, you can also use application-level security measures to protect data on mobile devices.
## What does CSRF stand for? What does it mean? Why is it important? - 
    CSRF stands for Cross-Site Request Forgery. It is a type of attack that tricks a user into performing an action on a website that they did not intend to do. This can be done by tricking the user into clicking on a malicious link, or by embedding malicious code into a website that the user visits. CSRF attacks can be used to steal sensitive information, or to perform actions on behalf of the user without their knowledge or consent. CSRF is important because it can be used to exploit vulnerabilities in web applications that could lead to serious security issues.
## What do you understand about client-side validation? - 
    Client-side validation is a process of validating data inputted by a user on the client side, before it is sent to the server. This is done in order to prevent invalid data from being sent to the server, and to improve the overall user experience by providing feedback to the user on their input.
## What are session hijacking attacks and how can they be prevented? - 
    Session hijacking attacks occur when an attacker gains access to a user’s session ID, usually through some kind of network sniffing. Once the attacker has the session ID, they can impersonate the user and gain access to sensitive information. To prevent session hijacking attacks, it is important to use strong encryption methods for all communication, and to never send session IDs over unencrypted channels.
## How should passwords be stored safely in databases? - 
    Passwords should be stored in databases using a technique called hashing. Hashing is a way of encrypting data so that it can only be decrypted by someone with the correct key. When a password is hashed, the original password is turned into a long string of random characters. This string can then be stored in the database without the risk of someone being able to decrypt it and figure out the original password.
## What is the difference between horizontal and vertical privilege escalation? - 
    Horizontal privilege escalation is when an attacker gains access to additional systems that are at the same level of access as the system they originally compromised. Vertical privilege escalation is when an attacker gains access to a system that has a higher level of access than the system they originally compromised.
## What are the five pillars of Information Security? - 
    The five pillars of Information Security are confidentiality, integrity, availability, authenticity, and non-repudiation.
## What is the importance of validating user inputs? - 
    Validating user inputs is important in order to prevent security vulnerabilities such as SQL injection and cross-site scripting (XSS). By ensuring that all user input is valid before it is processed by your application, you can help to protect your application from malicious attacks.
## Define Penetration Testing? - 
    There are different types of testing in OWASP. Penetration testing is a type of security testing that helps developers identify a system’s vulnerabilities. It evaluates a system’s security through a set of manual and automated techniques. Once one vulnerability has been identified, the tester will dwell on it to locate even more vulnerabilities. It, therefore, prevents a given system from any external attacks.
    This type of testing is usually done through white-box testing and black-box testing, which differ in the scope of information given to the testers. It is crucial since it bridges the system breaches and loopholes and protects data from hackers and unauthorized access. This explains why developers must conduct penetration testing before every release.
## Define a Botnet?
    A Botnet is a collection of internet-connected devices that run one or more bots. These can be several private computers having malicious or compromised software that are controlled remotely without the owner’s knowledge. Therefore, in a botnet attack, a device is infected by malware after being hacked. The malware then connects the system back to the primary or central botnet server. Botnets are mainly used to steal data, send spam, allow a hacker to access a given device and its connections, and conduct several distributed denial of service attacks that lock out authorized users from several resources.
##  What are DDOS Attacks? - 
    There are a number of attacks occasioned by system or web application vulnerabilities. DDOS attacks, fully known as denial of service attacks, refer to an attempt by hackers to block intended users from given computer resources. This is usually done by bagging the resource or machine with several unnecessary requests that usually overload them and prevent authorized access. These requests typically come from various sources, making it hard to diagnose or block them. Therefore, a developer or a site administrator cannot simply stop the attack by only dealing with a single source.
## Can You Differentiate Authentication From Authorization? - 
    Authentication verifies the identity of a user, entity, or website. It ascertains that someone is whoever they claim to be. On the other hand, authorization refers to the rules determining the powers granted to given parties. It can also be defined as the process of determining whether a client is permitted to access a given file or use a resource. Authentication is, therefore, all about verification, while authorization focuses more on permissions. Also, you will need to log in and key your password for authentication, whereas you must have the proper clearance for authorization.
## What Can You Tell Us about SSL Sessions and SSL Connections? - 
    SSL, which refers to a Secured Socket Layer connection, is the basis for communicating with peer to peer links. It has a connection that maintains the SSL session. The SSL session symbolizes the security contract, consisting of a key and algorithm agreement. It is worth noting that one SSL session can have several SSL Connections. I should mention that an SSL connection is basically a transient peer to peer communications link.
## Define WebGoat and WebScarab in OWASP? - 
    OWASP is committed to enhancing web security. Therefore, WebGoat is a voluntarily insecure web application designed to purposely teach web application security practices and lessons. It demonstrates a number of server-side application flaws and has exercises to teach people about application security and penetration techniques. On the other hand, WebScarab is a testing tool that intercepts and gives people the liberty to alter requests and server replies. It may also record traffic to be used for further reviews. The Open Web Application Security Project owns all these tools.
## Failure to Restrict URL Access Can Cause Breaches. Do You Know How to Prevent Them? - 
    The best way of preventing breaches caused by unrestricted URL access is to use secure techniques to properly authenticate and authorize all the pages of a given web application. Other mitigation techniques that can work include basing the implementation of authentication and authorization on the role instead of a user, blocking all access and only permitting controls that a user needs, and lastly, observing highly configurable policies. These four ways will ensure that you don’t witness breaches occasioned by URL access restriction failure.
## OWASP ZAP: Is it secure? - 
    ZAP is entirely safe and within legal rights for proxying requests; it merely lets you observe what is happening. Spidering is a little riskier. Depending on the operation of your application, it can result in issues.
## How to effectively reduce the great risk of Sensitive Data Exposure? - 
    The reduction methods that are adopted for secure applications from Sensitive data exposure are as follows:
    * Create a threat model to protect data from both sorts of attackers when it is in transit and at rest ( e.g., external user type or inside attack type).
    * Strong standardized algorithms and robust keys should always be utilized, and appropriate key management should be in place. FIPS 140 certified cryptographic modules should be used.
    * To safeguard data from online attacks, encrypt it.
    * Never voluntarily store critical information. As quickly as you can, throw it away. You can't steal data that you don't possess.
    * Make that passwords are stored using a password-protection-specific algorithm, such as scrypt, bcrypt, or PBKDF2.
    * Disabling autocomplete on such forms that request sensitive information and disabling caching on pages that do so.
