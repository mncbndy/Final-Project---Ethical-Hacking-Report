# Final Project - Ethical Hacking Report
_**Client :**_ *Lazada Group*

_**Date :**_ *May, 11 2024*

_**Prepared By :**_ *Buquid, Ed Jim C. and Bondoy, Monica G.*

_*Executive Summary :*_ This report presents the technical findings of the ethical hacking assessment
conducted for Lazada. The assessment aimed to identify vulnerabilities within the
organization's network infrastructure, applications, and systems. Through various testing methodologies,
including penetration testing and vulnerability scanning, critical and high-risk issues were discovered.
This report provides detailed descriptions of these findings, along with actionable recommendations for
remediation.

_**Vulnerability Summary :**_
1.  #### Network Infrastructure ####

 * *Crital :* Remote Code Execution vulnerability (CVE-2024-1234) in the Apache Struts framework (version 2.3.34) running on Lazada’s main server, potentially allowing an attacker to execute arbitrary code remotely.
* *High :*  Misconfigured firewall rules on Lazada’s payment processing server permitting unrestricted access from external IP ranges to sensitive internal services such as SSH and RDP.

2.  #### Web Applications : ####
* *Critical :*
 - SQL Injection vulnerability in the login form of Lazada, potentially enabling an attacker to extract sensitive data from the database.
 - Insecure Direct Object References (IDOR) vulnerability in the user profile section of Lazada, potentially allowing an attacker to manipulate references to access unauthorized data.
 -  Server-Side Request Forgery (SSRF) vulnerability in the file upload functionality of Lazada, potentially allowing an attacker to make requests to internal resources.

* *High :*
* Cross-Site Scripting (XSS) vulnerability in Lazada, allowing attackers to execute malicious scripts in users’ browsers.
* Cross-Site Request Forgery (CSRF) vulnerability in Lazada, potentially enabling an attacker to trick a victim into performing actions they did not intend to.
* Unvalidated Redirects and Forwards vulnerability in [Application Name], potentially enabling an attacker to redirect users to malicious websites.



3.  #### Operating System : ####

* *Critical :*  Outdated and unpatched operating systems (Windows Server 2012 R2) on Lazada’s payment processing servers, potentially exposing them to known exploits and malware.
* *High :* Weak password policies on Lazada’s domain user accounts, potentially facilitating brute-force attacks and unauthorized access.


3.  #### Wireless : ####

 * *Critical :*  Rogue Access Point detected in Lazada’s wireless network, potentially allowing an attacker to intercept wireless traffic and perform man-in-the-middle attacks.
* *High :* Open wireless networks without any authentication in Lazada’s office, potentially allowing unauthorized access to the network.
So, the updated list would be:

* *Critical :*  Weak encryption (WEP) used in Lazada’s guest wireless network, potentially allowing attackers to intercept and decrypt wireless traffic, thereby exposing sensitive data.
* *Critical :* Rogue Access Point detected in Lazada’s wireless network, potentially allowing an attacker to intercept wireless traffic and perform man-in-the-middle attacks.
* *High :* Open wireless networks without any authentication in Lazada’s office, potentially allowing unauthorized access to the network.


_**Recommendations :**_

1. #### Remote Code Execution Vulnerability : ####
* *Patch or Upgrade Apache Struts :* The Apache Struts framework should be patched or upgraded to a version that fixes the CVE-2024-1234 vulnerability. Regularly check for and apply updates or patches released by the software vendor.
* *Regular Vulnerability Scanning :* Conduct regular vulnerability scanning to identify and fix any new vulnerabilities that may arise.
* *Least Privilege Principle :* Ensure that applications running on the server follow the principle of least privilege, meaning they should only have the permissions they need to function and no more. This can limit the potential damage from a remote code execution vulnerability.
* *Misconfigured Firewall Rules :*
* *Review and Update Firewall Rules :* Regularly review and update firewall rules to ensure that only necessary ports are open and that access is restricted to trusted IP addresses. Unnecessary ports should be closed or have access limited to specific IP addresses.
* *Intrusion Detection/Prevention Systems (IDS/IPS) :* Consider implementing an IDS/IPS to monitor network traffic and detect/prevent any malicious activities.
* *VPN for Remote Access :* If remote access to internal services is necessary, consider using a Virtual Private Network (VPN) to provide a secure, encrypted connection over the internet.

2.  #### SQL Injection Vulnerability : ####

* *Input Validation :* Implement input validation to check for illegal syntax in user inputs before it is processed by the application.
* *Parameterized Queries :* Use parameterized queries or prepared statements to ensure that parameters (values) are separated from the query itself, reducing the risk of SQL injection.
* Insecure Direct Object References (IDOR) :*
* *Access Control :*  Implement proper access control checks to verify the user is authorized to access the requested object.
* *Server-Side Request Forgery (SSRF) :* Whitelist URLs: Only allow connections to trusted URLs. This can prevent an attacker from making requests to internal resources.
* *Cross-Site Scripting (XSS) :*
* *Output Encoding :* Use output encoding when returning user input in HTML to ensure that any characters that have a special meaning in HTML are escaped properly.
* *Content Security Policy (CSP) :* mplement a Content Security Policy (CSP) to limit the locations from which scripts can be loaded.
* Cross-Site Request Forgery (CSRF): Anti-CSRF Tokens: Use anti-CSRF tokens in forms to ensure that requests are only accepted from legitimate sources.
* *Unvalidated Redirects and Forwards :* Avoid Redirects and Forwards: If possible, avoid using redirects and forwards in your application.
* *URL Validation :* If redirects or forwards are necessary, ensure that the target URL is validated to be a part of your application.

3.  #### Operating System : ####
   
* *Upgrade Operating Systems :* Consider upgrading to a more recent and supported version of the operating system. Newer versions often come with improved security features.
*  *Apply Patches Regularly :* Regularly apply security patches and updates to the operating system. This can help protect against known exploits and malware.
* *Weak Password Policies :*
* *Enforce Strong Password Policies :* Implement and enforce strong password policies. This includes using a mix of uppercase and lowercase letters, numbers, and special characters. Passwords should also be of sufficient length (e.g., 12 characters or more).
* *Regular Password Changes :* Require users to change their passwords regularly, but avoid too frequent changes as it may lead to weak passwords.
* *Use Two-Factor Authentication (2FA) :* Consider implementing two-factor authentication for an added layer of security.
