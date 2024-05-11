# Final Project - Ethical Hacking Report
_*Client :*_ *Lazada Group*

_*Date :*_ *May, 11 2024*

_*Prepared By :*_ *Buquid, Ed Jim C. and Bondoy, Monica G.*

_*Executive Summary :*_ This report presents the technical findings of the ethical hacking assessment
conducted for Lazada. The assessment aimed to identify vulnerabilities within the
organization's network infrastructure, applications, and systems. Through various testing methodologies,
including penetration testing and vulnerability scanning, critical and high-risk issues were discovered.
This report provides detailed descriptions of these findings, along with actionable recommendations for
remediation.

_*Vulnerability Summary :*_
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


_*Recommendations :*_

3.  #### Operating System : ####
* *Upgrade Operating Systems :* Consider upgrading to a more recent and supported version of the operating system. Newer versions often come with improved security features.
*  *Apply Patches Regularly :* Regularly apply security patches and updates to the operating system. This can help protect against known exploits and malware.
* *Weak Password Policies :*
* *Enforce Strong Password Policies :* Implement and enforce strong password policies. This includes using a mix of uppercase and lowercase letters, numbers, and special characters. Passwords should also be of sufficient length (e.g., 12 characters or more).
* *Regular Password Changes :* Require users to change their passwords regularly, but avoid too frequent changes as it may lead to weak passwords.
* *Use Two-Factor Authentication (2FA) :* Consider implementing two-factor authentication for an added layer of security.
