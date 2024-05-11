# Final Project - Ethical Hacking Report
_**Client :**_ *Lazada Group*

_**Date :**_ *May 11, 2024*

_**Prepared By :**_ *Buquid, Ed Jim C. and Bondoy, Monica G.*

_*Executive Summary :*_ This report presents the technical findings of the ethical hacking assessment
conducted for Lazada. The assessment aimed to identify vulnerabilities within the
organization's network infrastructure, applications, and systems. Through various testing methodologies,
including penetration testing and vulnerability scanning, critical and high-risk issues were discovered.
This report provides detailed descriptions of these findings, along with actionable recommendations for
remediation.

_**Vulnerability Summary**_
1.  #### Network Infrastructure ####

* *Crital :*
* Remote Code Execution vulnerability (CVE-2024-1234) in the Apache Struts framework (version 2.3.34) running on Lazada’s main server, potentially allowing an attacker to execute arbitrary code remotely.
* *High :*
* Misconfigured firewall rules on Lazada’s payment processing server permitting unrestricted access from external IP ranges to sensitive internal services such as SSH and RDP.

2.  #### Web Applications ####
   
* *Critical :*
* SQL Injection vulnerability in the login form of Lazada, potentially enabling an attacker to extract sensitive data from the database.
* Insecure Direct Object References (IDOR) vulnerability in the user profile section of Lazada, potentially allowing an attacker to manipulate references to access unauthorized data.
* Server-Side Request Forgery (SSRF) vulnerability in the file upload functionality of Lazada, potentially allowing an attacker to make requests to internal resources.
* *High :*
* Cross-Site Scripting (XSS) vulnerability in Lazada, allowing attackers to execute malicious scripts in users’ browsers.
* Cross-Site Request Forgery (CSRF) vulnerability in Lazada, potentially enabling an attacker to trick a victim into performing actions they did not intend to.
* Unvalidated Redirects and Forwards vulnerability in [Application Name], potentially enabling an attacker to redirect users to malicious websites.



3.  #### Operating System ####

* *Critical :*
* Outdated and unpatched operating systems (Windows Server 2012 R2) on Lazada’s payment processing servers, potentially exposing them to known exploits and malware.
* *High :*
*  Weak password policies on Lazada’s domain user accounts, potentially facilitating brute-force attacks and unauthorized access.


4.  #### Wireless Networks ####

* *Critical :*
* Rogue Access Point detected in Lazada’s wireless network, potentially allowing an attacker to intercept wireless traffic and perform man-in-the-middle attacks.
* Weak encryption (WEP) used in Lazada’s guest wireless network, potentially allowing attackers to intercept and decrypt wireless traffic, thereby exposing sensitive data.
* *High :*
* Open wireless networks without any authentication in Lazada’s office, potentially allowing unauthorized access to the network.
So, the updated list would be:

5.  #### Social Engineering ####

* *High :*
* Several employees fell victim to phishing emails, providing credentials and sensitive information in response.
* A number of employees were tricked into downloading malicious software through a spear-phishing attack, compromising the security of their systems.
* An attacker impersonated a company executive in an email, requesting urgent wire transfers from the finance department.
* *Critical :*
* An attacker posed as a tech support specialist and convinced an employee to provide remote access to their computer, potentially exposing sensitive company data.
* Employees were targeted by a vishing (voice phishing) attack where the attacker posed as a bank representative and collected sensitive financial information over the phone.
   
_**Recommendations**_

1. #### Remote Code Execution Vulnerability ####
   
* *Patch or Upgrade Apache Struts :* The Apache Struts framework should be patched or upgraded to a version that fixes the CVE-2024-1234 vulnerability. Regularly check for and apply updates or patches released by the software vendor.
* *Regular Vulnerability Scanning :* Conduct regular vulnerability scanning to identify and fix any new vulnerabilities that may arise.
* *Least Privilege Principle :* Ensure that applications running on the server follow the principle of least privilege, meaning they should only have the permissions they need to function and no more. This can limit the potential damage from a remote code execution vulnerability.
* *Misconfigured Firewall Rules :*
* *Review and Update Firewall Rules :* Regularly review and update firewall rules to ensure that only necessary ports are open and that access is restricted to trusted IP addresses. Unnecessary ports should be closed or have access limited to specific IP addresses.
* *Intrusion Detection/Prevention Systems (IDS/IPS) :* Consider implementing an IDS/IPS to monitor network traffic and detect/prevent any malicious activities.
* *VPN for Remote Access :* If remote access to internal services is necessary, consider using a Virtual Private Network (VPN) to provide a secure, encrypted connection over the internet.

2.  #### SQL Injection Vulnerability ####

* *Input Validation :* Implement input validation to check for illegal syntax in user inputs before it is processed by the application.
* *Parameterized Queries :* Use parameterized queries or prepared statements to ensure that parameters (values) are separated from the query itself, reducing the risk of SQL injection.
* Insecure Direct Object References (IDOR) :*
* *Access Control :*  Implement proper access control checks to verify the user is authorized to access the requested object.
* *Server-Side Request Forgery (SSRF) :* Whitelist URLs: Only allow connections to trusted URLs. This can prevent an attacker from making requests to internal resources.
* *Cross-Site Scripting (XSS) :*
* *Output Encoding :* Use output encoding when returning user input in HTML to ensure that any characters that have a special meaning in HTML are escaped properly.
* *Content Security Policy (CSP) :* Implement a Content Security Policy (CSP) to limit the locations from which scripts can be loaded.
* Cross-Site Request Forgery (CSRF): Anti-CSRF Tokens: Use anti-CSRF tokens in forms to ensure that requests are only accepted from legitimate sources.
* *Unvalidated Redirects and Forwards :* Avoid Redirects and Forwards: If possible, avoid using redirects and forwards in your application.
* *URL Validation :* If redirects or forwards are necessary, ensure that the target URL is validated to be a part of your application.

3.  #### Operating System ####
   
* *Upgrade Operating Systems :* Consider upgrading to a more recent and supported version of the operating system. Newer versions often come with improved security features.
*  *Apply Patches Regularly :* Regularly apply security patches and updates to the operating system. This can help protect against known exploits and malware.
* *Weak Password Policies :*
* *Enforce Strong Password Policies :* Implement and enforce strong password policies. This includes using a mix of uppercase and lowercase letters, numbers, and special characters. Passwords should also be of sufficient length (e.g., 12 characters or more).
* *Regular Password Changes :* Require users to change their passwords regularly, but avoid too frequent changes as it may lead to weak passwords.
* *Use Two-Factor Authentication (2FA) :* Consider implementing two-factor authentication for an added layer of security.

5.  #### Phishing Emails ####
   
* *Rogue Access Point :* Implement a Wireless Intrusion Prevention System (WIPS) to detect and neutralize rogue access points. Regularly monitor and audit the wireless network for any unauthorized devices.
* *Weak Encryption (WEP) :* Upgrade the encryption protocol on Lazada’s guest wireless network from WEP to a more secure standard such as WPA2 or WPA3. This will make it much harder for attackers to decrypt wireless traffic.
* *Open Wireless Networks :* Implement at least basic authentication for all wireless networks in Lazada’s office. Consider using a Virtual Private Network (VPN) for additional security. This will prevent unauthorized access to the network.
   
5.  #### Phishing Emails ####

* *Security Awareness Training :* Conduct regular security awareness training for employees to help them identify and respond appropriately to phishing emails.
* *Email Filtering :* Implement email filtering solutions that can detect and block phishing emails.
* *Spear-Phishing Attacks :*
* *Advanced Threat Protection :* Use advanced threat protection solutions that can detect and prevent spear-phishing attacks.
* *Regular Updates :* Keep all systems and software updated to protect against malware.
* *Tech Support Scams :*
* *Verification Procedures :* Implement procedures for employees to verify the identity of anyone claiming to be tech support.
* *Limited Access :* Limit the access rights of users and use strong access controls.
* *CEO Fraud :*
* *Verification Procedures :* Implement procedures for verifying any financial transactions requested via email.
* *Two-Factor Authentication :* Use two-factor authentication for initiating wire transfers.
* *Vishing Attacks :*
* *Security Awareness Training :* Train employees on how to recognize and respond to vishing attacks.
* *Caller ID Spoofing Awareness :* Make employees aware that caller ID can be spoofed and that they should not rely on it to verify a caller’s identity.

_**Conclusions**_

The results of the ethical hacking evaluation reveal a number of significant vulnerabilities and security gaps within Lazada’s infrastructure and applications. By taking action on the suggested remediation steps, Lazada can greatly improve its security stance and reduce the likelihood of cyber threats and data breaches. This will ensure a safer and more secure shopping experience for all Lazada customers.

_**Signature**_

![signature](img.png)
