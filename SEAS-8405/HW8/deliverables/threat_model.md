# Threat Model: Secure Containerized Microservices

## 1. Overview
This document outlines the threat modeling exercise performed on the initial insecure IAM solution, following STRIDE and MITRE ATT&CK methodologies.

---

## 2. STRIDE Analysis

| Threat Category | Example | Impact | Mitigation |
|----------------|---------|--------|------------|
| Spoofing | Malicious or malformed tokens accepted as valid | Protected endpoints are accessible to unauthenticated users | Validate issuer, audience, and expiration with jwt |
| Tampering | Decoding tokens with verify_signature=false | Forged tokens accepted | Validate signatures before decoding tokens |
| Repudiation | No audit logging of user actions (login, logout, token use) | No traceability | Log all token and user/admin activity |
| Information Disclosure | Exposed or hard-coded environment variables | Credential Leak | Use .env files with restricted permissions |
| Denial of Service | No rate limiting on endpoints | API resource exhaustion | Add request throttling and healthcheck isolation |
| Elevation of Privilege | Tokens include unverified role claims | Authorization bypass | Validate roles for realm and client resource access |

---

## 3. MITRE ATT&CK Mapping (Containers)

| Tactic         | Technique ID | Technique Name | Application Relevance |
|----------------|--------------|----------------|------------------------|
| Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/)         | Valid Accounts | Leaked credentials or tokens |
| Execution      | [T1068](https://attack.mitre.org/techniques/T1068/)         | Exploitation for Privilege Escalation | Unchecked role assertions |
| Persistence    | [T552.001](https://attack.mitre.org/techniques/T1552/001/)        | Unsecured Credentials: Credentials In Files | Leaked secrets in logs or .env |
| Privilege Escalation | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Indicator Removal: File Deletion | Log tampering |
| Defense Evasion | [T1087](https://attack.mitre.org/techniques/T1087/)        | Account Discovery | Unprotected API endpoints |

---

## 4. Controls Mapping

| Issue | Recommended Control | Framework Reference |
|-------|---------------------|---------------------|
| Unvalidated JWTs | Use RS256 and key validation with JWKS | [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/): API2 |
| Hardcoded credentials | Use .env file | [NIST 800-53](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf): AC-3, AC-6, CM-6 |
| No audit trail | Log user and admin events | [NIST 800-53](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf): AU-2 |
| Excessive token scope | Apply least privilege to client scope | [NIST 800-53](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf): AC-6, AC-17, IA-6 |
| Over-privileged containers | Add non-root users | [CIS Docker Benchmark](https://learn.cisecurity.org/benchmarks) |

---

## 5. Risk Rating Summary

| Threat | Risk | Likelihood | Impact | Mitigation Priority |
|--------|------|------------|--------|----------------------|
| JWT Forgery | High | Medium | Critical | Immediate |
| Privilege Escalation | High | Medium | High | Immediate |
| Credential Leakage | Medium | Medium | Medium | High |
| No Rate Limiting | Medium | High | Medium | High |
| No Audit Logs | Medium | Medium | Medium | Medium |

---

## 6. Conclusion

This threat model identifies the major flaws in the system and informs the remediation and architecture redesign. The final implementation significantly reduces the attack surface and enforces least privilege, defense in depth, and secure defaults.

## 7. References
* Chen, J., Microsoft Threat Intelligence Center, McCune, R., Manral, V., & Weizman, Y. (2025, April 15). *Unsecured credentials: Credentials in files, sub-technique T1552.001 - Enterprise. MITRE ATT&CK®.* https://attack.mitre.org/techniques/T1552/001/ 
* CIS (Center for Internet Security). (2024). *CIS Docker Benchmark (v1.7.0).* https://learn.cisecurity.org/benchmarks 
* Johnson, W. (2025, April 15). *Indicator Removal: File deletion, sub-technique T1070.004 - Enterprise. MITRE ATT&CK®.* https://attack.mitre.org/techniques/T1070/004/ 
* NIST. (2020). *NIST Special Publication 800-53. In NIST (Revision 5).* National Institute of Standards and Technology. https://doi.org/10.6028/nist.sp.800-53r5 
* OWASP API Security Project team. (2023). *API2:2023 Broken Authentication.* OWASP. https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
* Stepanic, D., Microsoft Threat Intelligence Center, & Smith, T. (2025, April 15). *Account Discovery, technique T1087 - Enterprise. MITRE ATT&CK®.* https://attack.mitre.org/techniques/T1087/ 
* Sternstein, J., Wee, M., Goldstein, M., Netskope, Praetorian, Somasamudram, P., Sarukkai, S., Farooqh, S. U., & Weizman, Y. (2025, April 15). *Valid Accounts, technique T1078 - Enterprise. MITRE ATT&CK®.* https://attack.mitre.org/techniques/T1078/ 
* Tayouri, D., Revivo, I., Dos Santos, J. A., & Agman, Y. (2025, April 15). *Exploitation for Privilege Escalation, Technique T1068 - Enterprise. MITRE ATT&CK®.* https://attack.mitre.org/techniques/T1068/