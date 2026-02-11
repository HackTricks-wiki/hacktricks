# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**बेहतरीन पोस्ट देखें:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR for attackers
- Kerberos डिफ़ॉल्ट AD auth प्रोटोकॉल है; अधिकांश lateral-movement चेन इससे जुड़े होंगे। hands‑on cheatsheets (AS‑REP/Kerberoasting, ticket forging, delegation abuse, आदि) के लिए देखें:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Fresh attack notes (2024‑2026)
- **RC4 finally going away** – Windows Server 2025 DCs अब RC4 TGTs जारी नहीं करते; Microsoft Q2 2026 के अंत तक AD DCs के लिए RC4 को डिफ़ॉल्ट के रूप में निष्क्रिय करने की योजना बना रहा है। जो वातावरण legacy ऐप्स के लिए RC4 को पुनः सक्षम करते हैं, वे Kerberoasting के लिए downgrade/fast‑crack अवसर पैदा करते हैं।
- **PAC validation enforcement (Apr 2025)** – April 2025 अपडेट "Compatibility" मोड को हटाते हैं; जब enforcement सक्षम होगा तो forged PACs/golden tickets patched DCs पर reject हो जाएँगे। Legacy/unpatched DCs abusable बने हुए रखेंगे।
- **CVE‑2025‑26647 (altSecID CBA mapping)** – यदि DCs unpatched हैं या Audit मोड में छोड़े गए हैं, तो non‑NTAuth CAs से chained प्रमाणपत्र जिन्हें SKI/altSecID के जरिए mapped किया गया है, फिर भी log on कर सकते हैं। जब प्रोटेक्शन्स trigger करते हैं तो Events 45/21 दिखाई देते हैं।
- **NTLM phase‑out** – Microsoft भविष्य के Windows रिलीज़ NTLM को डिफ़ॉल्ट रूप से disabled करके भेजेगा (2026 तक staged), जिससे अधिक auth Kerberos पर जाएगा। hardened नेटवर्क में अधिक Kerberos surface area और कड़े EPA/CBT की उम्मीद रखें।
- **Cross‑domain RBCD remains powerful** – Microsoft Learn नोट करता है कि resource‑based constrained delegation domains/forests में काम करता है; resource objects पर writable `msDS-AllowedToActOnBehalfOfOtherIdentity` अभी भी S4U2self→S4U2proxy impersonation की अनुमति देता है बिना front‑end service ACLs को छुए।

## Quick tooling
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — AES hashes आउटपुट करता है; GPU cracking की योजना बनाएं या इसके बजाय pre‑auth disabled users को लक्ष्य बनाएं।
- **RC4 downgrade target hunting**: उन accounts को enumerate करें जो अभी भी RC4 advertise करते हैं `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` के साथ ताकि RC4 पूरी तरह disabled होने से पहले कमजोर kerberoast उम्मीदवारों का पता लगाया जा सके।

## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
