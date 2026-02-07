# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Check the amazing post from:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR kwa wadukuzi
- Kerberos ni itifaki ya default ya uthibitishaji ya AD; mnyororo mwingi wa lateral‑movement utaigusa. Kwa cheatsheets za vitendo (AS‑REP/Kerberoasting, ticket forging, delegation abuse, n.k.) ona:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Vidokezo vya mashambulizi vipya (2024‑2026)
- **RC4 finally going away** – DCs za Windows Server 2025 hazitoa tena RC4 TGTs; Microsoft inakusudia kuzima RC4 kama chaguo‑msingi kwa AD DCs kabla ya mwisho wa Q2 2026. Mazingira yanayowasha tena RC4 kwa legacy apps huunda fursa za downgrade/uvunaji wa kasi kwa Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – masasisho ya Aprili 2025 yanatoa “Compatibility” mode; forged PACs/golden tickets zitatupwa kwenye DCs zilizosanishwa wakati enforcement imewezeshwa. DCs za legacy/zisizopachikwa zinabaki kutumiwa kwa matumizi mabaya.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Ikiwa DCs hazijapachikwa au zimeachwa katika Audit mode, certificates zilizofungwa kwenye non‑NTAuth CAs lakini zilizopangwa kupitia SKI/altSecID bado zinaweza kuingia. Events 45/21 zinaonekana wakati ulinzi unapoanza kazi.
- **NTLM phase‑out** – Microsoft itaweka matoleo ya baadaye ya Windows na NTLM imezimwa kama chaguo‑msingi (katika hatua kupitia 2026), ikisukuma uthibitishaji zaidi kwa Kerberos. Tarajia ongezeko la uso la Kerberos na EPA/CBT kali zaidi katika mitandao iliyoboreshwa.
- **Cross‑domain RBCD remains powerful** – Microsoft Learn inaonyesha kwamba resource‑based constrained delegation hufanya kazi across domains/forests; writable `msDS-AllowedToActOnBehalfOfOtherIdentity` kwenye resource objects bado inaruhusu S4U2self→S4U2proxy impersonation bila kugusa front‑end service ACLs.

## Zana za haraka
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — inatoa AES hashes; panga kuvunja kwa GPU au lenga watumiaji walio na pre‑auth disabled badala yake.
- **RC4 downgrade target hunting**: haga akaunti ambazo bado zinatangaza RC4 kwa `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` ili kupata wagombea dhaifu wa kerberoast kabla RC4 haijaondolewa kabisa.



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
