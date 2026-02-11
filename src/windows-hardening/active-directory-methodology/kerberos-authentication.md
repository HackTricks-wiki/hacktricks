# Uthibitishaji wa Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Angalia chapisho bora kutoka kwa:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Muhtasari kwa wadukuzi
- Kerberos ni default AD auth protocol; mnyororo wa wengi wa lateral‑movement utakutana nayo. Kwa cheatsheets za vitendo (AS‑REP/Kerberoasting, ticket forging, delegation abuse, n.k.) angalia:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Vidokezo vya mashambulizi vipya (2024‑2026)
- **RC4 hatimaye inaondoka** – Windows Server 2025 DCs hawatoi tena RC4 TGTs; Microsoft inapanga kuzima RC4 kama default kwa AD DCs ifikapo mwisho wa Q2 2026. Mazingira yanayoirudisha RC4 kwa programu za zamani hutoa fursa za downgrade/uvunjaji wa haraka kwa Kerberoasting.
- **Utekelezaji wa PAC validation (Apr 2025)** – Sasisho za Aprili 2025 zinaondoa “Compatibility” mode; PAC zilizotengenezwa/golden tickets zinakataliwa kwenye DC zilizopachikwa wakati enforcement imewezeshwa. DC za zamani/zisizopachikwa bado zinaweza kutumika.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Ikiwa DC ziko zisizopachikwa au zimetengwa katika Audit mode, vyeti (certificates) vilivyofungamana na non‑NTAuth CAs lakini vilivyopangwa kupitia SKI/altSecID bado vinaweza kuingia. Matukio Events 45/21 yanaonekana wakati kinga zinapoanzishwa.
- **Kuondolewa kwa NTLM kwa awamu** – Microsoft itasafirisha matoleo yajayo ya Windows yenye NTLM imezimwa kwa default (itekelezwe hadi 2026), ikisukuma uthibitishaji zaidi kwa Kerberos. Tarajia wigo kubwa zaidi wa Kerberos na EPA/CBT kali katika mitandao iliyoimarishwa.
- **Cross‑domain RBCD bado ni yenye nguvu** – Microsoft Learn inaonyesha kwamba resource‑based constrained delegation inafanya kazi across domains/forests; writable `msDS-AllowedToActOnBehalfOfOtherIdentity` kwenye resource objects bado inaruhusu S4U2self→S4U2proxy impersonation bila kugusa front‑end service ACLs.

## Zana za haraka
- **Rubeus kerberoast (AES default):** `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — hutoka AES hashes; panga uvunjaji kwa GPU au lenga watumiaji walio na pre‑auth imezimwa badala yake.
- **RC4 downgrade target hunting:** orodhesha akaunti ambazo bado zinatangaza RC4 kwa kutumia `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` ili kupata wagombea dhaifu wa kerberoast kabla RC4 haijatolewa kabisa.

## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
