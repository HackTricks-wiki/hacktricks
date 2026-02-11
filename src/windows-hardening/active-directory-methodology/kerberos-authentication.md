# Kerberos-verifikasie

{{#include ../../banners/hacktricks-training.md}}

**Kyk na die fantastiese artikel by:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR vir aanvallers
- Kerberos is die standaard AD auth-protokol; meeste lateral-movement kettings sal dit raak. Vir praktiese cheatsheets (AS‑REP/Kerberoasting, ticket forging, delegation abuse, etc.) sien:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Vars aanvalnotas (2024‑2026)
- **RC4 uiteindelik verdwyn** – Windows Server 2025 DCs gee nie meer RC4 TGTs uit nie; Microsoft beplan om RC4 as standaard vir AD DCs te deaktiveer teen die einde van Q2 2026. Omgewings wat RC4 weeraktiveer vir legacy‑apps skep downgrade/fast‑crack geleenthede vir Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – April 2025-opdaterings verwyder die “Compatibility” modus; vervalste PACs/golden tickets word geweier op gepatchte DCs wanneer afdwinging ingeskakel is. Legacy/ongepakte DCs bly misbruikbaar.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – As DCs ongepakte is of in Audit‑modus gelaat word, sertifikate wat gekoppel is aan non‑NTAuth CAs maar via SKI/altSecID gemap is, kan steeds aanmeld. Gebeure 45/21 verskyn wanneer beskerming aktiveer.
- **NTLM uitfasering** – Microsoft sal toekomstige Windows-uitgawes uitbring met NTLM standaard gedeaktiveer (gefaseer deur 2026), wat meer auth na Kerberos dwing. Verwag meer Kerberos-oppervlakte en strenger EPA/CBT in geharde netwerke.
- **Cross‑domain RBCD bly kragtig** – Microsoft Learn dui aan dat resource‑based constrained delegation oor domeine/foreste werk; skryfbare `msDS-AllowedToActOnBehalfOfOtherIdentity` op resource‑objekte laat steeds S4U2self→S4U2proxy impersonation toe sonder om front‑end service ACLs aan te raak.

## Vinnige gereedskap
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — lewer AES hashes; beplan GPU‑cracking of mik eerder gebruikers met pre‑auth gedeaktiveer.
- **RC4 downgrade teikenjag**: enumereer rekeninge wat steeds RC4 adverteer met `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` om swak kerberoast‑kandidate te vind voordat RC4 heeltemal gedeaktiveer word.



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
