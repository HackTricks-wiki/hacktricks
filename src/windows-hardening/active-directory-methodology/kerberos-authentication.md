# Kerberos Autentifikacija

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte odličan post od:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR za napadače
- Kerberos je podrazumevani AD autentifikacioni protokol; većina lateral-movement lanaca će se oslanjati na njega. Za praktične cheatsheets (AS‑REP/Kerberoasting, ticket forging, delegation abuse, itd.) pogledajte:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Sveže beleške o napadima (2024‑2026)
- **RC4 konačno odlazi** – Windows Server 2025 DCs više ne izdaju RC4 TGTs; Microsoft planira da onemogući RC4 kao podrazumevano za AD DCs do kraja Q2 2026. Okruženja koja ponovo omogućavaju RC4 za legacy apps stvaraju downgrade/fast‑crack mogućnosti za Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – April 2025 updates uklanjaju “Compatibility” mode; forged PACs/golden tickets bivaju odbijeni na patched DCs kada je enforcement uključen. Legacy/unpatched DCs ostaju abuzabilni.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Ako su DCs nepatechnuti ili ostavljeni u Audit modu, sertifikati povezani na non‑NTAuth CA-e ali mapirani preko SKI/altSecID i dalje mogu da se prijave. Pojavljuju se Events 45/21 kada zaštite intervenišu.
- **NTLM phase‑out** – Microsoft će isporučiti buduće Windows verzije sa NTLM onemogućenim po defaultu (postepeno do 2026), preusmeravajući više autentifikacije na Kerberos. Očekujte veću Kerberos površinu i strožiji EPA/CBT u ojačanim mrežama.
- **Cross‑domain RBCD ostaje moćan** – Microsoft Learn navodi da resource‑based constrained delegation radi preko domena/šuma; writable `msDS-AllowedToActOnBehalfOfOtherIdentity` na resource objektima i dalje dozvoljava S4U2self→S4U2proxy impersonaciju bez menjanja front‑end service ACLs.

## Brzi alati
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — outputs AES hashes; planirajte GPU cracking ili ciljanje pre‑auth disabled korisnika umesto toga.
- **RC4 downgrade target hunting**: enumerišite naloge koji i dalje reklamiraju RC4 sa `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` da locirate slabe kerberoast kandidate pre nego što RC4 bude potpuno onemogućen.



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
