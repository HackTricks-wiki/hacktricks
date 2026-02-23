# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Check the amazing post from:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR for attackers
- Kerberos is the default AD auth protocol; most lateral-movement chains will touch it. For hands‑on cheatsheets (AS‑REP/Kerberoasting, ticket forging, delegation abuse, etc.) see:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Fresh attack notes (2024‑2026)
- **RC4 finally going away** – Windows Server 2025 DCs no longer issue RC4 TGTs; Microsoft plans to disable RC4 as default for AD DCs by end of Q2 2026. Environments that re‑enable RC4 for legacy apps create downgrade/fast‑crack opportunities for Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – April 2025 updates remove “Compatibility” mode; forged PACs/golden tickets get rejected on patched DCs when enforcement is enabled. Legacy/unpatched DCs remain abusable.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – If DCs are unpatched or left in Audit mode, certificates chained to non‑NTAuth CAs but mapped via SKI/altSecID can still log on. Events 45/21 appear when protections trigger.
- **NTLM phase‑out** – Microsoft will ship future Windows releases with NTLM disabled by default (staged through 2026), pushing more auth to Kerberos. Expect more Kerberos surface area and stricter EPA/CBT in hardened networks.
- **Cross‑domain RBCD remains powerful** – Microsoft Learn notes that resource‑based constrained delegation works across domains/forests; writable `msDS-AllowedToActOnBehalfOfOtherIdentity` on resource objects still allows S4U2self→S4U2proxy impersonation without touching front‑end service ACLs.

## Quick tooling
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — outputs AES hashes; plan for GPU cracking or target pre‑auth disabled users instead.
- **RC4 downgrade target hunting**: enumerate accounts that still advertise RC4 with `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` to locate weak kerberoast candidates before RC4 is fully disabled.



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
