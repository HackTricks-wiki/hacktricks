# Kerberos-Authentifizierung

{{#include ../../banners/hacktricks-training.md}}

**Siehe den großartigen Beitrag von:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR für Angreifer
- Kerberos ist das Standard‑AD-Authentifizierungsprotokoll; die meisten Lateral‑Movement‑Ketten werden damit in Berührung kommen. Für praktische Cheatsheets (AS‑REP/Kerberoasting, ticket forging, delegation abuse, etc.) siehe:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Aktuelle Angriffsnotizen (2024‑2026)
- **RC4 wird endlich entfernt** – Windows Server 2025 DCs geben keine RC4 TGTs mehr aus; Microsoft plant, RC4 bis Ende Q2 2026 standardmäßig für AD DCs zu deaktivieren. Umgebungen, die RC4 für Legacy‑Apps wieder aktivieren, schaffen Downgrade/fast‑crack‑Chancen für Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – Die Updates im April 2025 entfernen den „Compatibility“‑Modus; gefälschte PACs/golden tickets werden auf gepatchten DCs abgewiesen, wenn die Durchsetzung aktiviert ist. Legacy/ungepatchte DCs bleiben ausnutzbar.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Wenn DCs ungepatcht sind oder im Audit‑Modus belassen werden, können Zertifikate, die an non‑NTAuth CAs angekettet sind, aber via SKI/altSecID gemappt werden, sich weiterhin anmelden. Events 45/21 erscheinen, wenn Schutzmechanismen ausgelöst werden.
- **NTLM‑Ausphasung** – Microsoft wird zukünftige Windows‑Releases mit standardmäßig deaktiviertem NTLM ausliefern (gestaffelt bis 2026) und damit mehr Auth auf Kerberos verlagern. Erwartet mehr Angriffsfläche im Kerberos‑Bereich und strengere EPA/CBT in gehärteten Netzwerken.
- **Cross‑domain RBCD bleibt mächtig** – Microsoft Learn weist darauf hin, dass resource‑based constrained delegation domänen‑/forestübergreifend funktioniert; beschreibbare `msDS-AllowedToActOnBehalfOfOtherIdentity`‑Attribute auf Ressourcenobjekten erlauben weiterhin S4U2self→S4U2proxy‑Impersonation, ohne die Front‑End‑Service‑ACLs zu ändern.

## Schnelle Tools
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — gibt AES‑Hashes aus; für GPU‑Cracking planen oder stattdessen auf Benutzer mit deaktivierter Pre‑Auth abzielen.
- **RC4‑Downgrade‑Zielsuche**: Konten auflisten, die noch RC4 ausweisen, mit `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes`, um schwache kerberoast‑Kandidaten zu finden, bevor RC4 vollständig deaktiviert ist.



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
