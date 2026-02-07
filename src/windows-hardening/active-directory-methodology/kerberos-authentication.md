# Kerberos-Authentifizierung

{{#include ../../banners/hacktricks-training.md}}

**Siehe den großartigen Beitrag von:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR für Angreifer
- Kerberos ist das Standard-AD-Auth-Protokoll; die meisten Lateral‑Movement-Ketten werden damit zu tun haben. Für praxisnahe Cheatsheets (AS‑REP/Kerberoasting, ticket forging, delegation abuse, etc.) siehe:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Aktuelle Angriffsnotizen (2024‑2026)
- **RC4 verschwindet endlich** – Windows Server 2025 DCs stellen keine RC4 TGTs mehr aus; Microsoft plant, RC4 bis Ende Q2 2026 standardmäßig für AD DCs zu deaktivieren. Umgebungen, die RC4 für Legacy-Anwendungen wieder aktivieren, schaffen Downgrade-/Fast‑Crack‑Möglichkeiten für Kerberoasting.
- **PAC-Validierungsdurchsetzung (Apr 2025)** – Die Updates vom April 2025 entfernen den „Compatibility“-Modus; gefälschte PACs/golden tickets werden auf gepatchten DCs abgelehnt, wenn die Durchsetzung aktiviert ist. Legacy/ungepatchte DCs bleiben weiterhin ausnutzbar.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Wenn DCs ungepatcht sind oder im Audit‑Modus verbleiben, können Zertifikate, die an non‑NTAuth CAs gebunden sind, aber via SKI/altSecID gemappt werden, sich weiterhin anmelden. Events 45/21 erscheinen, wenn Schutzmaßnahmen greifen.
- **NTLM-Ausphasung** – Microsoft wird künftige Windows‑Releases standardmäßig mit deaktiviertem NTLM ausliefern (stufenweise bis 2026), wodurch mehr Auth zu Kerberos verlagert wird. Erwarten Sie mehr Kerberos‑Angriffsfläche und strengere EPA/CBT in gehärteten Netzwerken.
- **Cross‑domain RBCD bleibt mächtig** – Microsoft Learn stellt fest, dass resource‑based constrained delegation über Domains/Forests hinweg funktioniert; ein beschreibbares `msDS-AllowedToActOnBehalfOfOtherIdentity` auf Resource‑Objekten erlaubt weiterhin S4U2self→S4U2proxy‑Impersonation, ohne Front‑End‑Service‑ACLs anzufassen.

## Schnelle Tools
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — gibt AES‑Hashes aus; planen Sie GPU‑Cracking oder zielen Sie stattdessen auf Benutzer mit deaktiviertem Pre‑Auth.
- **RC4‑Downgrade‑Zielsuche**: Enumerieren Sie Konten, die weiterhin RC4 ankündigen mit `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes`, um schwache Kerberoast‑Kandidaten zu finden, bevor RC4 vollständig deaktiviert ist.

## Referenzen
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
