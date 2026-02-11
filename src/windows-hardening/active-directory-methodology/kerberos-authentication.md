# Authentification Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Consultez l'excellent article :** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR pour les attaquants
- Kerberos est le protocole d'auth AD par défaut ; la plupart des chaînes de lateral-movement y feront appel. Pour des fiches pratiques (AS‑REP/Kerberoasting, ticket forging, delegation abuse, etc.) voir :
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Notes d'attaque récentes (2024‑2026)
- **RC4 finally going away** – Les DCs Windows Server 2025 ne délivrent plus de TGTs RC4 ; Microsoft prévoit de désactiver RC4 par défaut pour les AD DCs d'ici la fin du Q2 2026. Les environnements qui ré‑activent RC4 pour des apps legacy créent des opportunités de downgrade/fast‑crack pour Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – Les mises à jour d'avril 2025 suppriment le mode “Compatibility” ; les PACs forgés/golden tickets sont rejetés par les DCs patchés quand l'enforcement est activé. Les DCs legacy/unpatched restent exploitables.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Si les DCs ne sont pas patchés ou laissés en mode Audit, les certificates chaînés à des non‑NTAuth CAs mais mappés via SKI/altSecID peuvent toujours se connecter. Les événements 45/21 apparaissent lorsque les protections se déclenchent.
- **NTLM phase‑out** – Microsoft livrera les futures releases de Windows avec NTLM désactivé par défaut (déploiement progressif jusqu'en 2026), poussant davantage d'auth vers Kerberos. Attendez-vous à une surface Kerberos accrue et à des EPA/CBT plus stricts dans les réseaux durcis.
- **Cross‑domain RBCD remains powerful** – Microsoft Learn note que la resource‑based constrained delegation fonctionne à travers domaines/forests ; l'attribut inscriptible `msDS-AllowedToActOnBehalfOfOtherIdentity` sur les resource objects permet toujours l'impersonation S4U2self→S4U2proxy sans toucher aux ACLs des services front‑end.

## Quick tooling
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — génère des hashes AES ; prévoyez un cracking GPU ou ciblez plutôt des utilisateurs dont la pre‑auth est désactivée.
- **RC4 downgrade target hunting**: énumérez les comptes qui annoncent encore RC4 avec `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` pour localiser des candidats kerberoast faibles avant que RC4 soit complètement désactivé.



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
