# Authentification Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Consultez l'excellent article :** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR pour les attaquants
- Kerberos est le protocole d'authentification par défaut d'AD ; la plupart des chaînes de mouvement latéral y auront recours. Pour des cheatsheets pratiques (AS‑REP/Kerberoasting, ticket forging, delegation abuse, etc.) voir :
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Notes d'attaque récentes (2024‑2026)
- **RC4 disparaît enfin** – Les DCs Windows Server 2025 n'émettent plus de TGTs RC4 ; Microsoft prévoit de désactiver RC4 par défaut pour les DC AD d'ici la fin du T2 2026. Les environnements qui ré‑activent RC4 pour des applications legacy créent des opportunités de downgrade/fast‑crack pour Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – Les mises à jour d'avril 2025 suppriment le mode “Compatibility” ; les PACs falsifiés / golden tickets sont rejetés sur les DCs patchés lorsque l'enforcement est activé. Les DCs legacy/non patchés restent exploitables.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Si les DCs ne sont pas patchés ou laissés en mode Audit, les certificats chaînés à des CA non‑NTAuth mais mappés via SKI/altSecID peuvent toujours se connecter. Des événements 45/21 apparaissent lorsque les protections se déclenchent.
- **Suppression progressive de NTLM** – Microsoft livrera les futures versions de Windows avec NTLM désactivé par défaut (déploiement prévu jusqu'en 2026), poussant davantage d'authentifications vers Kerberos. Attendez‑vous à une surface Kerberos accrue et à des EPA/CBT plus stricts dans les réseaux durcis.
- **RBCD inter‑domain reste puissant** – Microsoft Learn indique que la resource‑based constrained delegation fonctionne à travers domaines/forests ; l'attribut modifiable `msDS-AllowedToActOnBehalfOfOtherIdentity` sur les objets de ressource permet toujours l'usurpation S4U2self→S4U2proxy sans toucher les ACLs des services frontaux.

## Outils rapides
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — renvoie des hashes AES ; prévoyez du cracking GPU ou ciblez plutôt les comptes avec pre‑auth désactivé.
- **RC4 downgrade target hunting**: énumérez les comptes qui annoncent encore RC4 avec `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` pour localiser des candidats kerberoast faibles avant que RC4 soit complètement désactivé.



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
