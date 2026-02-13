# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

L'attaque **Skeleton Key** est une technique qui permet aux attaquants de **contourner l'authentification Active Directory** en **injectant un mot de passe maître** dans le processus LSASS de chaque domain controller. Après l'injection, le mot de passe maître (par défaut **`mimikatz`**) peut être utilisé pour s'authentifier en tant que **n'importe quel utilisateur du domaine** tandis que leurs vrais mots de passe restent valides.

Faits clés:

- Nécessite **Domain Admin/SYSTEM + SeDebugPrivilege** sur chaque DC et doit être réappliqué après chaque redémarrage.
- Modifie les chemins de validation **NTLM** et **Kerberos RC4 (etype 0x17)** ; les realms uniquement AES ou les comptes imposant AES n'accepteront pas le skeleton key.
- Peut entrer en conflit avec des packages d'authentification LSA tiers ou des fournisseurs supplémentaires de smart‑card / MFA.
- Le module Mimikatz accepte l'option `/letaes` pour éviter de toucher les hooks Kerberos/AES en cas de problèmes de compatibilité.

### Exécution

LSASS classique non‑PPL protégé:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Si **LSASS fonctionne en tant que PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), un pilote noyau est nécessaire pour supprimer la protection avant de patcher LSASS :
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Après l'injection, authentifiez‑vous avec n'importe quel compte de domaine mais utilisez le mot de passe `mimikatz` (ou la valeur définie par l'opérateur). N'oubliez pas de répéter sur **tous les DCs** dans les environnements multi‑DC.

## Mesures d'atténuation

- **Surveillance des logs**
- Système **Event ID 7045** (installation de service/driver) pour les drivers non signés tels que `mimidrv.sys`.
- **Sysmon** : Event ID 7 (chargement de driver) pour `mimidrv.sys` ; Event ID 10 pour accès suspect à `lsass.exe` depuis des processus non‑système.
- Sécurité **Event ID 4673/4611** pour l'utilisation de privilèges sensibles ou des anomalies d'enregistrement du package d'authentification LSA ; corréler avec des connexions 4624 inattendues utilisant RC4 (etype 0x17) provenant des DCs.
- **Renforcement de LSASS**
- Garder **RunAsPPL/Credential Guard/Secure LSASS** activé sur les DCs pour forcer les attaquants à déployer des drivers en mode noyau (plus de télémétrie, exploitation plus difficile).
- Désactiver le **RC4** hérité lorsque possible ; limiter les tickets Kerberos à AES empêche la voie de hook RC4 utilisée par le skeleton key.
- Recherches PowerShell rapides :
- Detect unsigned kernel driver installs: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Hunt for Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Validate PPL is enforced after reboot: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Pour des conseils supplémentaires sur le durcissement des identifiants, consultez [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
