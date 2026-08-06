# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

L’**attaque Skeleton Key** est une technique qui permet aux attaquants de **contourner l’authentification Active Directory** en **injectant un mot de passe maître** dans le processus LSASS de chaque contrôleur de domaine. Après l’injection, le mot de passe maître (par défaut **`mimikatz`**) peut être utilisé pour s’authentifier en tant que **n’importe quel utilisateur du domaine**, tandis que leurs mots de passe réels continuent de fonctionner.<sup>[[1]](#references)[[2]](#references)</sup>

Points clés :

- Nécessite **Domain Admin/SYSTEM + SeDebugPrivilege** sur chaque DC et doit être **réappliqué après chaque redémarrage**.<sup>[[2]](#references)</sup>
- Patche les chemins de validation **NTLM** et **Kerberos RC4 (etype 0x17)** ; les realms uniquement AES ou les comptes imposant AES **n’accepteront pas la skeleton key**.<sup>[[2]](#references)</sup>
- Peut entrer en conflit avec des packages d’authentification LSA tiers ou des fournisseurs supplémentaires de cartes à puce / MFA.<sup>[[2]](#references)</sup>
- Le module Mimikatz accepte le switch optionnel `/letaes` afin d’éviter de modifier les hooks Kerberos/AES en cas de problèmes de compatibilité.<sup>[[3]](#references)</sup>

### Execution

LSASS classique, non protégé par PPL :
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Si **LSASS s’exécute en tant que PPL** (RunAsPPL/Credential Guard/LSASS sécurisé de Windows 11), un pilote kernel est nécessaire pour supprimer la protection avant de patcher LSASS :<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Après l’injection, authentifiez-vous avec n’importe quel compte du domaine, mais utilisez le mot de passe `mimikatz` (ou la valeur définie par l’opérateur). N’oubliez pas de répéter l’opération sur **tous les DCs** dans les environnements comportant plusieurs DCs.

## Mesures d’atténuation

- **Surveillance des logs**
- **Event ID 7045** du système (installation de service/driver) pour les drivers non signés tels que `mimidrv.sys`.
- **Sysmon** : Event ID 7 (chargement de driver) pour `mimidrv.sys` ; Event ID 10 pour les accès suspects à `lsass.exe` depuis des processus non système.
- **Event ID 4673/4611** de sécurité pour l’utilisation de privilèges sensibles ou les anomalies d’enregistrement de packages d’authentification LSA ; corrélez-les avec les logons 4624 inattendus utilisant RC4 (etype 0x17) depuis les DCs.
- **Hardening de LSASS**
- Maintenez **RunAsPPL/Credential Guard/Secure LSASS** activés sur les DCs afin de contraindre les attaquants à déployer un driver en kernel mode (davantage de télémétrie, exploitation plus difficile).
- Désactivez **RC4** legacy lorsque cela est possible ; les tickets Kerberos limités à AES empêchent le chemin de hook RC4 utilisé par le skeleton key.<sup>[[2]](#references)</sup>
- Recherches rapides avec PowerShell :
- Détecter les installations de drivers kernel non signés : `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Rechercher le driver Mimikatz : `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Vérifier que PPL est appliqué après le redémarrage : `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Pour obtenir des recommandations supplémentaires sur le hardening des credentials, consultez [Protections des credentials Windows](../stealing-credentials/credentials-protections.md).

## Références

- [1] [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
