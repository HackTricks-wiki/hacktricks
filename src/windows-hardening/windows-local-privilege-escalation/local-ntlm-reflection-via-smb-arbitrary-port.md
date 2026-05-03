# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Le build recenti di Windows hanno introdotto il **supporto SMB client per porte TCP alternative**. Questa funzionalità può essere abusata per trasformare l'**autenticazione NTLM locale** in una **privilege escalation locale SYSTEM** quando l'attaccante può:

1. Aprire una connessione SMB verso un listener controllato dall'attaccante su una **porta diversa da 445**
2. Mantenere viva quella connessione TCP
3. Costringere un **client locale privilegiato** ad accedere allo **stesso percorso della share SMB**
4. Relay dell'**autenticazione NTLM locale** risultante verso il vero servizio SMB della macchina

Questa è la primitive dietro **CVE-2026-24294**, corretta nel **March 2026**.

## Why it works

Il vecchio trucco di reflection CMTI / serialized-SPN è trattato qui:

{{#ref}}
../ntlm/README.md
{{#endref}}

Questa variante più recente **non** richiede un hostname marshalled. Invece abusa di due comportamenti del client SMB:

- **Supporto per porte alternative** su **Windows 11 24H2** e **Windows Server 2025**, esposto agli utenti con `net use \\host\share /tcpport:<port>`
- **Riutilizzo / multiplexing della connessione SMB**, dove più sessioni autenticate possono viaggiare sulla stessa connessione TCP

Questo significa che un utente con privilegi bassi può prima creare una connessione TCP dal client SMB verso un server SMB dell'attaccante su una porta alta, poi costringere un servizio privilegiato ad accedere allo **stesso identico percorso UNC**. Se Windows decide di riutilizzare la connessione TCP esistente, lo scambio NTLM privilegiato viene inviato sul trasporto controllato dall'attaccante e può essere relayato al server SMB locale.

## Preconditions

- Il target supporta porte SMB alternative:
- **Windows 11 24H2** o successivo
- **Windows Server 2025** o successivo
- L'attaccante può eseguire un server SMB locale o remoto su una porta alta scelta
- L'attaccante può costringere un servizio privilegiato ad accedere a un percorso UNC
- L'autenticazione privilegiata deve essere **NTLM local authentication**
- Il target deve essere relayable:
- Synacktiv ha segnalato che funzionava di default su **Windows Server 2025**
- La loro chain **non** funzionava su **Windows 11 24H2** perché lì SMB signing in uscita è imposto di default

## Userland and internals

Dalla command line la funzionalità sembra semplice:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmaticamente, il client usa `WNetAddConnection4W` con dati `lpUseOptions` non documentati. L'opzione rilevante è `TraP` (transport parameters), che alla fine raggiunge il client SMB del kernel tramite un FSCTL ed è analizzata da `mrxsmb`.

Note pratiche importanti:

- **La sintassi UNC non ha ancora un campo per la porta**
- **`net use` è per-logon-session**
- Il bypass funziona ancora perché **la connessione TCP e la sessione SMB sono oggetti separati**
- Riutilizzare lo **stesso share path** è obbligatorio se l'exploit dipende dal fatto che il client SMB riusi la connessione TCP creata in precedenza

## Flusso di exploitation

### 1. Create the attacker-controlled SMB transport

Esegui un SMB server su una porta alta e fai connettere Windows ad esso:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Il server può accettare qualsiasi coppia di credenziali che controlli, per esempio `user:user`. L’obiettivo di questo passo non è ancora il privilege escalation, ma solo far aprire al client SMB di Windows e mantenere una connessione TCP riutilizzabile verso il tuo listener.

### 2. Costringere un servizio privilegiato allo stesso percorso UNC

Usa una coercion primitive come **PetitPotam** contro lo **stesso** percorso `\\192.168.56.3\share`. Se il client forzato è privilegiato e il nome target è locale (`localhost` o un host/IP locale), Windows esegue **NTLM local authentication**.

Poiché la connessione TCP viene riutilizzata, quello scambio NTLM privilegiato viaggia verso il servizio SMB dell’attaccante invece che direttamente al vero server SMB locale.

### 3. Relay dell’autenticazione privilegiata verso SMB locale

Il servizio SMB controllato dall’attaccante inoltra lo scambio NTLM privilegiato a `ntlmrelayx.py`, che lo relaya al vero listener SMB della macchina e ottiene una sessione come `NT AUTHORITY\SYSTEM`.

Tool tipici dalla public writeup:

- `smbserver.py` su una porta custom per ricevere l’auth privilegiata sulla connessione TCP riutilizzata
- `ntlmrelayx.py` per relayare l’NTLM catturato verso SMB locale
- `PetitPotam.exe` o un’altra coercion primitive per forzare l’autenticazione privilegiata

## Note operative

- Questa è una tecnica di **local privilege escalation**, non un generico remote relay trick
- Il servizio SMB controllato dall’attaccante deve gestire l’autenticazione privilegiata sulla **stessa connessione TCP** usata inizialmente per il mount della share
- Se l’accesso forzato colpisce un **percorso di share diverso**, Windows può stabilire una connessione diversa e la chain si rompe
- I requisiti di SMB signing possono bloccare il relay anche quando il passo della porta arbitraria funziona
- Se hai solo materiale Kerberos o non puoi forzare NTLM locale, questa variante esatta non basta

## Detection and hardening

- Patch **CVE-2026-24294** da **March 2026 Patch Tuesday**
- Monitora `net use` o `New-SmbMapping` che usano **porte SMB non di default**
- Allerta su SMB in uscita insolito da workstation o server verso **porte TCP alte**
- Esamina opportunità di coercion come trigger **EFSRPC / PetitPotam-style**
- Applica SMB signing dove possibile; Synacktiv nota specificamente che questo ha bloccato il loro relay su Windows 11 24H2

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
