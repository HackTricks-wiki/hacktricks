# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Le build recenti di Windows hanno introdotto il **supporto del client SMB per porte TCP alternative**. Questa funzionalita puo essere sfruttata per trasformare l'**autenticazione NTLM locale** in una **local privilege escalation a SYSTEM** quando l'attaccante puo:<sup>[[1]](#references)</sup>

1. Aprire una connessione SMB verso un listener controllato dall'attaccante su una **porta diversa dalla 445**
2. Mantenere attiva la connessione TCP
3. Indurre un **client locale privilegiato** ad accedere allo **stesso percorso della share SMB**
4. Eseguire il relay della **autenticazione NTLM locale** risultante verso il vero servizio SMB della macchina

Questa e la primitive alla base di **CVE-2026-24294**, corretta nel **marzo 2026**.<sup>[[1]](#references)[[4]](#references)</sup>

## Perche funziona

La tecnica piu vecchia di reflection CMTI / serialized-SPN e descritta qui:

{{#ref}}
../ntlm/README.md
{{#endref}}

Questa variante piu recente **non** richiede un hostname marshalled. Sfrutta invece due comportamenti del client SMB:<sup>[[1]](#references)</sup>

- **Supporto per porte alternative** su **Windows 11 24H2** e **Windows Server 2025**, esposto agli utenti tramite `net use \\host\share /tcpport:<port>`
- **Riuso / multiplexing delle connessioni SMB**, in cui piu sessioni autenticate possono utilizzare la stessa connessione TCP

Questo significa che un utente con pochi privilegi puo prima creare una connessione TCP dal client SMB verso un server SMB dell'attaccante su una porta alta, quindi indurre un servizio privilegiato ad accedere al **percorso UNC esatto**. Se Windows decide di riutilizzare la connessione TCP esistente, lo scambio NTLM privilegiato viene inviato attraverso il transport controllato dall'attaccante e puo essere sottoposto a relay verso il server SMB locale.<sup>[[1]](#references)</sup>

## Prerequisiti

- Il target supporta le porte alternative SMB:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** o versioni successive
- **Windows Server 2025** o versioni successive
- L'attaccante puo eseguire un server SMB locale o remoto su una porta alta scelta
- L'attaccante puo indurre un servizio privilegiato ad accedere a un percorso UNC
- L'autenticazione privilegiata deve essere una **autenticazione NTLM locale**
- Il target deve essere relayable:<sup>[[1]](#references)</sup>
- Synacktiv ha riportato che la tecnica funzionava per impostazione predefinita su **Windows Server 2025**
- La loro chain **non** funzionava su **Windows 11 24H2** perche la firma SMB in uscita e applicata li per impostazione predefinita

## Userland e internals

Dalla command line la funzionalita appare semplice:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmaticamente, il client usa `WNetAddConnection4W` con dati `lpUseOptions` non documentati. L'opzione rilevante è `TraP` (transport parameters), che alla fine raggiunge il client SMB del kernel tramite un FSCTL e viene analizzata da `mrxsmb`.<sup>[[1]](#references)[[3]](#references)</sup>

Note pratiche importanti:<sup>[[1]](#references)</sup>

- **La sintassi UNC continua a non avere un campo per la porta**
- **`net use` è per-sessione di logon**
- Il bypass funziona comunque perché **la connessione TCP e la sessione SMB sono oggetti separati**
- Riutilizzare **lo stesso percorso della share** è obbligatorio se l'exploit dipende dal riutilizzo, da parte del client SMB, della connessione TCP creata in precedenza

## Exploitation flow

### 1. Create the attacker-controlled SMB transport

Esegui un server SMB su una porta alta e fai connettere Windows a essa:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Il server può accettare qualsiasi coppia di credenziali sotto il tuo controllo, ad esempio `user:user`. L'obiettivo di questo passaggio non è ancora la privilege escalation, ma solo fare in modo che il client SMB di Windows apra e mantenga una connessione TCP riutilizzabile verso il tuo listener.<sup>[[1]](#references)</sup>

### 2. Forzare un servizio privilegiato verso lo stesso percorso UNC

Usa una coercion primitive come **PetitPotam** sullo **stesso** percorso `\\192.168.56.3\share`. Se il client forzato dispone di privilegi e il nome di destinazione è locale (`localhost` o un IP/host locale), Windows esegue una **local authentication NTLM**.

Poiché la connessione TCP viene riutilizzata, questo scambio NTLM privilegiato viene inviato al servizio SMB dell'attacker invece che direttamente al vero server SMB locale.<sup>[[1]](#references)</sup>

### 3. Eseguire il relay dell'autenticazione privilegiata verso SMB locale

Il servizio SMB controllato dall'attacker inoltra lo scambio NTLM privilegiato a `ntlmrelayx.py`, che esegue il relay verso il listener SMB reale della macchina e ottiene una sessione come `NT AUTHORITY\SYSTEM`.<sup>[[1]](#references)</sup>

Strumenti tipici riportati nella writeup pubblica:<sup>[[1]](#references)</sup>

- `smbserver.py` su una porta personalizzata per ricevere l'autenticazione privilegiata tramite la connessione TCP riutilizzata
- `ntlmrelayx.py` per eseguire il relay dell'NTLM catturato verso SMB locale
- `PetitPotam.exe` o un'altra coercion primitive per forzare l'autenticazione privilegiata

## Note per l'operatore

- Questa è una tecnica di **local privilege escalation**, non un generico trucco di remote relay<sup>[[1]](#references)</sup>
- Il servizio SMB controllato dall'attacker deve gestire l'autenticazione privilegiata sulla **stessa connessione TCP** utilizzata originariamente per il montaggio della share<sup>[[1]](#references)</sup>
- Se l'accesso forzato raggiunge un **percorso share differente**, Windows potrebbe stabilire una connessione diversa e la catena si interromperebbe<sup>[[1]](#references)</sup>
- I requisiti di SMB signing possono bloccare il relay anche quando il passaggio tramite porta arbitraria funziona<sup>[[1]](#references)</sup>
- Se disponi solo di materiale Kerberos o non puoi forzare NTLM locale, questa variante esatta non è sufficiente<sup>[[1]](#references)</sup>

## Rilevamento e hardening

- Installa la patch per **CVE-2026-24294** inclusa nel **Patch Tuesday di marzo 2026**<sup>[[4]](#references)</sup>
- Monitora l'uso di `net use` o `New-SmbMapping` con **porte SMB non predefinite**<sup>[[1]](#references)</sup>
- Genera un alert per traffico SMB in uscita insolito dalle workstation o dai server verso **porte TCP elevate**<sup>[[1]](#references)</sup>
- Verifica le opportunità di coercion, come i trigger in stile **EFSRPC / PetitPotam**<sup>[[1]](#references)</sup>
- Applica SMB signing dove possibile; Synacktiv specifica che questa misura ha bloccato il loro relay su Windows 11 24H2<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
