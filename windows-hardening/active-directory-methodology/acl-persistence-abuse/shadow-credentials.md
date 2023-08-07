# Credenciales en Sombra

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introducción <a href="#3f17" id="3f17"></a>

Consulta la publicación original para [**toda la información sobre esta técnica**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

En resumen: si puedes escribir en la propiedad **msDS-KeyCredentialLink** de un usuario/ordenador, puedes obtener el **hash NT de ese objeto**.

Esto se debe a que podrás establecer credenciales de autenticación de clave pública-privada para el objeto y usarlas para obtener un **Ticket de Servicio especial que contiene su hash NTLM** dentro del Certificado de Atributo de Privilegio (PAC) en una entidad NTLM\_SUPPLEMENTAL\_CREDENTIAL encriptada que puedes descifrar.

### Requisitos <a href="#2de4" id="2de4"></a>

Esta técnica requiere lo siguiente:

* Al menos un Controlador de Dominio de Windows Server 2016.
* Un certificado digital para la autenticación del servidor instalado en el Controlador de Dominio.
* Nivel Funcional de Windows Server 2016 en Active Directory.
* Comprometer una cuenta con los derechos delegados para escribir en el atributo msDS-KeyCredentialLink del objeto objetivo.

## Abuso

El abuso de Key Trust para objetos de ordenador requiere pasos adicionales después de obtener un TGT y el hash NTLM de la cuenta. Generalmente hay dos opciones:

1. Forjar un **ticket de plata RC4** para suplantar a usuarios privilegiados en el host correspondiente.
2. Usar el TGT para llamar a **S4U2Self** para suplantar a **usuarios privilegiados** en el host correspondiente. Esta opción requiere modificar el Ticket de Servicio obtenido para incluir una clase de servicio en el nombre del servicio.

El abuso de Key Trust tiene la ventaja adicional de que no delega el acceso a otra cuenta que podría ser comprometida, sino que está **restringido a la clave privada generada por el atacante**. Además, no requiere crear una cuenta de ordenador que pueda ser difícil de limpiar hasta que se logre la escalada de privilegios.

Whisker

Junto con esta publicación, estoy lanzando una herramienta llamada "[Whisker](https://github.com/eladshamir/Whisker)". Basado en el código de DSInternals de Michael, Whisker proporciona un envoltorio en C# para realizar este ataque en compromisos. Whisker actualiza el objeto objetivo utilizando LDAP, mientras que DSInternals permite actualizar objetos utilizando tanto LDAP como RPC con el Servicio de Replicación de Directorios (DRS) Protocolo Remoto.

[Whisker](https://github.com/eladshamir/Whisker) tiene cuatro funciones:

* Add: Esta función genera un par de claves pública-privada y agrega una nueva credencial de clave al objeto objetivo como si el usuario se hubiera inscrito en WHfB desde un nuevo dispositivo.
* List: Esta función lista todas las entradas del atributo msDS-KeyCredentialLink del objeto objetivo.
* Remove: Esta función elimina una credencial de clave del objeto objetivo especificado por un GUID de DeviceID.
* Clear: Esta función elimina todos los valores del atributo msDS-KeyCredentialLink del objeto objetivo. Si el objeto objetivo está utilizando legítimamente WHfB, se romperá.

## [Whisker](https://github.com/eladshamir/Whisker) <a href="#7e2e" id="7e2e"></a>

Whisker es una herramienta en C# para tomar el control de cuentas de usuario y ordenador de Active Directory manipulando su atributo `msDS-KeyCredentialLink`, agregando efectivamente "Credenciales en Sombra" a la cuenta objetivo.

[**Whisker**](https://github.com/eladshamir/Whisker) tiene cuatro funciones:

* **Add**: Esta función genera un par de claves pública-privada y agrega una nueva credencial de clave al objeto objetivo como si el usuario se hubiera inscrito en WHfB desde un nuevo dispositivo.
* **List**: Esta función lista todas las entradas del atributo msDS-KeyCredentialLink del objeto objetivo.
* **Remove**: Esta función elimina una credencial de clave del objeto objetivo especificado por un GUID de DeviceID.
* **Clear**: Esta función elimina todos los valores del atributo msDS-KeyCredentialLink del objeto objetivo. Si el objeto objetivo está utilizando legítimamente WHfB, se romperá.

### Add

Agrega un nuevo valor al atributo **`msDS-KeyCredentialLink`** de un objeto objetivo:

* `/target:<samAccountName>`: Obligatorio. Establece el nombre del objetivo. Los objetos de ordenador deben terminar con el signo '$'.
* `/domain:<FQDN>`: Opcional. Establece el Nombre de Dominio Completo (FQDN) del objetivo. Si no se proporciona, intentará resolver el FQDN del usuario actual.
* `/dc:<IP/HOSTNAME>`: Opcional. Establece el Controlador de Dominio (DC) objetivo. Si no se proporciona, intentará apuntar al Controlador de Dominio Principal (PDC).
* `/path:<PATH>`: Opcional. Establece la ruta para almacenar el certificado autofirmado generado para la autenticación. Si no se proporciona, el certificado se mostrará como un blob Base64.
* `/password:<PASWORD>`: Opcional. Establece la contraseña para el certificado autofirmado almacenado. Si no se proporciona, se generará una contraseña aleatoria.

Ejemplo: **`Whisker.exe add /target:nombredeordenador$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\ruta\al\archivo.pfx /password:P@ssword1`**

{% hint style="info" %}
Más opciones en el [**Readme**](https://github.com/eladshamir/Whisker).
{% endhint %}
## [pywhisker](https://github.com/ShutdownRepo/pywhisker) <a href="#7e2e" id="7e2e"></a>

pyWhisker es el equivalente en Python del Whisker original creado por Elad Shamir y escrito en C#. Esta herramienta permite a los usuarios manipular el atributo msDS-KeyCredentialLink de un usuario/ordenador objetivo para obtener control total sobre ese objeto.

Está basado en Impacket y en un equivalente en Python de DSInternals de Michael Grafnetter llamado PyDSInternals creado por podalirius.
Esta herramienta, junto con PKINITtools de Dirk-jan, permite una explotación primitiva completa solo en sistemas basados en UNIX.

pyWhisker se puede utilizar para realizar varias acciones en el atributo msDs-KeyCredentialLink de un objetivo:

- *list*: listar todas las ID y el tiempo de creación actuales de KeyCredentials
- *info*: imprimir toda la información contenida en una estructura KeyCredential
- *add*: agregar un nuevo KeyCredential al msDs-KeyCredentialLink
- *remove*: eliminar un KeyCredential del msDs-KeyCredentialLink
- *clear*: eliminar todos los KeyCredentials del msDs-KeyCredentialLink
- *export*: exportar todos los KeyCredentials del msDs-KeyCredentialLink en formato JSON
- *import*: sobrescribir el msDs-KeyCredentialLink con KeyCredentials de un archivo JSON

pyWhisker admite las siguientes autenticaciones:
- (NTLM) Contraseña en texto claro
- (NTLM) Pass-the-hash
- (Kerberos) Contraseña en texto claro
- (Kerberos) Pass-the-key / Overpass-the-hash
- (Kerberos) Pass-the-cache (tipo de Pass-the-ticket)

![](https://github.com/ShutdownRepo/pywhisker/blob/main/.assets/add_pfx.png)


{% hint style="info" %}
Más opciones en el [**Readme**](https://github.com/ShutdownRepo/pywhisker).
{% endhint %}

## [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

En varios casos, el grupo "Everyone" / "Authenticated Users" / "Domain Users" u otro **grupo amplio** contiene casi todos los usuarios del dominio y tiene algunos DACLs de `GenericWrite`/`GenericAll` **sobre otros objetos** en el dominio. [**ShadowSpray**](https://github.com/Dec0ne/ShadowSpray/) intenta **abusar** de las **ShadowCredentials** sobre todos ellos.

El proceso es el siguiente:

1. **Iniciar sesión** en el dominio con las credenciales proporcionadas (o usar la sesión actual).
2. Comprobar que el **nivel funcional del dominio es 2016** (De lo contrario, detenerse ya que el ataque de Shadow Credentials no funcionará).
3. Recopilar una **lista de todos los objetos** en el dominio (usuarios y ordenadores) de LDAP.
4. **Para cada objeto** en la lista, hacer lo siguiente:
   1. Intentar **agregar KeyCredential** al atributo `msDS-KeyCredentialLink` del objeto.
   2. Si lo anterior es **exitoso**, usar **PKINIT** para solicitar un **TGT** utilizando el KeyCredential agregado.
   3. Si lo anterior es **exitoso**, realizar un ataque de **UnPACTheHash** para revelar el **hash NT** del usuario/ordenador.
   4. Si se especificó **`--RestoreShadowCred`**: Eliminar el KeyCredential agregado (limpiar después de ti mismo...).
   5. Si se especificó **`--Recursive`**: Realizar el **mismo proceso** utilizando cada una de las cuentas de usuario/ordenador que poseemos exitosamente.

## Referencias

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al repositorio [hacktricks](https://github.com/carlospolop/hacktricks) y al repositorio [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
