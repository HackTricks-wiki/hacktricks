# Credenciales en la Sombra

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres que tu **empresa sea anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al **grupo de Telegram** o **sígueme** en **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introducción <a href="#3f17" id="3f17"></a>

Consulta la publicación original para [**toda la información sobre esta técnica**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

En **resumen**: si puedes escribir en la propiedad **msDS-KeyCredentialLink** de un usuario/computadora, puedes recuperar el **hash NT de ese objeto**.

Esto se debe a que podrás establecer **credenciales de autenticación de clave pública-privada** para el objeto y usarlas para obtener un **Tique de Servicio especial que contiene su hash NT** dentro del Certificado de Atributos de Privilegio (PAC) en una entidad NTLM\_SUPPLEMENTAL\_CREDENTIAL encriptada que puedes descifrar.

### Requisitos <a href="#2de4" id="2de4"></a>

Esta técnica requiere lo siguiente:

* Al menos un Controlador de Dominio de Windows Server 2016.
* Un certificado digital para Autenticación de Servidor instalado en el Controlador de Dominio.
* Nivel Funcional de Windows Server 2016 en Active Directory.
* Comprometer una cuenta con los derechos delegados para escribir en el atributo msDS-KeyCredentialLink del objeto objetivo.

## Abuso

Abusar de Key Trust para objetos de computadora requiere pasos adicionales después de obtener un TGT y el hash NT de la cuenta. Generalmente hay dos opciones:

1. Forjar un **tique de plata RC4** para hacerse pasar por usuarios privilegiados en el host correspondiente.
2. Usar el TGT para llamar a **S4U2Self** para hacerse pasar por **usuarios privilegiados** en el host correspondiente. Esta opción requiere modificar el Tique de Servicio obtenido para incluir una clase de servicio en el nombre del servicio.

El abuso de Key Trust tiene el beneficio adicional de que no delega acceso a otra cuenta que podría ser comprometida, está **restringido a la clave privada generada por el atacante**. Además, no requiere crear una cuenta de computadora que podría ser difícil de limpiar hasta lograr la escalada de privilegios.

Whisker

Junto con esta publicación, estoy lanzando una herramienta llamada " [Whisker](https://github.com/eladshamir/Whisker) ". Basado en el código de DSInternals de Michael, Whisker proporciona un envoltorio C# para realizar este ataque en compromisos. Whisker actualiza el objeto objetivo utilizando LDAP, mientras que DSInternals permite actualizar objetos utilizando tanto LDAP como RPC con el Servicio de Replicación de Directorio (DRS) Remote Protocol.

[Whisker](https://github.com/eladshamir/Whisker) tiene cuatro funciones:

* Agregar: Esta función genera un par de claves pública-privada y agrega una nueva credencial de clave al objeto objetivo como si el usuario se hubiera inscrito en WHfB desde un nuevo dispositivo.
* Listar: Esta función lista todas las entradas del atributo msDS-KeyCredentialLink del objeto objetivo.
* Eliminar: Esta función elimina una credencial de clave del objeto objetivo especificada por un GUID de DeviceID.
* Limpiar: Esta función elimina todos los valores del atributo msDS-KeyCredentialLink del objeto objetivo. Si el objeto objetivo está utilizando legítimamente WHfB, se romperá.

## [Whisker](https://github.com/eladshamir/Whisker) <a href="#7e2e" id="7e2e"></a>

Whisker es una herramienta C# para tomar el control de cuentas de usuario y computadora de Active Directory manipulando su atributo `msDS-KeyCredentialLink`, agregando efectivamente "Credenciales en la Sombra" a la cuenta objetivo.

[**Whisker**](https://github.com/eladshamir/Whisker) tiene cuatro funciones:

* **Agregar** — Esta función genera un par de claves pública-privada y agrega una nueva credencial de clave al objeto objetivo como si el usuario se hubiera inscrito en WHfB desde un nuevo dispositivo.
* **Listar** — Esta función lista todas las entradas del atributo msDS-KeyCredentialLink del objeto objetivo.
* **Eliminar** — Esta función elimina una credencial de clave del objeto objetivo especificada por un GUID de DeviceID.
* **Limpiar** — Esta función elimina todos los valores del atributo msDS-KeyCredentialLink del objeto objetivo. Si el objeto objetivo está utilizando legítimamente WHfB, se romperá.

### Agregar

Agregar un nuevo valor al atributo **`msDS-KeyCredentialLink`** de un objeto objetivo:

* `/objetivo:<samAccountName>`: Requerido. Establece el nombre del objetivo. Los objetos de computadora deben terminar con un signo '$'.
* `/dominio:<FQDN>`: Opcional. Establece el Nombre de Dominio Completo (FQDN) del objetivo. Si no se proporciona, intentará resolver el FQDN del usuario actual.
* `/dc:<IP/HOSTNAME>`: Opcional. Establece el Controlador de Dominio (DC) de destino. Si no se proporciona, intentará apuntar al Controlador de Dominio Principal (PDC).
* `/ruta:<RUTA>`: Opcional. Establece la ruta para almacenar el certificado autofirmado generado para la autenticación. Si no se proporciona, el certificado se imprimirá como un blob Base64.
* `/contraseña:<CONTRASEÑA>`: Opcional. Establece la contraseña para el certificado autofirmado almacenado. Si no se proporciona, se generará una contraseña aleatoria.

Ejemplo: **`Whisker.exe add /objetivo:nombrecomputadora$ /dominio:constoso.local /dc:dc1.contoso.local /ruta:C:\ruta\a\archivo.pfx /contraseña:P@ssword1`**

{% hint style="info" %}
Más opciones en el [**Readme**](https://github.com/eladshamir/Whisker).
{% endhint %}

## [pywhisker](https://github.com/ShutdownRepo/pywhisker) <a href="#7e2e" id="7e2e"></a>

pyWhisker es un equivalente en Python del Whisker original creado por Elad Shamir y escrito en C#. Esta herramienta permite a los usuarios manipular el atributo msDS-KeyCredentialLink de un usuario/computadora objetivo para obtener control total sobre ese objeto.

Está basado en Impacket y en un equivalente en Python de DSInternals de Michael Grafnetter llamado PyDSInternals hecho por podalirius.
Esta herramienta, junto con las PKINITtools de Dirk-jan, permiten una explotación primitiva completa solo en sistemas basados en UNIX.


pyWhisker se puede utilizar para realizar varias acciones en el atributo msDs-KeyCredentialLink de un objetivo

- *listar*: listar todos los ID de KeyCredentials y la hora de creación actuales
- *info*: imprimir toda la información contenida en una estructura KeyCredential
- *agregar*: agregar un nuevo KeyCredential al msDs-KeyCredentialLink
- *eliminar*: eliminar un KeyCredential del msDs-KeyCredentialLink
- *limpiar*: eliminar todos los KeyCredentials del msDs-KeyCredentialLink
- *exportar*: exportar todos los KeyCredentials del msDs-KeyCredentialLink en JSON
- *importar*: sobrescribir el msDs-KeyCredentialLink con KeyCredentials de un archivo JSON


pyWhisker admite las siguientes autenticaciones:
- (NTLM) Contraseña en texto claro
- (NTLM) Pasar el hash
- (Kerberos) Contraseña en texto claro
- (Kerberos) Pasar la clave / Pasar el hash
- (Kerberos) Pasar la caché (tipo de Pasar el tique)

![](https://github.com/ShutdownRepo/pywhisker/blob/main/.assets/add_pfx.png)


{% hint style="info" %}
Más opciones en el [**Readme**](https://github.com/ShutdownRepo/pywhisker).
{% endhint %}

## [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

En varios casos, el grupo "Everyone" / "Authenticated Users" / "Domain Users" u otro **grupo amplio** contiene casi todos los usuarios en el dominio y tiene algunos DACLs de **GenericWrite**/ **GenericAll** **sobre otros objetos** en el dominio. [**ShadowSpray**](https://github.com/Dec0ne/ShadowSpray/) intenta **abusar** por lo tanto de **Credenciales en la Sombra** sobre todos ellos

Funciona de la siguiente manera:

1. **Iniciar sesión** en el dominio con las credenciales proporcionadas (o usar la sesión actual).
2. Verificar que el **nivel funcional del dominio sea 2016** (De lo contrario, detenerse ya que el ataque de Credenciales en la Sombra no funcionará)
3. Recopilar una **lista de todos los objetos** en el dominio (usuarios y computadoras) desde LDAP.
4. **Para cada objeto** en la lista, hacer lo siguiente:
1. Intentar **agregar KeyCredential** al atributo `msDS-KeyCredentialLink` del objeto.
2. Si lo anterior es **exitoso**, usar **PKINIT** para solicitar un **TGT** usando el KeyCredential agregado.
3. Si lo anterior es **exitoso**, realizar un ataque **UnPACTheHash** para revelar el hash NT del usuario/computadora.
4. Si se especificó **`--RestoreShadowCred`**: Eliminar el KeyCredential agregado (limpiar después de ti mismo...)
5. Si se especificó **`--Recursive`**: Realizar el **mismo proceso** utilizando cada una de las cuentas de usuario/computadora **que poseemos exitosamente**.

## Referencias

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/) 

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres que tu **empresa sea anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al **grupo de Telegram** o **sígueme** en **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
