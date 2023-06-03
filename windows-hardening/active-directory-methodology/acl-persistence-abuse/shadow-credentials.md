# Credenciales Shadow

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introducción <a href="#3f17" id="3f17"></a>

Consulte la publicación original para obtener [**toda la información sobre esta técnica**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

En resumen: si puede escribir en la propiedad **msDS-KeyCredentialLink** de un usuario / computadora, puede recuperar el **hash NT de ese objeto**.

Esto se debe a que podrá establecer credenciales de autenticación de **clave pública-privada** para el objeto y usarlas para obtener un **Ticket de servicio especial que contiene su hash NTLM** dentro del Certificado de atributo de privilegio (PAC) en una entidad NTLM\_SUPPLEMENTAL\_CREDENTIAL cifrada que se puede descifrar.

### Requisitos <a href="#2de4" id="2de4"></a>

Esta técnica requiere lo siguiente:

* Al menos un controlador de dominio de Windows Server 2016.
* Un certificado digital para la autenticación del servidor instalado en el controlador de dominio.
* Nivel funcional de Windows Server 2016 en Active Directory.
* Comprometer una cuenta con los derechos delegados para escribir en el atributo msDS-KeyCredentialLink del objeto de destino.

## Abuso

El abuso de Key Trust para objetos de computadora requiere pasos adicionales después de obtener un TGT y el hash NTLM de la cuenta. En general, hay dos opciones:

1. Forjar un **RC4 silver ticket** para suplantar a usuarios privilegiados en el host correspondiente.
2. Usar el TGT para llamar a **S4U2Self** para suplantar a **usuarios privilegiados** en el host correspondiente. Esta opción requiere modificar el Ticket de servicio obtenido para incluir una clase de servicio en el nombre del servicio.

El abuso de Key Trust tiene la ventaja adicional de que no delega el acceso a otra cuenta que podría ser comprometida, está **restringido a la clave privada generada por el atacante**. Además, no requiere crear una cuenta de computadora que pueda ser difícil de limpiar hasta que se logre la escalada de privilegios.

Whisker

Junto con esta publicación, estoy lanzando una herramienta llamada "[Whisker](https://github.com/eladshamir/Whisker)". Basado en el código de DSInternals de Michael, Whisker proporciona un envoltorio C# para realizar este ataque en compromisos. Whisker actualiza el objeto de destino usando LDAP, mientras que DSInternals permite actualizar objetos usando tanto LDAP como RPC con el servicio de replicación de directorios (DRS) Protocolo remoto.

[Whisker](https://github.com/eladshamir/Whisker) tiene cuatro funciones:

* Agregar: esta función genera un par de claves pública-privada y agrega una nueva credencial de clave al objeto de destino como si el usuario se hubiera inscrito en WHfB desde un nuevo dispositivo.
* Listar: esta función enumera todas las entradas del atributo msDS-KeyCredentialLink del objeto de destino.
* Eliminar: esta función elimina una credencial de clave del objeto de destino especificada por un GUID de DeviceID.
* Limpiar: esta función elimina todos los valores del atributo msDS-KeyCredentialLink del objeto de destino. Si el objeto de destino está utilizando legítimamente WHfB
