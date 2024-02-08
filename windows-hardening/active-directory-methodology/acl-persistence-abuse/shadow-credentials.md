# Credenciales en Sombra

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres que tu **empresa sea anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introducción <a href="#3f17" id="3f17"></a>

**Consulta la publicación original para [toda la información sobre esta técnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

En **resumen**: si puedes escribir en la propiedad **msDS-KeyCredentialLink** de un usuario/computadora, puedes recuperar el **hash NT de ese objeto**.

En la publicación se describe un método para configurar credenciales de autenticación **clave pública-privada** para adquirir un **Ticket de Servicio** único que incluye el hash NTLM del objetivo. Este proceso implica el NTLM_SUPPLEMENTAL_CREDENTIAL encriptado dentro del Certificado de Atributo de Privilegio (PAC), que se puede descifrar.

### Requisitos

Para aplicar esta técnica, se deben cumplir ciertas condiciones:
- Se necesita un mínimo de un Controlador de Dominio de Windows Server 2016.
- El Controlador de Dominio debe tener instalado un certificado digital de autenticación de servidor.
- El Active Directory debe estar en el Nivel Funcional de Windows Server 2016.
- Se requiere una cuenta con derechos delegados para modificar el atributo msDS-KeyCredentialLink del objeto objetivo.

## Abuso

El abuso de Key Trust para objetos de computadora abarca pasos más allá de obtener un Ticket Granting Ticket (TGT) y el hash NTLM. Las opciones incluyen:
1. Crear un **ticket silver RC4** para actuar como usuarios privilegiados en el host previsto.
2. Utilizar el TGT con **S4U2Self** para la suplantación de **usuarios privilegiados**, lo que requiere modificaciones en el Ticket de Servicio para agregar una clase de servicio al nombre del servicio.

Una ventaja significativa del abuso de Key Trust es su limitación a la clave privada generada por el atacante, evitando la delegación a cuentas potencialmente vulnerables y sin necesidad de crear una cuenta de computadora, lo que podría ser difícil de eliminar.

## Herramientas

### [**Whisker**](https://github.com/eladshamir/Whisker)

Está basado en DSInternals y proporciona una interfaz C# para este ataque. Whisker y su contraparte en Python, **pyWhisker**, permiten la manipulación del atributo `msDS-KeyCredentialLink` para obtener control sobre las cuentas de Active Directory. Estas herramientas admiten diversas operaciones como agregar, listar, eliminar y limpiar credenciales clave del objeto objetivo.

Las funciones de **Whisker** incluyen:
- **Add**: Genera un par de claves y agrega una credencial clave.
- **List**: Muestra todas las entradas de credenciales clave.
- **Remove**: Elimina una credencial clave especificada.
- **Clear**: Borra todas las credenciales clave, lo que podría interrumpir el uso legítimo de WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Extiende la funcionalidad de Whisker a sistemas basados en **UNIX**, aprovechando Impacket y PyDSInternals para capacidades de explotación exhaustivas, que incluyen listar, agregar y eliminar KeyCredentials, así como importar y exportarlos en formato JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray tiene como objetivo **explotar permisos GenericWrite/GenericAll que grupos de usuarios amplios pueden tener sobre objetos de dominio** para aplicar ShadowCredentials de manera amplia. Implica iniciar sesión en el dominio, verificar el nivel funcional del dominio, enumerar objetos de dominio e intentar agregar KeyCredentials para la adquisición de TGT y la revelación de hash NT. Las opciones de limpieza y las tácticas de explotación recursiva mejoran su utilidad.


## Referencias

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial mercancía de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
