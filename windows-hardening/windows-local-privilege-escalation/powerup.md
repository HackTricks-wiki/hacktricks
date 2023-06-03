<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al repositorio [hacktricks](https://github.com/carlospolop/hacktricks) y al repositorio [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Invoke
```text
powershell -ep bypass
. .\powerup.ps
Invoke-AllChecks
```
# Comprobaciones

_03/2019_

* [x] Privilegios actuales
* [x] Rutas de servicio sin comillas
* [x] Permisos de ejecución de servicio
* [x] Permisos de servicio
* [x] %PATH% para ubicaciones de DLL secuestrables
* [x] Clave de registro AlwaysInstallElevated
* [x] Credenciales de autologon en el registro
* [x] Autoruns y configuraciones de registro modificables
* [x] Archivos/configuraciones de schtask modificables
* [x] Archivos de instalación sin supervisión
* [x] Cadenas web.config cifradas
* [x] Contraseñas de la aplicación de piscina y directorio virtual cifradas
* [x] Contraseñas en texto plano en McAfee SiteList.xml
* [x] Archivos .xml de Preferencias de Política de Grupo en caché
