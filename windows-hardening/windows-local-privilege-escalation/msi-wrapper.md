# Envoltorio MSI

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Descarga la aplicación gratuita desde [https://www.exemsi.com/documentation/getting-started/](https://www.exemsi.com/download/), ejecútala y envuelve el binario "malicioso" en ella.\
Ten en cuenta que puedes envolver un archivo "**.bat**" si solo quieres ejecutar líneas de comando (en lugar de cmd.exe, selecciona el archivo .bat)

![](<../../.gitbook/assets/image (304) (1).png>)

Y esta es la parte más importante de la configuración:

![](<../../.gitbook/assets/image (305).png>)

![](<../../.gitbook/assets/image (308).png>)

![](<../../.gitbook/assets/image (310).png>)

(Ten en cuenta que si intentas empaquetar tu propio binario, podrás modificar estos valores)

A partir de aquí, simplemente haz clic en los botones **siguiente** y el último botón **compilar** y se generará tu instalador/envoltorio.
