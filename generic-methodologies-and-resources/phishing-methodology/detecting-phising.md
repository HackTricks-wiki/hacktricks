# Detectando Phishing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com).

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introducción

Para detectar un intento de phishing es importante **entender las técnicas de phishing que se están utilizando hoy en día**. En la página principal de esta publicación, puedes encontrar esta información, así que si no estás al tanto de las técnicas que se están utilizando hoy en día, te recomiendo que vayas a la página principal y leas al menos esa sección.

Esta publicación se basa en la idea de que los **atacantes intentarán de alguna manera imitar o usar el nombre de dominio de la víctima**. Si tu dominio se llama `ejemplo.com` y te hacen phishing usando un nombre de dominio completamente diferente por alguna razón, como `hasganadoelloteria.com`, estas técnicas no lo descubrirán.

## Variaciones de nombres de dominio

Es bastante **fácil** descubrir aquellos intentos de **phishing** que utilizarán un **nombre de dominio similar** dentro del correo electrónico.\
Es suficiente con **generar una lista de los nombres de phishing más probables** que un atacante puede usar y **comprobar** si está **registrado** o simplemente comprobar si hay alguna **IP** usándolo.

### Encontrando dominios sospechosos

Para este propósito, puedes usar cualquiera de las siguientes herramientas. Ten en cuenta que estas herramientas también realizarán solicitudes DNS automáticamente para comprobar si el dominio tiene alguna IP asignada:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

En el mundo de la informática, todo se almacena en bits (ceros y unos) en la memoria detrás de escena.\
Esto también se aplica a los dominios. Por ejemplo, _windows.com_ se convierte en _01110111..._ en la memoria volátil de tu dispositivo informático.\
Sin embargo, ¿qué pasa si uno de estos bits se invierte automáticamente debido a una llamarada solar, rayos cósmicos o un error de hardware? Es decir, uno de los 0 se convierte en 1 y viceversa.\
Aplicando este concepto a las solicitudes DNS, es posible que el **dominio solicitado** que llega al servidor DNS **no sea el mismo que el dominio solicitado inicialmente**.

Por ejemplo, una modificación de 1 bit en el dominio microsoft.com puede transformarlo en _windnws.com._\
**Los atacantes pueden registrar tantos dominios de bit-flipping como sea posible relacionados con la víctima para redirigir a los usuarios legítimos a su infraestructura**.

Para obtener más información, lee [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

**Todos los posibles nombres de dominio de bit-flipping también deben ser monitoreados.**

### Comprobaciones básicas

Una vez que tengas una lista de posibles nombres de dominio sospechosos, debes **comprobarlos** (principalmente los puertos HTTP y HTTPS) para **ver si están usando algún formulario de inicio de sesión similar** a alguien del dominio de la víctima.\
También podrías comprobar el puerto 3333 para ver si está abierto y ejecutando una instancia de `gophish`.\
También es interesante saber **cuánto tiempo tiene cada dominio sospechoso descubierto**, cuanto más joven sea, más riesgoso será.\
También puedes obtener **capturas de pantalla** de la página web HTTP y/o HTTPS sospechosa para ver si es sospechosa y en ese caso **acceder a ella para profundizar**.

### Comprobaciones avanzadas

Si quieres ir un paso más allá, te recomendaría **monitorear esos dominios sospechosos y buscar más** de vez en cuando (¿todos los días? solo toma unos segundos/minutos). También debes **comprobar** los **puertos** abiertos de las IPs relacionadas y **buscar instancias de `gophish
