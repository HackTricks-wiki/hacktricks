<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR a los repositorios [hacktricks](https://github.com/carlospolop/hacktricks) y [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan los valores importantes dentro de la memoria de un juego en ejecución y cambiarlos.\
Cuando lo descargas y ejecutas, se te presenta un tutorial de cómo usar la herramienta. Si quieres aprender a usar la herramienta, se recomienda encarecidamente completarlo.

# ¿Qué estás buscando?

![](<../../.gitbook/assets/image (580).png>)

Esta herramienta es muy útil para encontrar **dónde se almacena algún valor** (generalmente un número) **en la memoria** de un programa.\
**Generalmente los números** se almacenan en formato **4bytes**, pero también puedes encontrarlos en formatos **double** o **float**, o puede que quieras buscar algo **diferente a un número**. Por esa razón, debes asegurarte de **seleccionar** lo que quieres **buscar**:

![](<../../.gitbook/assets/image (581).png>)

También puedes indicar **diferentes tipos de búsquedas**:

![](<../../.gitbook/assets/image (582).png>)

También puedes marcar la casilla para **detener el juego mientras escanea la memoria**:

![](<../../.gitbook/assets/image (584).png>)

## Atajos de teclado

En _**Editar --> Configuración --> Atajos de teclado**_ puedes establecer diferentes **atajos de teclado** para diferentes propósitos, como **detener** el **juego** (lo cual es bastante útil si en algún momento quieres escanear la memoria). Hay otras opciones disponibles:

![](<../../.gitbook/assets/image (583).png>)

# Modificar el valor

Una vez que **encontraste** dónde está el **valor** que estás **buscando** (más sobre esto en los siguientes pasos), puedes **modificarlo** haciendo doble clic en él, luego haciendo doble clic en su valor:

![](<../../.gitbook/assets/image (585).png>)

Y finalmente **marcando la casilla** para que la modificación se realice en la memoria:

![](<../../.gitbook/assets/image (586).png>)

El **cambio** en la **memoria** se aplicará
