# Protecciones de seguridad en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Gatekeeper

Gatekeeper se utiliza generalmente para referirse a la combinación de **Quarantine + Gatekeeper + XProtect**, 3 módulos de seguridad de macOS que intentarán **evitar que los usuarios ejecuten software potencialmente malicioso descargado**.

Más información en:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## MRT - Herramienta de eliminación de malware

La Herramienta de eliminación de malware (MRT) es otra parte de la infraestructura de seguridad de macOS. Como su nombre indica, la función principal de MRT es **eliminar malware conocido de sistemas infectados**.

Una vez que se detecta malware en un Mac (ya sea por XProtect o por otros medios), se puede utilizar MRT para **eliminar automáticamente el malware**. MRT funciona en segundo plano de forma silenciosa y se ejecuta normalmente cuando se actualiza el sistema o se descarga una nueva definición de malware (parece que las reglas que MRT utiliza para detectar malware están dentro del binario).

Si bien tanto XProtect como MRT forman parte de las medidas de seguridad de macOS, realizan funciones diferentes:

* **XProtect** es una herramienta preventiva. **Comprueba los archivos a medida que se descargan** (a través de ciertas aplicaciones) y, si detecta algún tipo de malware conocido, **impide que el archivo se abra**, evitando así que el malware infecte el sistema en primer lugar.
* **MRT**, por otro lado, es una herramienta **reactiva**. Opera después de que se haya detectado malware en un sistema, con el objetivo de eliminar el software ofensivo para limpiar el sistema.

La aplicación MRT se encuentra en **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Limitaciones de procesos

### SIP - Protección de la integridad del sistema

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

La Sandbox de macOS **limita las aplicaciones** que se ejecutan dentro de la sandbox a las **acciones permitidas especificadas en el perfil de la Sandbox** con el que se ejecuta la aplicación. Esto ayuda a garantizar que **la aplicación solo acceda a los recursos esperados**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparencia, Consentimiento y Control**

**TCC (Transparencia, Consentimiento y Control)** es un mecanismo en macOS para **limitar y controlar el acceso de las aplicaciones a ciertas funciones**, generalmente desde una perspectiva de privacidad. Esto puede incluir cosas como servicios de ubicación, contactos, fotos, micrófono, cámara, accesibilidad, acceso completo al disco y muchas más.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

## Caché de confianza

La caché de confianza de Apple macOS, a veces también conocida como caché AMFI (Apple Mobile File Integrity), es un mecanismo de seguridad en macOS diseñado para **evitar que se ejecute software no autorizado o malicioso**. Esencialmente, es una lista de hashes criptográficos que el sistema operativo utiliza para **verificar la integridad y autenticidad del software**.

Cuando una aplicación o archivo ejecutable intenta ejecutarse en macOS, el sistema operativo verifica la caché de confianza de AMFI. Si se encuentra el **hash del archivo en la caché de confianza**, el sistema **permite** que el programa se ejecute porque lo reconoce como confiable.

## Restricciones de lanzamiento

Controla desde dónde y qué puede lanzar un binario firmado por Apple:

* No se puede lanzar una aplicación directamente si debe ser ejecutada por launchd.
* No se puede ejecutar una aplicación fuera de la ubicación de confianza (como /System/).
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
