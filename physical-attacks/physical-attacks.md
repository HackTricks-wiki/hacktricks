# Ataques Físicos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Contraseña de BIOS

### La batería

La mayoría de las **placas base** tienen una **batería**. Si la **retiras** durante **30 minutos**, los ajustes de la BIOS se **restablecerán** (incluida la contraseña).

### Jumper CMOS

La mayoría de las **placas base** tienen un **jumper** que puede restablecer los ajustes. Este jumper conecta un pin central con otro, si **conectas esos pines, la placa base se reiniciará**.

### Herramientas en vivo

Si pudieras **ejecutar**, por ejemplo, un **Kali** Linux desde un CD/USB en vivo, podrías usar herramientas como _**killCmos**_ o _**CmosPWD**_ (este último está incluido en Kali) para intentar **recuperar la contraseña de la BIOS**.

### Recuperación de contraseña de BIOS en línea

Introduce la contraseña de la BIOS **3 veces incorrectamente**, luego la BIOS mostrará un **mensaje de error** y se bloqueará.\
Visita la página [https://bios-pw.org](https://bios-pw.org) e **introduce el código de error** mostrado por la BIOS y podrías tener suerte y obtener una **contraseña válida** (la **misma búsqueda podría mostrarte contraseñas diferentes y más de una podría ser válida**).

## UEFI

Para verificar los ajustes de UEFI y realizar algún tipo de ataque, debes probar [chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf).\
Usando esta herramienta, puedes desactivar fácilmente el Secure Boot:
```
python chipsec_main.py -module exploits.secure.boot.pk
```
## RAM

### Cold boot

La memoria **RAM es persistente de 1 a 2 minutos** desde que se apaga la computadora. Si aplicas **frío** (nitrógeno líquido, por ejemplo) en la tarjeta de memoria, puedes extender este tiempo hasta **10 minutos**.

Luego, puedes hacer un **volcado de memoria** (usando herramientas como dd.exe, mdd.exe, Memoryze, win32dd.exe o DumpIt) para analizar la memoria.

Debes **analizar** la memoria **usando volatility**.

### [INCEPTION](https://github.com/carmaa/inception)

Inception es una herramienta de **manipulación de memoria física** y hacking que explota DMA basado en PCI. La herramienta puede atacar a través de **FireWire**, **Thunderbolt**, **ExpressCard**, PC Card y cualquier otra interfaz de hardware PCI/PCIe.\
**Conecta** tu computadora a la computadora víctima a través de una de esas **interfaces** y **INCEPTION** intentará **modificar** la **memoria física** para darte **acceso**.

**Si INCEPTION tiene éxito, cualquier contraseña introducida será válida.**

**No funciona con Windows10.**

## Live CD/USB

### Sticky Keys y más

* **SETHC:** _sethc.exe_ se invoca cuando se presiona SHIFT 5 veces
* **UTILMAN:** _Utilman.exe_ se invoca al presionar WINDOWS+U
* **OSK:** _osk.exe_ se invoca al presionar WINDOWS+U, luego se lanza el teclado en pantalla
* **DISP:** _DisplaySwitch.exe_ se invoca al presionar WINDOWS+P

Estos binarios se encuentran dentro de _**C:\Windows\System32**_. Puedes **cambiar** cualquiera de ellos por una **copia** del binario **cmd.exe** (también en la misma carpeta) y cada vez que invoques alguno de esos binarios, aparecerá un símbolo del sistema como **SYSTEM**.

### Modificando SAM

Puedes usar la herramienta _**chntpw**_ para **modificar el archivo** _**SAM**_ de un sistema de archivos de Windows montado. Luego, podrías cambiar la contraseña del usuario Administrador, por ejemplo.\
Esta herramienta está disponible en KALI.
```
chntpw -h
chntpw -l <path_to_SAM>
```
**Dentro de un sistema Linux, podrías modificar el archivo** _**/etc/shadow**_ **o** _**/etc/passwd**_.

### **Kon-Boot**

**Kon-Boot** es una de las mejores herramientas disponibles que puede iniciar sesión en Windows sin conocer la contraseña. Funciona **interfiriendo en la BIOS del sistema y cambiando temporalmente el contenido del kernel de Windows** durante el arranque (las nuevas versiones también funcionan con **UEFI**). Luego te permite ingresar **cualquier cosa como contraseña** durante el inicio de sesión. La próxima vez que inicies la computadora sin Kon-Boot, la contraseña original volverá, los cambios temporales se descartarán y el sistema se comportará como si nada hubiera sucedido.\
Leer más: [https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)

Es un CD/USB en vivo que puede **modificar la memoria** para que **no necesites conocer la contraseña para iniciar sesión**.\
Kon-Boot también realiza el truco de **StickyKeys** para que puedas presionar _**Shift**_ **5 veces y obtener un cmd de Administrador**.

## **Ejecutando Windows**

### Atajos iniciales

### Atajos de arranque

* supr - BIOS
* f8 - Modo de recuperación
* _supr_ - BIOS ini
* _f8_ - Modo de recuperación
* _Shitf_ (después del banner de Windows) - Ir a la página de inicio de sesión en lugar de autologon (evitar autologon)

### **USBs maliciosos**

#### **Tutoriales de Rubber Ducky**

* [Tutorial 1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
* [Tutorial 2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

* [Cargas útiles y tutoriales](https://github.com/Screetsec/Pateensy)

También hay toneladas de tutoriales sobre **cómo crear tu propio USB malicioso**.

### Copia de sombra de volumen

Con privilegios de administrador y PowerShell, puedes hacer una copia del archivo SAM. [Ver este código](../windows-hardening/basic-powershell-for-pentesters/#volume-shadow-copy).

## Saltarse Bitlocker

Bitlocker utiliza **2 contraseñas**. La que utiliza el **usuario** y la contraseña de **recuperación** (48 dígitos).

Si tienes suerte y dentro de la sesión actual de Windows existe el archivo _**C:\Windows\MEMORY.DMP**_ (es un volcado de memoria), puedes intentar **buscar dentro de él la contraseña de recuperación**. Puedes **obtener este archivo** y una **copia del sistema de archivos** y luego usar _Elcomsoft Forensic Disk Decryptor_ para obtener el contenido (esto solo funcionará si la contraseña está dentro del volcado de memoria). También puedes **forzar el volcado de memoria** utilizando _**NotMyFault**_ de _Sysinternals_, pero esto reiniciará el sistema y debe ejecutarse como administrador.

También puedes intentar un **ataque de fuerza bruta** utilizando _**Passware Kit Forensic**_.

### Ingeniería social

Finalmente, puedes hacer que el usuario agregue una nueva contraseña de recuperación haciéndolo ejecutar como administrador:
```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```
Esto agregará una nueva clave de recuperación (compuesta por 48 ceros) en el próximo inicio de sesión.

Para verificar las claves de recuperación válidas, puedes ejecutar:
```
manage-bde -protectors -get c:
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
