# Ataques Físicos

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Contraseña del BIOS

### La batería

La mayoría de las **placas base** tienen una **batería**. Si la **retiras** durante **30min**, la configuración del BIOS se **reiniciará** (incluida la contraseña).

### Jumper CMOS

La mayoría de las **placas base** tienen un **jumper** que puede reiniciar la configuración. Este jumper conecta un pin central con otro, si **conectas esos pines la placa base se reiniciará**.

### Herramientas en Vivo

Si pudieras **ejecutar**, por ejemplo, un Linux **Kali** desde un CD/USB en Vivo, podrías usar herramientas como _**killCmos**_ o _**CmosPWD**_ (este último está incluido en Kali) para intentar **recuperar la contraseña del BIOS**.

### Recuperación de contraseña del BIOS en línea

Introduce la contraseña del BIOS **3 veces incorrectamente**, luego el BIOS **mostrará un mensaje de error** y se bloqueará.\
Visita la página [https://bios-pw.org](https://bios-pw.org) e **introduce el código de error** mostrado por el BIOS y podrías tener suerte y obtener una **contraseña válida** (la **misma búsqueda podría mostrarte diferentes contraseñas y más de una podría ser válida**).

## UEFI

Para verificar la configuración del UEFI y realizar algún tipo de ataque, deberías probar [chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf).\
Usando esta herramienta podrías desactivar fácilmente el Secure Boot:
```
python chipsec_main.py -module exploits.secure.boot.pk
```
## RAM

### Cold boot

La **memoria RAM es persistente de 1 a 2 minutos** desde que se apaga el ordenador. Si aplicas **frío** (nitrógeno líquido, por ejemplo) en la tarjeta de memoria puedes extender este tiempo hasta **10 minutos**.

Luego, puedes realizar un **volcado de memoria** (usando herramientas como dd.exe, mdd.exe, Memoryze, win32dd.exe o DumpIt) para analizar la memoria.

Debes **analizar** la memoria **usando volatility**.

### [INCEPTION](https://github.com/carmaa/inception)

Inception es una herramienta de **manipulación de memoria física** y hacking que explota DMA basado en PCI. La herramienta puede atacar a través de **FireWire**, **Thunderbolt**, **ExpressCard**, PC Card y cualquier otra interfaz HW PCI/PCIe.\
**Conecta** tu ordenador al ordenador víctima a través de una de esas **interfaces** y **INCEPTION** intentará **parchear** la **memoria física** para darte **acceso**.

**Si INCEPTION tiene éxito, cualquier contraseña introducida será válida.**

**No funciona con Windows10.**

## Live CD/USB

### Sticky Keys y más

* **SETHC:** _sethc.exe_ se invoca cuando se presiona SHIFT 5 veces
* **UTILMAN:** _Utilman.exe_ se invoca al presionar WINDOWS+U
* **OSK:** _osk.exe_ se invoca al presionar WINDOWS+U, luego lanzando el teclado en pantalla
* **DISP:** _DisplaySwitch.exe_ se invoca al presionar WINDOWS+P

Estos binarios se encuentran dentro de _**C:\Windows\System32**_. Puedes **cambiar** cualquiera de ellos por una **copia** del binario **cmd.exe** (también en la misma carpeta) y cada vez que invoques cualquiera de esos binarios aparecerá una línea de comandos como **SYSTEM**.

### Modificando SAM

Puedes usar la herramienta _**chntpw**_ para **modificar el** _**archivo SAM**_ de un sistema de archivos Windows montado. Entonces, podrías cambiar la contraseña del usuario Administrador, por ejemplo.\
Esta herramienta está disponible en KALI.
```
chntpw -h
chntpw -l <path_to_SAM>
```
**Dentro de un sistema Linux podrías modificar el archivo** _**/etc/shadow**_ **o** _**/etc/passwd**_.

### **Kon-Boot**

**Kon-Boot** es una de las mejores herramientas que existen para iniciar sesión en Windows sin conocer la contraseña. Funciona **interceptando el BIOS del sistema y cambiando temporalmente el contenido del kernel de Windows** durante el arranque (las nuevas versiones también funcionan con **UEFI**). Luego te permite ingresar **cualquier cosa como contraseña** durante el inicio de sesión. La próxima vez que inicies el ordenador sin Kon-Boot, la contraseña original volverá, los cambios temporales se descartarán y el sistema se comportará como si nada hubiera sucedido.\
Más información: [https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)

Es un CD/USB en vivo que puede **parchear la memoria** para que **no necesites conocer la contraseña para iniciar sesión**.\
Kon-Boot también realiza el truco de **StickyKeys** para que puedas presionar _**Shift**_ **5 veces y obtener una cmd de Administrador**.

## **Ejecutando Windows**

### Atajos iniciales

### Atajos de arranque

* supr - BIOS
* f8 - Modo de recuperación
* _supr_ - BIOS ini
* _f8_ - Modo de recuperación
* _Shift_ (después del banner de windows) - Ir a la página de inicio de sesión en lugar de autologon (evitar autologon)

### **BAD USBs**

#### **Tutoriales de Rubber Ducky**

* [Tutorial 1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
* [Tutorial 2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

* [Cargas útiles y tutoriales](https://github.com/Screetsec/Pateensy)

También hay toneladas de tutoriales sobre **cómo crear tu propio bad USB**.

### Copia de sombra de volumen

Con privilegios de administrador y powershell podrías hacer una copia del archivo SAM.[ Ver este código](../windows-hardening/basic-powershell-for-pentesters/#volume-shadow-copy).

## Eludir Bitlocker

Bitlocker utiliza **2 contraseñas**. La que usa el **usuario** y la contraseña de **recuperación** (48 dígitos).

Si tienes suerte y dentro de la sesión actual de Windows existe el archivo _**C:\Windows\MEMORY.DMP**_ (Es un volcado de memoria) podrías intentar **buscar dentro de él la contraseña de recuperación**. Puedes **obtener este archivo** y una **copia del sistema de archivos** y luego usar _Elcomsoft Forensic Disk Decryptor_ para obtener el contenido (esto solo funcionará si la contraseña está dentro del volcado de memoria). También podrías **forzar el volcado de memoria** usando _**NotMyFault**_ de _Sysinternals,_ pero esto reiniciará el sistema y debe ser ejecutado como Administrador.

También podrías intentar un **ataque de fuerza bruta** usando _**Passware Kit Forensic**_.

### Ingeniería Social

Finalmente, podrías hacer que el usuario agregue una nueva contraseña de recuperación haciéndole ejecutar como administrador:
```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```
Esto agregará una nueva clave de recuperación (compuesta de 48 ceros) en el próximo inicio de sesión.

Para verificar las claves de recuperación válidas puedes ejecutar:
```
manage-bde -protectors -get c:
```
<details>

<summary><strong>Aprende a hackear AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue**me en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
