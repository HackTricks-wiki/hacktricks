# Ataques Físicos

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) es un motor de búsqueda alimentado por la **dark web** que ofrece funcionalidades **gratuitas** para verificar si una empresa o sus clientes han sido **comprometidos** por **malwares roba información**.

El objetivo principal de WhiteIntel es combatir los secuestros de cuentas y los ataques de ransomware resultantes de malwares que roban información.

Puedes visitar su sitio web y probar su motor de búsqueda de forma **gratuita** en:

{% embed url="https://whiteintel.io" %}

---

## Recuperación de Contraseña de BIOS y Seguridad del Sistema

**Restablecer la BIOS** se puede lograr de varias formas. La mayoría de las placas base incluyen una **batería** que, al retirarse durante unos **30 minutos**, restablecerá los ajustes de la BIOS, incluida la contraseña. Alternativamente, se puede ajustar un **puente en la placa base** para restablecer estos ajustes conectando pines específicos.

Para situaciones donde los ajustes de hardware no son posibles o prácticos, las **herramientas de software** ofrecen una solución. Ejecutar un sistema desde un **Live CD/USB** con distribuciones como **Kali Linux** proporciona acceso a herramientas como **_killCmos_** y **_CmosPWD_**, que pueden ayudar en la recuperación de la contraseña de la BIOS.

En casos donde la contraseña de la BIOS es desconocida, al ingresarla incorrectamente **tres veces** generalmente resultará en un código de error. Este código se puede utilizar en sitios web como [https://bios-pw.org](https://bios-pw.org) para posiblemente recuperar una contraseña utilizable.

### Seguridad UEFI

Para sistemas modernos que utilizan **UEFI** en lugar de la BIOS tradicional, la herramienta **chipsec** se puede utilizar para analizar y modificar los ajustes de UEFI, incluida la desactivación del **Secure Boot**. Esto se puede lograr con el siguiente comando:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Análisis de RAM y Ataques de Arranque en Frío

La RAM retiene datos brevemente después de que se corta la energía, generalmente durante **1 a 2 minutos**. Esta persistencia se puede extender a **10 minutos** aplicando sustancias frías, como nitrógeno líquido. Durante este período extendido, se puede crear un **volcado de memoria** utilizando herramientas como **dd.exe** y **volatility** para su análisis.

### Ataques de Acceso Directo a la Memoria (DMA)

**INCEPTION** es una herramienta diseñada para la **manipulación física de la memoria** a través de DMA, compatible con interfaces como **FireWire** y **Thunderbolt**. Permite eludir los procedimientos de inicio de sesión parcheando la memoria para aceptar cualquier contraseña. Sin embargo, es ineficaz contra sistemas **Windows 10**.

### Live CD/USB para Acceso al Sistema

Cambiar binarios del sistema como **_sethc.exe_** o **_Utilman.exe_** con una copia de **_cmd.exe_** puede proporcionar un símbolo del sistema con privilegios del sistema. Se pueden utilizar herramientas como **chntpw** para editar el archivo **SAM** de una instalación de Windows, permitiendo cambios de contraseña.

**Kon-Boot** es una herramienta que facilita el inicio de sesión en sistemas Windows sin conocer la contraseña al modificar temporalmente el kernel de Windows o UEFI. Se puede encontrar más información en [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Manejo de Funciones de Seguridad de Windows

#### Accesos Directos de Arranque y Recuperación

- **Supr**: Acceder a los ajustes de la BIOS.
- **F8**: Entrar en el modo de recuperación.
- Presionar **Shift** después del banner de Windows puede omitir el inicio de sesión automático.

#### Dispositivos BAD USB

Dispositivos como **Rubber Ducky** y **Teensyduino** sirven como plataformas para crear dispositivos **bad USB**, capaces de ejecutar cargas útiles predefinidas al conectarse a un ordenador objetivo.

#### Copia de Sombra de Volumen

Los privilegios de administrador permiten la creación de copias de archivos sensibles, incluido el archivo **SAM**, a través de PowerShell.

### Eludir el Cifrado BitLocker

El cifrado BitLocker potencialmente se puede eludir si se encuentra la **contraseña de recuperación** dentro de un archivo de volcado de memoria (**MEMORY.DMP**). Se pueden utilizar herramientas como **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic** con este propósito.

### Ingeniería Social para Agregar una Clave de Recuperación

Se puede agregar una nueva clave de recuperación de BitLocker a través de tácticas de ingeniería social, convenciendo a un usuario para que ejecute un comando que agregue una nueva clave de recuperación compuesta por ceros, simplificando así el proceso de descifrado.
