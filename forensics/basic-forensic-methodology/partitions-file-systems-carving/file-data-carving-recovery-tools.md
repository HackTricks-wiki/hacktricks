<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/metodologia-pentesting"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Herramientas de recuperación y tallado

Más herramientas en [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

La herramienta más comúnmente utilizada en forense para extraer archivos de imágenes es [**Autopsy**](https://www.autopsy.com/download/). Descárguela, instálela y haga que ingiera el archivo para encontrar archivos "ocultos". Tenga en cuenta que Autopsy está diseñado para admitir imágenes de disco y otros tipos de imágenes, pero no archivos simples.

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** es una herramienta para buscar archivos binarios como imágenes y archivos de audio para encontrar archivos y datos incrustados.\
Se puede instalar con `apt`, sin embargo, la [fuente](https://github.com/ReFirmLabs/binwalk) se puede encontrar en github.\
**Comandos útiles**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Otra herramienta común para encontrar archivos ocultos es **foremost**. Puedes encontrar el archivo de configuración de foremost en `/etc/foremost.conf`. Si solo quieres buscar algunos archivos específicos, descoméntalos. Si no descomentas nada, foremost buscará los tipos de archivo configurados por defecto.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** es otra herramienta que se puede utilizar para encontrar y extraer **archivos incrustados en un archivo**. En este caso, deberá descomentar del archivo de configuración (_/etc/scalpel/scalpel.conf_) los tipos de archivo que desea extraer.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Esta herramienta viene incluida en Kali, pero también se puede encontrar aquí: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Esta herramienta puede escanear una imagen y **extraer pcaps**, **información de red (URLs, dominios, IPs, MACs, correos electrónicos)** y más **archivos**. Solo tienes que hacer:
```
bulk_extractor memory.img -o out_folder
```
Navegue a través de **toda la información** que la herramienta ha recopilado (¿contraseñas?), **analice** los **paquetes** (lea [**Análisis de Pcaps**](../pcap-inspection/)), busque **dominios extraños** (dominios relacionados con **malware** o **no existentes**).

## PhotoRec

Puede encontrarlo en [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Viene con versiones GUI y CLI. Puede seleccionar los **tipos de archivo** que desea que PhotoRec busque.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

Consulte el [código](https://code.google.com/archive/p/binvis/) y la [herramienta de página web](https://binvis.io/#/).

### Características de BinVis

* Visor de **estructura visual y activa**
* Múltiples gráficos para diferentes puntos de enfoque
* Enfocándose en porciones de una muestra
* **Viendo cadenas y recursos**, en ejecutables PE o ELF, por ejemplo.
* Obteniendo **patrones** para criptoanálisis en archivos
* **Detectando** algoritmos de empaquetado o codificación
* **Identificar** la esteganografía por patrones
* **Visual** binary-diffing

BinVis es un gran **punto de partida para familiarizarse con un objetivo desconocido** en un escenario de caja negra.

# Herramientas específicas de recuperación de datos

## FindAES

Busca claves AES buscando sus horarios de claves. Capaz de encontrar claves de 128, 192 y 256 bits, como las utilizadas por TrueCrypt y BitLocker.

Descargar [aquí](https://sourceforge.net/projects/findaes/).

# Herramientas complementarias

Puede usar [**viu** ](https://github.com/atanunq/viu)para ver imágenes desde la terminal.\
Puede usar la herramienta de línea de comandos de Linux **pdftotext** para transformar un pdf en texto y leerlo.


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparta sus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
