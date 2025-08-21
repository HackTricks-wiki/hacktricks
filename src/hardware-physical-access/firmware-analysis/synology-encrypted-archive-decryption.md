# Décryptage des archives cryptées PAT/SPK de Synology

{{#include ../../banners/hacktricks-training.md}}

## Aperçu

Plusieurs appareils Synology (DSM/BSM NAS, BeeStation, …) distribuent leur firmware et leurs packages d'application dans des **archives PAT / SPK cryptées**. Ces archives peuvent être décryptées *hors ligne* avec rien d'autre que les fichiers de téléchargement publics grâce à des clés codées en dur intégrées dans les bibliothèques d'extraction officielles.

Cette page documente, étape par étape, comment fonctionne le format crypté et comment récupérer complètement le **TAR** en texte clair qui se trouve à l'intérieur de chaque package. La procédure est basée sur des recherches de Synacktiv réalisées lors de Pwn2Own Ireland 2024 et implémentée dans l'outil open-source [`synodecrypt`](https://github.com/synacktiv/synodecrypt).

> ⚠️  Le format est exactement le même pour les archives `*.pat` (mise à jour système) et `*.spk` (application) – elles diffèrent seulement par la paire de clés codées en dur qui sont sélectionnées.

---

## 1. Récupérer l'archive

La mise à jour du firmware/de l'application peut normalement être téléchargée depuis le portail public de Synology :
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Dump the PAT structure (optionnel)

`*.pat` images sont eux-mêmes un **cpio bundle** qui intègre plusieurs fichiers (boot loader, kernel, rootfs, packages…). L'outil gratuit [`patology`](https://github.com/sud0woodo/patology) est pratique pour inspecter cet emballage :
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Pour `*.spk`, vous pouvez directement passer à l'étape 3.

## 3. Extraire les bibliothèques d'extraction Synology

La véritable logique de décryptage se trouve dans :

* `/usr/syno/sbin/synoarchive`               → wrapper CLI principal
* `/usr/lib/libsynopkg.so.1`                 → appelle le wrapper depuis l'interface DSM
* `libsynocodesign.so`                       → **contient l'implémentation cryptographique**

Les deux binaires sont présents dans le rootfs du système (`hda1.tgz`) **et** dans l'init-rd compressé (`rd.bin`). Si vous n'avez que le PAT, vous pouvez les obtenir de cette manière :
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Récupérer les clés codées en dur (`get_keys`)

À l'intérieur de `libsynocodesign.so`, la fonction `get_keys(int keytype)` retourne simplement deux variables globales de 128 bits pour la famille d'archives demandée :
```c
case 0:            // PAT (system)
case 10:
case 11:
signature_key = qword_23A40;
master_key    = qword_23A68;
break;

case 3:            // SPK (applications)
signature_key = qword_23AE0;
master_key    = qword_23B08;
break;
```
* **signature_key** → Clé publique Ed25519 utilisée pour vérifier l'en-tête de l'archive.
* **master_key**    → Clé racine utilisée pour dériver la clé de chiffrement par archive.

Vous devez uniquement extraire ces deux constantes une fois pour chaque version majeure de DSM.

## 5. Structure de l'en-tête & vérification de la signature

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` effectue les opérations suivantes :

1. Lire le magic (3 octets) `0xBFBAAD` **ou** `0xADBEEF`.
2. Lire `header_len` 32 bits en little-endian.
3. Lire `header_len` octets + la prochaine **signature Ed25519 de 0x40 octets**.
4. Itérer sur toutes les clés publiques intégrées jusqu'à ce que `crypto_sign_verify_detached()` réussisse.
5. Décoder l'en-tête avec **MessagePack**, produisant :
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` permet ensuite à libarchive de vérifier l'intégrité de chaque fichier au fur et à mesure qu'il est déchiffré.

## 6. Dériver la sous-clé par archive

À partir du blob `data` contenu dans l'en-tête MessagePack :

* `subkey_id`  = `uint64` en little-endian à l'offset 0x10
* `ctx`        = 7 octets à l'offset 0x18

La clé de **flux** de 32 octets est obtenue avec libsodium :
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Backend **libarchive** personnalisé de Synology

Synology regroupe une libarchive patchée qui enregistre un format "tar" fictif chaque fois que la magie est `0xADBEEF`:
```c
register_format(
"tar", spk_bid, spk_options,
spk_read_header, spk_read_data, spk_read_data_skip,
NULL, spk_cleanup, NULL, NULL);
```
### spk_read_header()
```
- Read 0x200 bytes
- nonce  = buf[0:0x18]
- cipher = buf[0x18:0x18+0x193]
- crypto_secretstream_xchacha20poly1305_init_pull(state, nonce, kdf_subkey)
- crypto_secretstream_xchacha20poly1305_pull(state, tar_hdr, …, cipher, 0x193)
```
L'`tar_hdr` déchiffré est un **en-tête TAR POSIX classique**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Chaque **nonce de 0x18 octets** est préfixé au morceau chiffré.

Une fois toutes les entrées traitées, libarchive produit un **`.tar`** parfaitement valide qui peut être décompressé avec n'importe quel outil standard.

## 8. Décryptez tout avec synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` détecte automatiquement PAT/SPK, charge les clés correctes et applique la chaîne complète décrite ci-dessus.

## 9. Pièges courants

* Ne **swappez pas** `signature_key` et `master_key` – ils ont des objectifs différents.
* Le **nonce** vient *avant* le texte chiffré pour chaque bloc (en-tête et données).
* La taille maximale du morceau chiffré est **0x400000 + 0x11** (tag libsodium).
* Les archives créées pour une génération de DSM peuvent passer à des clés codées en dur différentes dans la prochaine version.

## 10. Outils supplémentaires

* [`patology`](https://github.com/sud0woodo/patology) – analyser/dumper les archives PAT.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – déchiffrer PAT/SPK/autres.
* [`libsodium`](https://github.com/jedisct1/libsodium) – implémentation de référence de XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – sérialisation d'en-tête.

## Références

- [Extraction des archives chiffrées Synology – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt sur GitHub](https://github.com/synacktiv/synodecrypt)
- [patology sur GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
