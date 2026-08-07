# Déchiffrement des archives chiffrées PAT/SPK de Synology

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble

Plusieurs appareils Synology (NAS DSM/BSM, BeeStation, …) distribuent leur firmware et leurs packages d’application dans des **archives PAT / SPK chiffrées**. Ces archives peuvent être déchiffrées *offline* avec rien d’autre que les fichiers de téléchargement publics, grâce aux clés codées en dur intégrées aux bibliothèques officielles d’extraction.

Cette page décrit, étape par étape, le fonctionnement du format chiffré et la manière de récupérer entièrement le **TAR** en clair contenu dans chaque package. La procédure est basée sur les recherches de Synacktiv réalisées lors de Pwn2Own Ireland 2024 et implémentées dans l’outil open source [`synodecrypt`](https://github.com/synacktiv/synodecrypt).<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  Le format est exactement le même pour les archives `*.pat` (mise à jour système) et `*.spk` (application) : seule la paire de clés codées en dur sélectionnée diffère.

---

## 1. Télécharger l’archive

La mise à jour du firmware/de l’application peut normalement être téléchargée depuis le portail public de Synology :
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Extraire la structure PAT (optionnel)

Les images `*.pat` sont elles-mêmes un **bundle cpio** qui intègre plusieurs fichiers (chargeur de démarrage, kernel, rootfs, packages…). L’utilitaire gratuit [`patology`](https://github.com/sud0woodo/patology) est pratique pour inspecter cette enveloppe :<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Pour les fichiers `*.spk`, vous pouvez passer directement à l’étape 3.

## 3. Extraire les libraries d’extraction de Synology

La véritable logique de décryption se trouve dans :

* `/usr/syno/sbin/synoarchive`               → wrapper CLI principal
* `/usr/lib/libsynopkg.so.1`                 → appelle le wrapper depuis l’interface DSM
* `libsynocodesign.so`                       → **contient l’implémentation cryptographique**

Les deux binaries sont présents dans le system rootfs (`hda1.tgz`) **ainsi que** dans l’init-rd compressé (`rd.bin`). Si vous disposez uniquement du PAT, vous pouvez les obtenir de cette manière :
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Récupérer les clés codées en dur (`get_keys`)

Dans `libsynocodesign.so`, la fonction `get_keys(int keytype)` retourne simplement deux variables globales de 128 bits pour la famille d’archives demandée :<sup>[[1]](#references)</sup>
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
* **signature_key** → clé publique Ed25519 utilisée pour vérifier l’en-tête de l’archive.
* **master_key**    → clé racine utilisée pour dériver la clé de chiffrement propre à chaque archive.

Vous devez vider ces deux constantes une seule fois pour chaque version majeure de DSM.

## 5. Structure de l’en-tête et vérification de la signature

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` effectue les opérations suivantes :<sup>[[1]](#references)</sup>

1. Lire le magic (3 octets) `0xBFBAAD` **ou** `0xADBEEF`.
2. Lire `header_len` sur 32 bits en little-endian.
3. Lire `header_len` octets + la **signature Ed25519 de 0x40 octets** suivante.
4. Parcourir toutes les clés publiques intégrées jusqu’à ce que `crypto_sign_verify_detached()` réussisse.
5. Décoder l’en-tête avec **MessagePack**, ce qui produit :
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` permet ensuite à libarchive de vérifier l'intégrité de chaque fichier au fur et à mesure de son déchiffrement.

## 6. Dériver la sous-clé par archive

À partir du blob `data` contenu dans l'en-tête MessagePack :

* `subkey_id`  = `uint64` little-endian à l'offset 0x10
* `ctx`        = 7 octets à l'offset 0x18

La **clé de flux** de 32 octets est obtenue avec libsodium :
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Backend **libarchive** personnalisé de Synology

Synology intègre une version corrigée de libarchive qui enregistre un faux format « tar » lorsque le magic est `0xADBEEF` :<sup>[[1]](#references)</sup>
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
Le `tar_hdr` déchiffré est un **en-tête TAR POSIX classique**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Chaque **nonce de 0x18 octet** est placé avant le chunk chiffré.

Une fois toutes les entrées traitées, libarchive produit un **`.tar`** parfaitement valide qui peut être décompressé avec n’importe quel outil standard.

## 8. Tout déchiffrer avec synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` détecte automatiquement PAT/SPK, charge les clés correctes et applique la chaîne complète décrite ci-dessus.<sup>[[2]](#references)</sup>

## 9. Pièges courants

* Ne permutez **pas** `signature_key` et `master_key` : elles ont des fonctions différentes.
* Le **nonce** se trouve *avant* le ciphertext pour chaque bloc (header et data).
* La taille maximale d’un chunk chiffré est **0x400000 + 0x11** (tag libsodium).
* Les archives créées pour une génération de DSM peuvent utiliser d’autres clés hard-coded dans la release suivante.

## 10. Outils supplémentaires

* [`patology`](https://github.com/sud0woodo/patology) – parse/dump des archives PAT.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – déchiffrement de PAT/SPK/autres formats.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – implémentation de référence de XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – sérialisation du header.

## Références

- [1] [Extraction des archives chiffrées Synology – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt sur GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology sur GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
