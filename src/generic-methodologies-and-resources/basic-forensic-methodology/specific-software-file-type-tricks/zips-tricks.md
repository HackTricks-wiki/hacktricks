# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Outils en ligne de commande** pour gérer les **fichiers zip** sont essentiels pour diagnostiquer, réparer et cracker des fichiers zip. Voici quelques utilitaires clés :

- **`unzip`** : Révèle pourquoi un fichier zip peut ne pas se décompresser.
- **`zipdetails -v`** : Offre une analyse détaillée des champs de format de fichier zip.
- **`zipinfo`** : Liste le contenu d'un fichier zip sans les extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`** : Essaye de réparer des fichiers zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)** : Un outil pour le cracking par force brute des mots de passe zip, efficace pour les mots de passe jusqu'à environ 7 caractères.

La [spécification du format de fichier Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des détails complets sur la structure et les normes des fichiers zip.

Il est crucial de noter que les fichiers zip protégés par mot de passe **ne cryptent pas les noms de fichiers ou les tailles de fichiers** à l'intérieur, un défaut de sécurité non partagé avec les fichiers RAR ou 7z qui cryptent ces informations. De plus, les fichiers zip cryptés avec l'ancienne méthode ZipCrypto sont vulnérables à une **attaque par texte en clair** si une copie non cryptée d'un fichier compressé est disponible. Cette attaque exploite le contenu connu pour cracker le mot de passe du zip, une vulnérabilité détaillée dans [l'article de HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) et expliquée plus en détail dans [ce document académique](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Cependant, les fichiers zip sécurisés avec le cryptage **AES-256** sont immunisés contre cette attaque par texte en clair, montrant l'importance de choisir des méthodes de cryptage sécurisées pour les données sensibles.

## Références

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}
