# Stockage cloud local

## OneDrive

Dans Windows, vous pouvez trouver le dossier OneDrive dans `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Et dans `logs\Personal`, il est possible de trouver le fichier `SyncDiagnostics.log`, qui contient des données intéressantes concernant les fichiers synchronisés :<sup>[[3]](#references)</sup>

- Taille en octets
- Date de création
- Date de modification
- Nombre de fichiers dans le cloud
- Nombre de fichiers dans le dossier
- **CID** : identifiant unique de l'utilisateur OneDrive
- Heure de génération du rapport
- Taille du disque dur du système d'exploitation

Une fois le CID trouvé, il est recommandé de **rechercher les fichiers contenant cet identifiant**. Vous pourrez peut-être trouver des fichiers nommés : _**\<CID>.ini**_ et _**\<CID>.dat**_, qui peuvent contenir des informations intéressantes, comme les noms des fichiers synchronisés avec OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

Dans Windows, vous pouvez trouver le dossier principal de Google Drive dans `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ce dossier contient un fichier appelé Sync_log.log, qui enregistre les sessions de synchronisation du client Google Drive ainsi que les événements de création, de modification et de suppression de fichiers.<sup>[[4]](#references)[[6]](#references)</sup>

Le fichier **`Cloud_graph\Cloud_graph.db`** est une base de données sqlite.<sup>[[6]](#references)</sup> Elle contient la table **`cloud_graph_entry`**. Dans cette table, vous pouvez trouver le **nom** des **fichiers** **synchronisés**, leur date de modification, leur taille et leur checksum MD5.

La table **`cloud_entry`** de la base de données associée **`snapshot.db`** peut conserver les enregistrements supprimés avec les noms de fichiers, les horodatages, les tailles et les checksums.<sup>[[4]](#references)</sup>

Les données de la table de la base de données **`Sync_config.db`** contiennent l'adresse e-mail du compte, le chemin des dossiers partagés et la version de Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox utilise des **bases de données SQLite** pour gérer les fichiers.<sup>[[2]](#references)</sup> Dans ce\
Vous pouvez trouver les bases de données dans les dossiers :

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Et les bases de données principales sont :

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

L'extension ".dbx" signifie que les **bases de données** sont **chiffrées**. Dropbox utilise **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Pour mieux comprendre le chiffrement utilisé par Dropbox, vous pouvez consulter [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Cependant, les informations principales sont les suivantes :<sup>[[1]](#references)</sup>

- **Entropie** : d114a55212655f74bd772e37e64aee9b
- **Salt** : 0D638C092E8B82FC452883F95F355B8E
- **Algorithme** : PBKDF2
- **Itérations** : 1066

En plus de ces informations, pour déchiffrer les bases de données, vous avez toujours besoin des éléments suivants :<sup>[[2]](#references)</sup>

- La **clé DPAPI chiffrée** : vous pouvez la trouver dans le registre, à l'intérieur de `NTUSER.DAT\Software\Dropbox\ks\client` (exportez ces données au format binaire)
- Les ruches **`SYSTEM`** et **`SECURITY`**
- Les **clés principales DPAPI** : elles se trouvent dans `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Le **nom d'utilisateur** et le **mot de passe** de l'utilisateur Windows

Vous pouvez ensuite utiliser l'outil [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox : vous pouvez ensuite utiliser l'outil DataProtectionDecryptor](<../../../images/image (443).png>)

Si tout se déroule comme prévu, l'outil indiquera la **clé primaire** que vous devez **utiliser pour récupérer la clé originale**. Pour récupérer la clé originale, utilisez simplement cette [recette cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) en plaçant la clé primaire comme « passphrase » dans la recette.

L'hexadécimal obtenu est la clé finale utilisée pour chiffrer les bases de données, qui peuvent être déchiffrées avec :<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
La base de données **`config.dbx`** contient :

- **Email** : L’adresse e-mail de l’utilisateur
- **usernamedisplayname** : Le nom de l’utilisateur
- **dropbox_path** : Chemin où se trouve le dossier Dropbox
- **Host_id: Hash** utilisé pour s’authentifier auprès du cloud. Celui-ci peut uniquement être révoqué depuis le web.
- **Root_ns** : Identifiant de l’utilisateur

La base de données **`filecache.db`** contient des informations sur tous les fichiers et dossiers synchronisés avec Dropbox. La table `File_journal` contient les informations les plus utiles :<sup>[[5]](#references)</sup>

- **Server_path** : Chemin où se trouve le fichier sur le serveur (ce chemin est précédé par le `host_id` du client).
- **local_sjid** : Version du fichier
- **local_mtime** : Date de modification
- **local_ctime** : Date de création

D’autres tables de cette base de données contiennent des informations encore plus intéressantes :

- **block_cache** : hash de tous les fichiers et dossiers de Dropbox
- **block_ref** : Associe l’ID du hash de la table `block_cache` à l’ID du fichier dans la table `file_journal`
- **mount_table** : Dossiers partagés de Dropbox
- **deleted_fields** : Fichiers supprimés de Dropbox
- **date_added**

## References

- [1] [Une analyse critique de la sécurité du logiciel Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Révision du déchiffrement de Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Analyse forensic du cloud storage (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Cas de fuite de données NIST CFReDS : réponses concernant la fuite](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Forensics de Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artifacts de l’utilisation de Google Drive sous Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
