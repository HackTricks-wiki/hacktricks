# Stockage Cloud Local

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

Dans Windows, vous pouvez trouver le dossier OneDrive dans `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Et à l'intérieur de `logs\Personal`, il est possible de trouver le fichier `SyncDiagnostics.log` qui contient des données intéressantes concernant les fichiers synchronisés :

- Taille en octets
- Date de création
- Date de modification
- Nombre de fichiers dans le cloud
- Nombre de fichiers dans le dossier
- **CID** : ID unique de l'utilisateur OneDrive
- Heure de génération du rapport
- Taille du disque dur du système d'exploitation

Une fois que vous avez trouvé le CID, il est recommandé de **chercher des fichiers contenant cet ID**. Vous pourriez être en mesure de trouver des fichiers avec le nom : _**\<CID>.ini**_ et _**\<CID>.dat**_ qui peuvent contenir des informations intéressantes comme les noms des fichiers synchronisés avec OneDrive.

## Google Drive

Dans Windows, vous pouvez trouver le dossier principal de Google Drive dans `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ce dossier contient un fichier appelé Sync_log.log avec des informations comme l'adresse e-mail du compte, les noms de fichiers, les horodatages, les hachages MD5 des fichiers, etc. Même les fichiers supprimés apparaissent dans ce fichier journal avec leur MD5 correspondant.

Le fichier **`Cloud_graph\Cloud_graph.db`** est une base de données sqlite qui contient la table **`cloud_graph_entry`**. Dans cette table, vous pouvez trouver le **nom** des **fichiers synchronisés**, l'heure de modification, la taille et le hachage MD5 des fichiers.

Les données de la table de la base de données **`Sync_config.db`** contiennent l'adresse e-mail du compte, le chemin des dossiers partagés et la version de Google Drive.

## Dropbox

Dropbox utilise des **bases de données SQLite** pour gérer les fichiers. Dans ce\
Vous pouvez trouver les bases de données dans les dossiers :

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Et les principales bases de données sont :

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

L'extension ".dbx" signifie que les **bases de données** sont **chiffrées**. Dropbox utilise **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Pour mieux comprendre le chiffrement utilisé par Dropbox, vous pouvez lire [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Cependant, les informations principales sont :

- **Entropy** : d114a55212655f74bd772e37e64aee9b
- **Salt** : 0D638C092E8B82FC452883F95F355B8E
- **Algorithm** : PBKDF2
- **Iterations** : 1066

En plus de ces informations, pour déchiffrer les bases de données, vous avez encore besoin de :

- La **clé DPAPI chiffrée** : Vous pouvez la trouver dans le registre à l'intérieur de `NTUSER.DAT\Software\Dropbox\ks\client` (exportez ces données au format binaire)
- Les **hives `SYSTEM`** et **`SECURITY`**
- Les **clés maîtresses DPAPI** : Qui peuvent être trouvées dans `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Le **nom d'utilisateur** et le **mot de passe** de l'utilisateur Windows

Ensuite, vous pouvez utiliser l'outil [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../images/image (443).png>)

Si tout se passe comme prévu, l'outil indiquera la **clé primaire** que vous devez **utiliser pour récupérer l'originale**. Pour récupérer l'originale, utilisez simplement cette [recette cyber_chef](<https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) en mettant la clé primaire comme "phrase secrète" à l'intérieur de la recette.

Le hex résultant est la clé finale utilisée pour chiffrer les bases de données qui peut être déchiffrée avec :
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
La base de données **`config.dbx`** contient :

- **Email** : L'email de l'utilisateur
- **usernamedisplayname** : Le nom de l'utilisateur
- **dropbox_path** : Chemin où le dossier Dropbox est situé
- **Host_id : Hash** utilisé pour s'authentifier dans le cloud. Cela ne peut être révoqué que depuis le web.
- **Root_ns** : Identifiant de l'utilisateur

La base de données **`filecache.db`** contient des informations sur tous les fichiers et dossiers synchronisés avec Dropbox. La table `File_journal` est celle avec les informations les plus utiles :

- **Server_path** : Chemin où le fichier est situé à l'intérieur du serveur (ce chemin est précédé par le `host_id` du client).
- **local_sjid** : Version du fichier
- **local_mtime** : Date de modification
- **local_ctime** : Date de création

D'autres tables à l'intérieur de cette base de données contiennent des informations plus intéressantes :

- **block_cache** : hash de tous les fichiers et dossiers de Dropbox
- **block_ref** : Relie l'ID de hash de la table `block_cache` avec l'ID de fichier dans la table `file_journal`
- **mount_table** : Dossiers partagés de Dropbox
- **deleted_fields** : Fichiers supprimés de Dropbox
- **date_added**

{{#include ../../../banners/hacktricks-training.md}}
