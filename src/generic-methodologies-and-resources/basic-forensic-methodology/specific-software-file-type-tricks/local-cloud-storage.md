# Stockage cloud local

{{#include ../../../banners/hacktricks-training.md}}

## Émulateurs de stockage local et clés de compte

Un émulateur Blob compatible avec Azure exécuté dans un conteneur peut être accessible depuis son hôte ou son réseau bridge, même si le service de stockage n’est pas exposé à l’extérieur. Examinez les fichiers de configuration locaux lisibles et les métadonnées des fichiers de sauvegarde à la recherche d’un nom de compte et d’une clé, sans afficher la clé lors d’une énumération de routine. [Azurite prend en charge les clés de compte locales personnalisées](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); [l’autorisation Shared Key](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access) peut accorder un accès étendu aux données du compte correspondant. La présence d’un fichier de clé ne suffit pas à établir une escalade de privilèges : confirmez que le point de terminaison est accessible, que le compte et la clé sont acceptés et que le blob en question contient réellement un identifiant utilisable pour une identité plus privilégiée. S’il contient une clé privée SSH, la clé publique correspondante doit également être autorisée pour cette identité et l’accès SSH doit être permis. Protégez et faites tourner la clé une fois son exposition confirmée.

## OneDrive

Sous Windows, le dossier OneDrive se trouve dans `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Dans `logs\Personal`, le fichier `SyncDiagnostics.log` peut contenir des données intéressantes concernant les fichiers synchronisés :<sup>[[3]](#references)</sup>

- Taille en octets
- Date de création
- Date de modification
- Nombre de fichiers dans le cloud
- Nombre de fichiers dans le dossier
- **CID** : identifiant unique de l’utilisateur OneDrive
- Heure de génération du rapport
- Taille du disque dur du système d’exploitation

Une fois le CID trouvé, il est recommandé de **rechercher les fichiers contenant cet identifiant**. Vous pourrez peut-être trouver des fichiers nommés _**\<CID>.ini**_ et _**\<CID>.dat**_ qui contiennent des informations intéressantes, comme les noms des fichiers synchronisés avec OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

Sous Windows, le dossier principal de Google Drive se trouve dans `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ce dossier contient un fichier nommé Sync_log.log, qui consigne les sessions de synchronisation du client Google Drive ainsi que les événements de création, de modification et de suppression de fichiers.<sup>[[4]](#references)[[6]](#references)</sup>

Le fichier **`Cloud_graph\Cloud_graph.db`** est une base de données SQLite.<sup>[[6]](#references)</sup> Elle contient la table **`cloud_graph_entry`**. Cette table contient le **nom** des **fichiers** **synchronisés**, leur heure de modification, leur taille et leur somme de contrôle MD5.

La table **`cloud_entry`** de la base de données associée **`snapshot.db`** peut conserver les enregistrements supprimés, avec leurs noms de fichiers, horodatages, tailles et sommes de contrôle.<sup>[[4]](#references)</sup>

Les données de la table de la base de données **`Sync_config.db`** contiennent l’adresse e-mail du compte, le chemin des dossiers partagés et la version de Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox utilise des **bases de données SQLite** pour gérer les fichiers.<sup>[[2]](#references)</sup> Dans ce dossier,\
Vous pouvez trouver les bases de données dans les dossiers suivants :

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Les principales bases de données sont :

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

L’extension « .dbx » indique que les **bases de données** sont **chiffrées**. Dropbox utilise **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Pour mieux comprendre le chiffrement utilisé par Dropbox, vous pouvez lire [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Voici toutefois les principales informations :<sup>[[1]](#references)</sup>

- **Entropie** : d114a55212655f74bd772e37e64aee9b
- **Sel** : 0D638C092E8B82FC452883F95F355B8E
- **Algorithme** : PBKDF2
- **Itérations** : 1066

En plus de ces informations, vous avez encore besoin des éléments suivants pour déchiffrer les bases de données :<sup>[[2]](#references)</sup>

- La **clé DPAPI chiffrée** : vous pouvez la trouver dans le registre, sous `NTUSER.DAT\Software\Dropbox\ks\client` (exportez ces données au format binaire)
- Les ruches **`SYSTEM`** et **`SECURITY`**
- Les **clés principales DPAPI** : elles se trouvent dans `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- Le **nom d’utilisateur** et le **mot de passe** de l’utilisateur Windows

Vous pouvez ensuite utiliser l’outil [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox : vous pouvez ensuite utiliser l’outil DataProtectionDecryptor](<../../../images/image (443).png>)

Si tout se passe comme prévu, l’outil indiquera la **clé principale** que vous devez **utiliser pour récupérer la clé d’origine**. Pour récupérer cette dernière, utilisez simplement cette [recette cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) en plaçant la clé principale dans le champ « passphrase » de la recette.

La valeur hexadécimale obtenue est la clé finale utilisée pour chiffrer les bases de données. Elles peuvent être déchiffrées avec :<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

La base de données **`config.dbx`** contient :

- **Email** : L’adresse email de l’utilisateur
- **usernamedisplayname** : Le nom de l’utilisateur
- **dropbox_path** : Chemin où se trouve le dossier Dropbox
- **Host_id: Hash** utilisé pour s’authentifier auprès du cloud. Il ne peut être révoqué que depuis le Web.
- **Root_ns** : Identifiant de l’utilisateur

La base de données **`filecache.db`** contient des informations sur tous les fichiers et dossiers synchronisés avec Dropbox. La table `File_journal` contient les informations les plus utiles :<sup>[[5]](#references)</sup>

- **Server_path** : Chemin où se trouve le fichier sur le serveur (ce chemin est précédé du `host_id` du client).
- **local_sjid** : Version du fichier
- **local_mtime** : Date de modification
- **local_ctime** : Date de création

D’autres tables de cette base de données contiennent des informations intéressantes :

- **block_cache** : Hash de tous les fichiers et dossiers Dropbox
- **block_ref** : Associe l’identifiant de hash de la table `block_cache` à l’identifiant du fichier dans la table `file_journal`
- **mount_table** : Dossiers partagés de Dropbox
- **deleted_fields** : Fichiers Dropbox supprimés
- **date_added**

## References

- [1] [Analyse critique de la sécurité du logiciel Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [À propos du déchiffrement des fichiers DBX Dropbox](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Analyse forensique du stockage cloud (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Cas de fuite de données NIST CFReDS : réponses sur les fuites](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Analyse forensique de Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefacts liés à l’utilisation de Google Drive sous Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
