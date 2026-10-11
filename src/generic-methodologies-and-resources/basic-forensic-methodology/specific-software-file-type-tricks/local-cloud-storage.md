# Almacenamiento local en la nube

{{#include ../../../banners/hacktricks-training.md}}

## Emuladores de almacenamiento local y claves de cuenta

Un emulador de Blob compatible con Azure que se ejecute en un contenedor puede ser accesible desde el host o la red puente, incluso cuando el servicio de almacenamiento no está expuesto externamente. Revisa la configuración local legible y los metadatos de los archivos de copia de seguridad en busca del nombre y la clave de una cuenta, sin mostrar la clave durante la enumeración rutinaria. [Azurite supports custom local account keys](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); [Shared Key authorization](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access) puede otorgar acceso amplio a los datos de la cuenta correspondiente. El hecho de tener un archivo de clave no demuestra por sí solo que haya una escalada: confirma que el endpoint es accesible, que se aceptan la cuenta y la clave, y que el blob concreto contiene una credencial utilizable para una identidad con más privilegios. Si contiene una clave privada SSH, también debe estar autorizada para esa identidad la clave pública correspondiente, y debe permitirse el acceso SSH. Protege y rota la clave una vez confirmada la exposición.

## OneDrive

En Windows, puedes encontrar la carpeta de OneDrive en `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Dentro de `logs\Personal` es posible encontrar el archivo `SyncDiagnostics.log`, que contiene datos interesantes sobre los archivos sincronizados:<sup>[[3]](#references)</sup>

- Tamaño en bytes
- Fecha de creación
- Fecha de modificación
- Número de archivos en la nube
- Número de archivos en la carpeta
- **CID**: ID único del usuario de OneDrive
- Hora de generación del informe
- Tamaño del disco duro del sistema operativo

Una vez que encuentres el CID, se recomienda **buscar archivos que contengan este ID**. Es posible que encuentres archivos llamados _**\<CID>.ini**_ y _**\<CID>.dat**_ que pueden contener información interesante, como los nombres de los archivos sincronizados con OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

En Windows, puedes encontrar la carpeta principal de Google Drive en `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Esta carpeta contiene un archivo llamado Sync_log.log que registra las sesiones de sincronización del cliente de Google Drive y los eventos de creación, modificación y eliminación de archivos.<sup>[[4]](#references)[[6]](#references)</sup>

El archivo **`Cloud_graph\Cloud_graph.db`** es una base de datos SQLite.<sup>[[6]](#references)</sup> Contiene la tabla **`cloud_graph_entry`**. En esta tabla puedes encontrar el **nombre** de los **archivos** **sincronizados**, la hora de modificación, el tamaño y la suma de comprobación MD5 de los archivos.

La tabla **`cloud_entry`** de la base de datos relacionada **`snapshot.db`** puede conservar registros eliminados con nombres de archivo, marcas de tiempo, tamaños y sumas de comprobación.<sup>[[4]](#references)</sup>

Los datos de la tabla de la base de datos **`Sync_config.db`** contienen la dirección de correo electrónico de la cuenta, la ruta de las carpetas compartidas y la versión de Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox utiliza **bases de datos SQLite** para administrar los archivos.<sup>[[2]](#references)</sup> En este caso,
puedes encontrar las bases de datos en las carpetas:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Y las bases de datos principales son:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

La extensión «.dbx» indica que las **bases de datos** están **cifradas**. Dropbox utiliza **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Para comprender mejor el cifrado que utiliza Dropbox, puedes leer [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Sin embargo, la información principal es:<sup>[[1]](#references)</sup>

- **Entropía**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritmo**: PBKDF2
- **Iteraciones**: 1066

Además de esa información, para descifrar las bases de datos aún necesitas:<sup>[[2]](#references)</sup>

- La **clave DPAPI cifrada**: puedes encontrarla en el registro, dentro de `NTUSER.DAT\Software\Dropbox\ks\client` (exporta estos datos en formato binario)
- Las secciones **`SYSTEM`** y **`SECURITY`**
- Las **claves maestras DPAPI**: se encuentran en `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- El **nombre de usuario** y la **contraseña** del usuario de Windows

Luego puedes utilizar la herramienta [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Then you can use the tool DataProtectionDecryptor](<../../../images/image (443).png>)

Si todo sale como se espera, la herramienta indicará la **clave principal** que necesitas **usar para recuperar la original**. Para recuperar la clave original, utiliza este [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) e introduce la clave principal como «passphrase» en la receta.

El valor hexadecimal resultante es la clave final utilizada para cifrar las bases de datos, que se pueden descifrar con:<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

La base de datos **`config.dbx`** contiene:

- **Email**: El correo electrónico del usuario
- **usernamedisplayname**: El nombre del usuario
- **dropbox_path**: Ruta donde se encuentra la carpeta de Dropbox
- **Host_id: Hash** usado para autenticarse en la nube. Solo se puede revocar desde la web.
- **Root_ns**: Identificador del usuario

La base de datos **`filecache.db`** contiene información sobre todos los archivos y carpetas sincronizados con Dropbox. La tabla `File_journal` es la que contiene la información más útil:<sup>[[5]](#references)</sup>

- **Server_path**: Ruta donde se encuentra el archivo en el servidor (esta ruta va precedida por el `host_id` del cliente).
- **local_sjid**: Versión del archivo
- **local_mtime**: Fecha de modificación
- **local_ctime**: Fecha de creación

Otras tablas de esta base de datos contienen información más interesante:

- **block_cache**: Hash de todos los archivos y carpetas de Dropbox
- **block_ref**: Relaciona el ID hash de la tabla `block_cache` con el ID del archivo en la tabla `file_journal`
- **mount_table**: Carpetas compartidas de Dropbox
- **deleted_fields**: Archivos eliminados de Dropbox
- **date_added**

## References

- [1] [Un análisis crítico de la seguridad del software de Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Repaso del descifrado de Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Análisis forense del almacenamiento en la nube (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Caso de filtración de datos de NIST CFReDS: respuestas sobre la filtración](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Análisis forense de Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefactos del uso de Google Drive en Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
