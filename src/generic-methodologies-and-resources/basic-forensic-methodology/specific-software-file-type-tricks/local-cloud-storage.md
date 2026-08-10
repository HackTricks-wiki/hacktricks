# Almacenamiento local en la nube

## OneDrive

En Windows, puedes encontrar la carpeta de OneDrive en `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Y dentro de `logs\Personal` es posible encontrar el archivo `SyncDiagnostics.log`, que contiene algunos datos interesantes sobre los archivos sincronizados:<sup>[[3]](#references)</sup>

- Tamaño en bytes
- Fecha de creación
- Fecha de modificación
- Número de archivos en la nube
- Número de archivos en la carpeta
- **CID**: ID único del usuario de OneDrive
- Hora de generación del informe
- Tamaño del HD del sistema operativo

Una vez que hayas encontrado el CID, se recomienda **buscar archivos que contengan este ID**. Es posible que encuentres archivos con los nombres: _**\<CID>.ini**_ y _**\<CID>.dat**_, que pueden contener información interesante, como los nombres de los archivos sincronizados con OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

En Windows, puedes encontrar la carpeta principal de Google Drive en `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Esta carpeta contiene un archivo llamado Sync_log.log, que registra las sesiones de sincronización del cliente de Google Drive y los eventos de creación, modificación y eliminación de archivos.<sup>[[4]](#references)[[6]](#references)</sup>

El archivo **`Cloud_graph\Cloud_graph.db`** es una base de datos sqlite.<sup>[[6]](#references)</sup> Contiene la tabla **`cloud_graph_entry`**. En esta tabla puedes encontrar el **nombre** de los **archivos** **sincronizados**, la hora de modificación, el tamaño y la suma de comprobación MD5 de los archivos.

La tabla **`cloud_entry`** de la base de datos relacionada **`snapshot.db`** puede conservar registros eliminados con nombres de archivo, marcas de tiempo, tamaños y sumas de comprobación.<sup>[[4]](#references)</sup>

Los datos de la tabla de la base de datos **`Sync_config.db`** contienen la dirección de correo electrónico de la cuenta, la ruta de las carpetas compartidas y la versión de Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox utiliza **bases de datos SQLite** para administrar los archivos.<sup>[[2]](#references)</sup> En esta\
Puedes encontrar las bases de datos en las carpetas:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Y las bases de datos principales son:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

La extensión ".dbx" significa que las **bases de datos** están **cifradas**. Dropbox utiliza **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Para comprender mejor el cifrado que utiliza Dropbox, puedes leer [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Sin embargo, la información principal es:<sup>[[1]](#references)</sup>

- **Entropía**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritmo**: PBKDF2
- **Iteraciones**: 1066

Además de esa información, para descifrar las bases de datos todavía necesitas:<sup>[[2]](#references)</sup>

- La **clave DPAPI cifrada**: puedes encontrarla en el registro, dentro de `NTUSER.DAT\Software\Dropbox\ks\client` (exporta estos datos como binario)
- Las colmenas **`SYSTEM`** y **`SECURITY`**
- Las **claves maestras DPAPI**: se pueden encontrar en `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- El **nombre de usuario** y la **contraseña** del usuario de Windows

A continuación, puedes utilizar la herramienta [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: A continuación, puedes utilizar la herramienta DataProtectionDecryptor](<../../../images/image (443).png>)

Si todo sale según lo esperado, la herramienta indicará la **clave primaria** que necesitas **utilizar para recuperar la original**. Para recuperar la original, solo tienes que utilizar esta [receta de cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) introduciendo la clave primaria como la "passphrase" dentro de la receta.

El valor hexadecimal resultante es la clave final utilizada para cifrar las bases de datos, que se pueden descifrar con:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
La base de datos **`config.dbx`** contiene:

- **Email**: El correo electrónico del usuario
- **usernamedisplayname**: El nombre del usuario
- **dropbox_path**: Ruta donde se encuentra la carpeta de Dropbox
- **Host_id: Hash** utilizado para autenticarse en la nube. Solo puede revocarse desde la web.
- **Root_ns**: Identificador del usuario

La base de datos **`filecache.db`** contiene información sobre todos los archivos y carpetas sincronizados con Dropbox. La tabla `File_journal` es la que contiene la información más útil:<sup>[[5]](#references)</sup>

- **Server_path**: Ruta donde se encuentra el archivo dentro del servidor (esta ruta lleva precedido el `host_id` del cliente).
- **local_sjid**: Versión del archivo
- **local_mtime**: Fecha de modificación
- **local_ctime**: Fecha de creación

Otras tablas dentro de esta base de datos contienen información más interesante:

- **block_cache**: hash de todos los archivos y carpetas de Dropbox
- **block_ref**: Relaciona el ID del hash de la tabla `block_cache` con el ID del archivo en la tabla `file_journal`
- **mount_table**: Carpetas compartidas de Dropbox
- **deleted_fields**: Archivos eliminados de Dropbox
- **date_added**

## References

- [1] [Un análisis crítico de la seguridad del software Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Repaso del descifrado de Dropbox DBX](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Análisis forense del almacenamiento en la nube (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Caso de fuga de datos de NIST CFReDS: respuestas sobre la fuga](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Análisis forense de Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artefactos del uso de Google Drive en Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
