# Almacenamiento local en la nube

{{#include ../../../banners/hacktricks-training.md}}


## OneDrive

En Windows, puedes encontrar la carpeta de OneDrive en `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Y dentro de `logs\Personal` es posible encontrar el archivo `SyncDiagnostics.log`, que contiene algunos datos interesantes sobre los archivos sincronizados:

- Tamaño en bytes
- Fecha de creación
- Fecha de modificación
- Número de archivos en la nube
- Número de archivos en la carpeta
- **CID**: ID único del usuario de OneDrive
- Hora de generación del informe
- Tamaño del HD del sistema operativo

Una vez encontrado el CID, se recomienda **buscar archivos que contengan este ID**. Es posible que encuentres archivos con los nombres: _**\<CID>.ini**_ y _**\<CID>.dat**_, que pueden contener información interesante, como los nombres de los archivos sincronizados con OneDrive.

## Google Drive

En Windows, puedes encontrar la carpeta principal de Google Drive en `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Esta carpeta contiene un archivo llamado Sync_log.log con información como la dirección de correo electrónico de la cuenta, nombres de archivo, marcas de tiempo, hashes MD5 de los archivos, etc. Incluso los archivos eliminados aparecen en ese archivo de registro con su MD5 correspondiente.

El archivo **`Cloud_graph\Cloud_graph.db`** es una base de datos sqlite que contiene la tabla **`cloud_graph_entry`**. En esta tabla puedes encontrar el **nombre** de los archivos **sincronizados**, la hora de modificación, el tamaño y la suma de comprobación MD5 de los archivos.

Los datos de la tabla de la base de datos **`Sync_config.db`** contienen la dirección de correo electrónico de la cuenta, la ruta de las carpetas compartidas y la versión de Google Drive.

## Dropbox

Dropbox utiliza **bases de datos SQLite** para gestionar los archivos. En esta\
Puedes encontrar las bases de datos en las carpetas:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Y las bases de datos principales son:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

La extensión ".dbx" significa que las **bases de datos** están **cifradas**. Dropbox utiliza **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))

Para comprender mejor el cifrado que utiliza Dropbox, puedes leer [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Sin embargo, la información principal es:<sup>[[1]](#references)</sup>

- **Entropía**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algoritmo**: PBKDF2
- **Iteraciones**: 1066

Además de esa información, para descifrar las bases de datos todavía necesitas:<sup>[[2]](#references)</sup>

- La **clave DPAPI cifrada**: puedes encontrarla en el registro dentro de `NTUSER.DAT\Software\Dropbox\ks\client` (exporta estos datos como binario)
- Las colmenas **`SYSTEM`** y **`SECURITY`**
- Las **claves maestras DPAPI**: se pueden encontrar en `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- El **nombre de usuario** y la **contraseña** del usuario de Windows

A continuación, puedes utilizar la herramienta [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: A continuación, puedes utilizar la herramienta DataProtectionDecryptor](<../../../images/image (443).png>)

Si todo sale según lo esperado, la herramienta indicará la **clave primaria** que necesitas **utilizar para recuperar la original**. Para recuperar la original, solo tienes que utilizar esta [receta de cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) introduciendo la clave primaria como la "frase de contraseña" dentro de la receta.

El hex resultante es la clave final utilizada para cifrar las bases de datos, que se pueden descifrar con:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
La base de datos **`config.dbx`** contiene:

- **Correo electrónico**: El correo electrónico del usuario
- **usernamedisplayname**: El nombre del usuario
- **dropbox_path**: Ruta donde se encuentra la carpeta de Dropbox
- **Host_id: Hash** utilizado para autenticarse en la cloud. Esto solo se puede revocar desde la web.
- **Root_ns**: Identificador del usuario

La base de datos **`filecache.db`** contiene información sobre todos los archivos y carpetas sincronizados con Dropbox. La tabla `File_journal` es la que contiene la información más útil:

- **Server_path**: Ruta donde se encuentra el archivo dentro del servidor (esta ruta está precedida por el `host_id` del cliente).
- **local_sjid**: Versión del archivo
- **local_mtime**: Fecha de modificación
- **local_ctime**: Fecha de creación

Otras tablas dentro de esta base de datos contienen información más interesante:

- **block_cache**: Hash de todos los archivos y carpetas de Dropbox
- **block_ref**: Relaciona el ID del hash de la tabla `block_cache` con el ID del archivo en la tabla `file_journal`
- **mount_table**: Carpetas compartidas de Dropbox
- **deleted_fields**: Archivos eliminados de Dropbox
- **date_added**

## Referencias

- [1] [Un análisis crítico de la seguridad del software Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Repaso del descifrado de DBX de Dropbox](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)

{{#include ../../../banners/hacktricks-training.md}}
