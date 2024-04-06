# Writable Sys Path +Dll Hijacking Privesc

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**oficial mercancía de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Introducción

Si descubres que puedes **escribir en una carpeta de Ruta del Sistema** (ten en cuenta que esto no funcionará si puedes escribir en una carpeta de Ruta de Usuario), es posible que puedas **escalar privilegios** en el sistema.

Para lograrlo, puedes abusar de un **Dll Hijacking** donde vas a **secuestrar una biblioteca que está siendo cargada** por un servicio o proceso con **más privilegios** que los tuyos, y debido a que ese servicio está cargando un Dll que probablemente ni siquiera existe en todo el sistema, intentará cargarlo desde la Ruta del Sistema donde puedes escribir.

Para obtener más información sobre **qué es el Dll Hijacking** consulta:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Privilegio de Escalada con Dll Hijacking

### Encontrar un Dll faltante

Lo primero que necesitas es **identificar un proceso** en ejecución con **más privilegios** que los tuyos que esté intentando **cargar un Dll desde la Ruta del Sistema** en la que puedes escribir.

El problema en estos casos es que probablemente esos procesos ya estén en ejecución. Para encontrar qué Dlls faltan en los servicios, necesitas ejecutar procmon lo antes posible (antes de que se carguen los procesos). Entonces, para encontrar los .dlls faltantes haz lo siguiente:

* **Crea** la carpeta `C:\privesc_hijacking` y añade la ruta `C:\privesc_hijacking` a la **variable de entorno de Ruta del Sistema**. Puedes hacer esto **manualmente** o con **PS**:

```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```

* Inicia **`procmon`** y ve a **`Options`** --> **`Enable boot logging`** y presiona **`OK`** en el mensaje emergente.
* Luego, **reinicia**. Cuando la computadora se reinicie, **`procmon`** comenzará a **grabar** eventos lo antes posible.
* Una vez que **Windows** se haya **iniciado, ejecuta `procmon`** nuevamente, te dirá que ha estado en ejecución y te **preguntará si deseas almacenar** los eventos en un archivo. Di **sí** y **almacena los eventos en un archivo**.
* **Después** de que se genere el **archivo**, **cierra** la ventana abierta de **`procmon`** y **abre el archivo de eventos**.
* Agrega estos **filtros** y encontrarás todas las Dlls que algún **proceso intentó cargar** desde la carpeta de Ruta del Sistema escribible:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### Dlls Perdidas

Al ejecutar esto en una **máquina virtual (vmware) de Windows 11** gratuita, obtuve estos resultados:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

En este caso, los .exe son inútiles, así que ignóralos, las Dlls perdidas eran de:

| Servicio                                    | Dll                | Línea de comandos                                                    |
| ------------------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Programador de tareas (Schedule)            | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Servicio de directivas de diagnóstico (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                                         | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Después de encontrar esto, encontré esta interesante publicación de blog que también explica cómo [**abusar de WptsExtensions.dll para escalada de privilegios**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Lo que **haremos ahora**.

### Explotación

Entonces, para **escalar privilegios** vamos a secuestrar la biblioteca **WptsExtensions.dll**. Teniendo la **ruta** y el **nombre** solo necesitamos **generar la Dll maliciosa**.

Puedes [**intentar usar cualquiera de estos ejemplos**](./#creating-and-compiling-dlls). Podrías ejecutar payloads como: obtener un shell reverso, agregar un usuario, ejecutar un beacon...

{% hint style="warning" %}
Ten en cuenta que **no todos los servicios se ejecutan** con **`NT AUTHORITY\SYSTEM`**, algunos también se ejecutan con **`NT AUTHORITY\LOCAL SERVICE`** que tiene **menos privilegios** y no podrás crear un nuevo usuario para abusar de sus permisos.\
Sin embargo, ese usuario tiene el privilegio **`seImpersonate`**, por lo que puedes usar la [**suite potato para escalar privilegios**](../roguepotato-and-printspoofer.md). Por lo tanto, en este caso, un shell reverso es una mejor opción que intentar crear un usuario.
{% endhint %}

En el momento de escribir esto, el servicio **Programador de tareas** se ejecuta con **Nt AUTHORITY\SYSTEM**.

Una vez que hayas **generado la Dll maliciosa** (en mi caso usé un shell reverso x64 y obtuve un shell, pero Defender lo eliminó porque era de msfvenom), guárdalo en la Ruta del Sistema escribible con el nombre **WptsExtensions.dll** y **reinicia** la computadora (o reinicia el servicio o haz lo que sea necesario para volver a ejecutar el servicio/programa afectado).

Cuando se reinicie el servicio, la **dll debería cargarse y ejecutarse** (puedes **reutilizar** el truco de **procmon** para verificar si la **biblioteca se cargó como se esperaba**).
