# Ruta del Sistema Escriturable + Escalada de Privilegios por Secuestro de Dll

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción

Si descubriste que puedes **escribir en una carpeta de Ruta del Sistema** (ten en cuenta que esto no funcionará si puedes escribir en una carpeta de Ruta de Usuario), es posible que puedas **escalar privilegios** en el sistema.

Para hacerlo, puedes abusar de un **Secuestro de Dll** donde vas a **secuestrar una biblioteca que está siendo cargada** por un servicio o proceso con **más privilegios** que los tuyos, y debido a que ese servicio está cargando una Dll que probablemente ni siquiera existe en todo el sistema, intentará cargarla desde la Ruta del Sistema donde puedes escribir.

Para más información sobre **qué es el Secuestro de Dll**, consulta:

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Escalada de Privilegios con Secuestro de Dll

### Encontrando una Dll faltante

Lo primero que necesitas es **identificar un proceso** que se ejecute con **más privilegios** que tú y que esté intentando **cargar una Dll desde la Ruta del Sistema** en la que puedes escribir.

El problema en estos casos es que probablemente esos procesos ya están en ejecución. Para encontrar qué Dlls faltan en los servicios, necesitas lanzar procmon lo antes posible (antes de que los procesos se carguen). Entonces, para encontrar .dlls faltantes haz lo siguiente:

* **Crea** la carpeta `C:\privesc_hijacking` y añade la ruta `C:\privesc_hijacking` a la variable de entorno **Ruta del Sistema**. Puedes hacer esto **manualmente** o con **PS**:
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
* Inicie **`procmon`** y vaya a **`Opciones`** --> **`Habilitar registro de arranque`** y presione **`OK`** en el mensaje.
* Luego, **reinicie**. Cuando la computadora se reinicie, **`procmon`** comenzará a **registrar** eventos lo antes posible.
* Una vez que **Windows** esté **iniciado, ejecute `procmon`** nuevamente, le informará que ha estado funcionando y le **preguntará si desea almacenar** los eventos en un archivo. Diga **sí** y **almacene los eventos en un archivo**.
* **Después** de que el **archivo** sea **generado**, **cierre** la ventana de **`procmon`** abierta y **abra el archivo de eventos**.
* Añada estos **filtros** y encontrará todas las DLL que algún **proceso intentó cargar** desde la carpeta del Sistema con permisos de escritura:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### DLLs Faltantes

Ejecutando esto en una máquina **virtual (vmware) Windows 11 gratuita**, obtuve estos resultados:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

En este caso los .exe no sirven, así que ignórelos, las DLL faltantes eran de:

| Servicio                         | Dll                | Línea de comandos                                                    |
| -------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Programador de tareas (Schedule) | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Servicio de Política de Diagnóstico (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                              | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Después de encontrar esto, encontré esta interesante publicación de blog que también explica cómo [**abusar de WptsExtensions.dll para privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Que es lo que **vamos a hacer ahora**.

### Explotación

Entonces, para **escalar privilegios** vamos a secuestrar la biblioteca **WptsExtensions.dll**. Teniendo la **ruta** y el **nombre**, solo necesitamos **generar la dll maliciosa**.

Puede [**intentar usar cualquiera de estos ejemplos**](../dll-hijacking.md#creating-and-compiling-dlls). Podría ejecutar cargas útiles como: obtener un rev shell, agregar un usuario, ejecutar un beacon...

{% hint style="warning" %}
Tenga en cuenta que **no todos los servicios se ejecutan** con **`NT AUTHORITY\SYSTEM`**, algunos también se ejecutan con **`NT AUTHORITY\LOCAL SERVICE`**, que tiene **menos privilegios** y **no podrá crear un nuevo usuario** ni abusar de sus permisos.\
Sin embargo, ese usuario tiene el privilegio **`seImpersonate`**, por lo que puede usar la [**suite de potato para escalar privilegios**](../roguepotato-and-printspoofer.md). Por lo tanto, en este caso un rev shell es una mejor opción que intentar crear un usuario.
{% endhint %}

En el momento de escribir, el servicio **Programador de tareas** se ejecuta con **Nt AUTHORITY\SYSTEM**.

Habiendo **generado la Dll maliciosa** (_en mi caso usé x64 rev shell y obtuve una shell de vuelta pero defender la mató porque era de msfvenom_), guárdela en la ruta del Sistema con permisos de escritura con el nombre **WptsExtensions.dll** y **reinicie** la computadora (o reinicie el servicio o haga lo que sea necesario para volver a ejecutar el servicio/programa afectado).

Cuando se reinicie el servicio, la **dll debería cargarse y ejecutarse** (puede **reutilizar** el truco de **procmon** para verificar si la **biblioteca se cargó como se esperaba**).

<details>

<summary><strong>Aprenda hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si desea ver a su **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtenga el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únase al grupo de** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) o al grupo de [**telegram**](https://t.me/peass) o **sígame** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparta sus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
