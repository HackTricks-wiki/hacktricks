# Explotación de Race Conditions del Kernel mediante Slow Paths del Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Por qué es importante ampliar la ventana de la race

Muchas LPE del kernel de Windows siguen el patrón clásico `check_state(); NtOpenX("name"); privileged_action();`. En hardware moderno, un `NtOpenEvent`/`NtOpenSection` en frío resuelve un nombre corto en aproximadamente 2 µs, dejando muy poco tiempo para modificar el estado comprobado antes de que se produzca la acción segura. Al forzar deliberadamente que la búsqueda del Object Manager Namespace (OMNS) del paso 2 tarde decenas de microsegundos, el atacante obtiene tiempo suficiente para ganar de forma consistente races que, de otro modo, serían poco fiables, sin necesidad de realizar miles de intentos.<sup>[[1]](#references)</sup>

## Funcionamiento interno de las búsquedas del Object Manager en resumen

* **Estructura del OMNS** – Los nombres como `\BaseNamedObjects\Foo` se resuelven directorio por directorio. Cada componente hace que el kernel busque/abra un *Object Directory* y compare cadenas Unicode. Los enlaces simbólicos (por ejemplo, las letras de unidad) pueden atravesarse durante el proceso.
* **Límite de UNICODE_STRING** – Las rutas del OM se transportan dentro de un `UNICODE_STRING` cuyo campo `Length` es un valor de 16 bits. El límite absoluto es de 65 535 bytes (32 767 codepoints UTF-16). Con prefijos como `\BaseNamedObjects\`, el atacante aún controla aproximadamente 32 000 caracteres.
* **Requisitos del atacante** – Cualquier usuario puede crear objetos dentro de directorios con permisos de escritura, como `\BaseNamedObjects`. Cuando el código vulnerable usa un nombre situado allí, o sigue un enlace simbólico que termina allí, el atacante controla el rendimiento de la búsqueda sin privilegios especiales.<sup>[[1]](#references)</sup>

## Primitiva de ralentización n.º 1 – Componente único máximo

El coste de resolver un componente es aproximadamente lineal respecto a su longitud, porque el kernel debe realizar una comparación Unicode con cada entrada del directorio principal. Crear un evento con un nombre de 32 kB aumenta inmediatamente la latencia de `NtOpenEvent` de aproximadamente 2 µs a aproximadamente 35 µs en Windows 11 24H2 (entorno de pruebas Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notas prácticas*

- Puedes alcanzar el límite de longitud usando cualquier objeto de kernel con nombre (eventos, secciones, semáforos…).
- Los enlaces simbólicos o puntos de reanálisis pueden apuntar desde un nombre corto de “víctima” a este componente gigante, de modo que la ralentización se aplique de forma transparente.
- Como todo reside en namespaces modificables por el usuario, el payload funciona desde un nivel de integridad de usuario estándar.<sup>[[1]](#references)</sup>

## Primitiva de ralentización n.º 2 – Directorios recursivos profundos

Una variante más agresiva asigna una cadena de miles de directorios (`\BaseNamedObjects\A\A\...\X`). Cada salto activa la lógica de resolución de directorios (comprobaciones de ACL, búsquedas hash, conteo de referencias), por lo que la latencia por nivel es mayor que la de una única comparación de cadenas. Con unos 16 000 niveles (limitados por el mismo tamaño de `UNICODE_STRING`), las mediciones empíricas superan la barrera de 35 µs alcanzada por componentes individuales largos.
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
Consejos:

* Alterna el carácter por nivel (`A/B/C/...`) si el directorio padre empieza a rechazar duplicados.
* Mantén un array de handles para poder eliminar la cadena limpiamente después de la explotación y evitar contaminar el namespace.<sup>[[1]](#references)</sup>

## Primitiva de slowdown n.º 3 – Shadow directories, colisiones de hash y reparses de symlinks (minutos en lugar de microsegundos)

Los directorios de Object Manager admiten **shadow directories** (búsquedas de fallback) y tablas hash divididas en buckets para las entradas. Abusa de ambos, además del límite de 64 componentes de reparse de symbolic links, para multiplicar el slowdown sin superar la longitud de `UNICODE_STRING`:

1. Crea dos directorios bajo `\BaseNamedObjects`, por ejemplo `A` (shadow) y `A\A` (target). Crea el segundo usando el primero como shadow directory (`NtCreateDirectoryObjectEx`), de modo que las búsquedas que no encuentren coincidencias en `A` continúen en `A\A`.
2. Rellena cada directorio con miles de **nombres que colisionen** y terminen en el mismo hash bucket (por ejemplo, variando los dígitos finales mientras mantienes el mismo valor de `RtlHashUnicodeString`). Las búsquedas ahora se degradan a scans lineales O(n) dentro de un único directorio.
3. Construye una cadena de aproximadamente 63 **symbolic links de Object Manager** que hagan reparse repetidamente hacia el sufijo largo `A\A\…`, consumiendo el presupuesto de reparse. Cada reparse reinicia el parsing desde el principio, multiplicando el coste de las colisiones.
4. La búsqueda del componente final (`...\\0`) ahora tarda **minutos** en Windows 11 cuando hay 16 000 colisiones por directorio, lo que proporciona una victoria de race prácticamente garantizada para LPEs de kernel one-shot.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por qué importa*: Una ralentización de varios minutos convierte los LPEs basados en race de una sola oportunidad en exploits deterministas.<sup>[[1]](#references)</sup>

### Notas de la reevaluación de 2025 y tooling listo para usar

- James Forshaw volvió a publicar la técnica con tiempos actualizados en Windows 11 24H2 (ARM64). Las aperturas de referencia siguen siendo de ~2 µs; un componente de 32 kB eleva este valor a ~35 µs, y las cadenas de shadow-dir + collision + 63-reparse siguen alcanzando ~3 minutos, lo que confirma que los primitives sobreviven en las builds actuales. El código fuente y el perf harness están en la publicación actualizada de Project Zero.<sup>[[1]](#references)</sup>
- Puedes automatizar la configuración mediante el bundle público `symboliclink-testing-tools`: `CreateObjectDirectory.exe` para crear el par shadow/target y `NativeSymlink.exe` en un bucle para generar la cadena de 63 saltos. Esto evita escribir manualmente wrappers de `NtCreate*` y mantiene las ACLs coherentes.<sup>[[2]](#references)</sup>

## Medición de tu race window

Integra un harness rápido en tu exploit para medir cuánto aumenta la window en el hardware de la víctima. El snippet siguiente abre el objeto target `iterations` veces y devuelve el coste medio por apertura mediante `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
Los resultados se incorporan directamente a tu estrategia de orquestación de la race (p. ej., el número de worker threads necesarios, los intervalos de suspensión y con cuánta antelación necesitas cambiar el estado compartido).

## Flujo de explotación

1. **Localiza la apertura vulnerable** – Rastrea la ruta del kernel (mediante symbols, ETW, hypervisor tracing o reversing) hasta encontrar una llamada `NtOpen*`/`ObOpenObjectByName` que recorra un nombre controlado por el atacante o un symbolic link en un directorio con permisos de escritura para el usuario.
2. **Sustituye ese nombre por una ruta lenta**
- Crea el componente largo o la cadena de directorios bajo `\BaseNamedObjects` (u otra raíz de OM con permisos de escritura).
- Crea un symbolic link para que el nombre que espera el kernel ahora resuelva a la ruta lenta. Puedes redirigir la búsqueda de directorio del driver vulnerable a tu estructura sin tocar el target original.
3. **Activa la race**
- El Thread A (víctima) ejecuta el código vulnerable y queda bloqueado dentro de la búsqueda lenta.
- El Thread B (atacante) cambia el estado protegido (p. ej., intercambia un file handle, reescribe un symbolic link o alterna la seguridad del objeto) mientras el Thread A está ocupado.
- Cuando el Thread A continúa y realiza la acción privilegiada, observa un estado obsoleto y ejecuta la operación controlada por el atacante.
4. **Limpia** – Elimina la cadena de directorios y los symbolic links para no dejar artefactos sospechosos ni interrumpir a los usuarios legítimos de IPC.<sup>[[1]](#references)</sup>

## Cadena aplicada: placeholders mutables de Cloud Files + cambio de ruta del Object Manager

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), publicado como bypass para RoguePlanet (CVE-2026-50656), demuestra un patrón de explotación más amplio: hacer que un scanner privilegiado clasifique una representación de un archivo lógico y cambiar después tanto sus bytes como la resolución de su namespace antes de que la remediación lo utilice. El PoC combina un TOCTOU de hydration de Cloud Files, un fallback de shadow-directory del Object Manager, la captura de nombres generados por CLFS y un link de administrative share local para convertir la limpieza de Defender en una escritura de DLL protegida.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Sustituir el contenido mediante la hydration de Cloud Files

Registra un directorio controlado por el atacante como sync root de Cloud Files, conecta un callback `CF_CALLBACK_TYPE_FETCH_DATA` y crea un placeholder cuyo tamaño anunciado coincida con un trigger de detección determinista, como el EICAR ZIP. El primer fetch devuelve el trigger y cambia el estado del callback; los fetch posteriores devuelven el payload. Después de que el scanner haya clasificado la primera representación, obtiene la transfer key y reinicia la hydration con metadata del tamaño del payload; después, fuerza la hydration hasta EOF.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
El límite de seguridad falla si el scan, el veredicto y la remediación se refieren únicamente a un pathname o a una identidad de marcador de posición: ninguno garantiza que una hidratación posterior devuelva los bytes que se inspeccionaron.<sup>[[4]](#references)</sup>

### 2. Cambiar una ruta invariable mediante un fallback de shadow-directory

Crea un directorio de Object Manager de destino y un segundo directorio con `NtCreateDirectoryObjectEx`, pasando el handle del destino como su directorio shadow/fallback. Coloca una entrada `WD_SCAN` con el mismo nombre en ambas capas de resolución: la entrada visible apunta al directorio de trabajo normal, mientras que la entrada fallback apunta a `\CLFS\??\<working-directory>`. Proporciona a Defender únicamente la ruta invariable indicada a continuación; eliminar el enlace visible mientras la operación está activa hace que la misma cadena continúe hasta la entrada respaldada por CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Esto es distinto de usar shadow directories únicamente para ralentizar la búsqueda: el atacante cambia el **significado** de una ruta aceptada previamente sin modificar su cadena.<sup>[[4]](#references)</sup>

### 3. Capturar el nombre generado e instalar un enlace específico para el nombre de archivo

Monitoriza el directorio de trabajo con `ReadDirectoryChangesW`. En el primer `FILE_ACTION_ADDED`, elimina el enlace visible `WD_SCAN` para activar la búsqueda de reserva. Captura el segundo nombre de archivo generado, abre ese archivo relacionado con CLFS y bloquea el rango `0..MAXLONGLONG` con `LockFileEx`. Mientras la operación con privilegios está detenida, reemplaza `WD_SCAN` en el directorio visible por un directorio real de Object Manager y crea un enlace simbólico hijo con el nombre del archivo observado (el PoC elimina sus cuatro caracteres finales). Apúntalo al destino protegido mediante SMB local:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
El proceso sin privilegios no puede escribir por sí mismo en ese destino, pero el contexto SYSTEM de Defender puede atravesar el recurso administrativo de loopback. Combinar la observación de nombres generados con un enlace del Object Manager específico para el nombre de archivo evita tener que predecir de antemano el artefacto de remediación.<sup>[[4]](#references)</sup>

### 4. Estabilizar la race de limpieza y activar un loader privilegiado

Antes del escaneo, el PoC almacena un PE válido (`ntdll.dll`) en el flujo de datos alternativo NTFS `:stream` del placeholder. Después de que la redirección cree el archivo base protegido, abre `phoneinfo.dll:stream` con acceso de ejecución y mantiene activo un mapping `PAGE_EXECUTE_READ | SEC_IMAGE` mientras se reanuda la limpieza; los objetos de archivo/sección activos restringen la eliminación o sustitución durante la race final. La hidratación reiniciada devuelve ahora la payload DLL en lugar de EICAR, por lo que el archivo base protegido contiene código controlado por el atacante.<sup>[[4]](#references)</sup>

A continuación, una escritura protegida se convierte en ejecución como SYSTEM colocando un `Report.wer` manipulado bajo `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` e invocando `\Microsoft\Windows\Windows Error Reporting\QueueReporting` mediante la API COM del Task Scheduler. En esta cadena, el procesamiento privilegiado de WER carga la `C:\Windows\System32\phoneinfo.dll` colocada; una conexión de named pipe se utiliza como señal de ejecución de la payload.<sup>[[4]](#references)</sup>

### Pivotes de detección

Las correlaciones útiles son más específicas que cualquier nombre temporal individual y abarcan todas las transiciones de namespace de la cadena:<sup>[[4]](#references)</sup>

- Un proveedor de Cloud Files registrado recientemente, seguido de la detección de EICAR y de `CF_OPERATION_TYPE_RESTART_HYDRATION` en el mismo placeholder.
- Rutas del Object Manager que contengan `WD_TARGET_*`, `WD_SHADOW_*` o `WD_SCAN`, especialmente una ruta de escaneo bajo `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Creación de archivos CLFS seguida de un bloqueo exclusivo del archivo completo y acceso de loopback a `\\127.0.0.1\C$\Windows\System32\*.dll` desde un proceso de seguridad privilegiado.
- Creación de una DLL en System32 junto con un NTFS ADS, seguida del mapping `SEC_IMAGE` del stream.
- Una entrada de cola WER creada por el atacante, seguida de una ejecución manual inusual de `\Microsoft\Windows\Windows Error Reporting\QueueReporting` y de la carga de imagen de la DLL colocada.

## Cadena aplicada: cambio de mount point controlado por oplock contra una remediación privilegiada

Un patrón reutilizable de LPE aparece cuando un scanner privilegiado comprueba un archivo controlado por el atacante y posteriormente lo remedia reabriendo el **pathname** en lugar de continuar mediante handles validados. FalconFlank es un ejemplo público dirigido al workflow de eliminación de macros de Office de CrowdStrike Falcon; el repositorio afirma haber realizado pruebas en Windows 11 25H2 y Windows Server 2025 con la policy relevante habilitada, pero no publica ningún CVE, rango de builds afectadas, advisory del vendor ni estado del parche, por lo que la afirmación específica del producto debe tratarse como no verificada y dependiente del build.<sup>[[5]](#references)[[6]](#references)</sup>

### Disposición de la race

1. Crea un árbol escribible cuyo nombre relativo final sea útil en el destino previsto. El ejemplo utiliza `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`, pero inicialmente escribe un documento de macros OLE —no una DLL PE— en `bcrypt.dll`. La detección basada en el contenido activa la remediación mientras conserva el basename controlado por el atacante para el side-load posterior.<sup>[[5]](#references)</sup>
2. Abre los directorios con sharing amplio y `FILE_OPEN_REPARSE_POINT`, y solicita un oplock RH asíncrono en el trigger mediante `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` y `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`. Espera el evento overlapped y utiliza su finalización como indicación para cambiar la ruta. Una notificación de ruptura de un oplock RH es consultiva, no una prueba de que todas las operaciones conflictivas estén bloqueadas, por lo que la explotabilidad sigue dependiendo de la secuencia exacta de apertura/remediación de la víctima.<sup>[[5]](#references)[[7]](#references)</sup>
3. Después de la ruptura, elimina el directorio leaf con `FileDispositionInformationEx` (information class 64), usando flags de eliminación y semántica POSIX, cierra su handle y aplica un `IO_REPARSE_TAG_MOUNT_POINT` al parent ahora vacío mediante `FSCTL_SET_REPARSE_POINT_EX`. El mount point redirige el sufijo sin cambios hacia un árbol protegido como `\\SystemRoot\\System32\\WindowsPowerShell`; establecer un reparse point falla si el directorio no está vacío, lo que explica el paso de eliminación anterior.<sup>[[5]](#references)[[8]](#references)</sup>
4. Reanuda el workflow privilegiado. Si vuelve a resolver el string sin demostrar que la cadena de directorios y el objeto final son los que se inspeccionaron anteriormente, el mismo pathname lógico llega ahora al directorio protegido seleccionado por el atacante. En el ejemplo, el éxito se comprueba reabriendo `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` con acceso de lectura/escritura desde el proceso original; esto distingue la primitive de escritura confused-deputy de la fase posterior de ejecución de código.<sup>[[5]](#references)</sup>
5. Sustituye el archivo resultante por la DLL real y activa un loader privilegiado. El PoC utiliza `CreateTransaction` + `CreateFileTransacted`, trunca el archivo, mapea la sustitución del tamaño de la DLL, copia el PE y hace commit; TxF vincula el file handle y las operaciones posteriores basadas en handles a la transacción, pero es un mecanismo de sustitución posterior a la race, no el origen del fallo del límite de privilegios.<sup>[[5]](#references)[[9]](#references)</sup>
6. Por último, ejecuta una scheduled task privilegiada existente cuyo ejecutable busca el nombre adyacente colocado. FalconFlank invoca `\\Microsoft\\Windows\\Application Experience\\MareBackup`, espera a que la DLL se conecte a `\\??\\pipe\\FALCONFLANK` y después elimina el archivo colocado. No asumas un token resultante concreto únicamente por el nombre de la task: verifica el proceso iniciado, la ruta del módulo, el nivel de integridad y el token en el build probado.<sup>[[5]](#references)</sup>

Por tanto, la pregunta central de auditoría no es «¿valida el servicio el input path original?», sino «¿cada mutación privilegiada permanece vinculada a los mismos objetos de archivo y directorio abiertos que fueron validados?». Mantener handles entre la comprobación y el uso, abrir objetos child relativos a un handle de directorio de confianza, rechazar tags de reparse inesperados y volver a validar la identidad del archivo antes de la mutación cierran esta clase de bug de sustitución de pathname.<sup>[[1]](#references)[[8]](#references)</sup>

### Detección y triage del PoC

La detección de alta señal correlaciona la transición del namespace con el consumidor privilegiado: un encabezado OLE bajo un basename de DLL en un árbol temporal con nombre GUID, una ruptura de oplock, la eliminación con estilo POSIX del directorio leaf, la creación de un mount point dirigido a un directorio protegido de Windows y la creación o modificación del mismo basename bajo ese destino. Para el ejemplo público, añade `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, la ejecución manual de `MareBackup` y la named pipe `FALCONFLANK` como pivotes más específicos; ninguno es suficiente por sí solo.<sup>[[5]](#references)</sup>

Al reproducir el PoC, ten en cuenta tres defectos de fiabilidad del código fuente publicado: llama a `FlushFileBuffers` con el puntero al byte-array integrado en lugar del file handle, comprueba un `HRESULT` obsoleto después de `GetFolder`, `GetTask` y `Run`, y utiliza loops de retry/wait sin límite para la eliminación del directorio, la creación del reparse, el evento del oplock y la conexión de la pipe.<sup>[[5]](#references)</sup>

## Consideraciones operativas

- **Combinar primitives** – Puedes utilizar un nombre largo *por nivel* en una cadena de directorios para obtener aún más latencia hasta agotar el tamaño de `UNICODE_STRING`.
- **Bugs de un solo disparo** – La ventana ampliada (de decenas de microsegundos a minutos) hace realistas los bugs de «trigger único» cuando se combinan con fijación de afinidad de CPU o preemption asistida por hypervisor.
- **Efectos secundarios** – El slowdown solo afecta a la ruta maliciosa, por lo que el rendimiento general del sistema permanece intacto; los defenders rara vez lo notarán salvo que monitoricen el crecimiento del namespace.
- **Limpieza** – Conserva handles de cada directorio/objeto que crees para poder llamar posteriormente a `NtMakeTemporaryObject`/`NtClose`. De lo contrario, las cadenas de directorios sin límite pueden persistir tras los reinicios.
- **Races del sistema de archivos** – Si la ruta vulnerable termina resolviéndose mediante NTFS, puedes colocar un Oplock (por ejemplo, `SetOpLock.exe` del mismo toolkit) sobre el archivo subyacente mientras se ejecuta el slowdown del OM, congelando el consumer durante milisegundos adicionales sin modificar el grafo del OM.<sup>[[2]](#references)</sup>

## Notas defensivas

- El código del kernel que dependa de named objects debe volver a validar el estado sensible a la seguridad *después* de la apertura, o tomar una referencia antes de la comprobación (cerrando la ventana TOCTOU).
- Aplica límites superiores a la profundidad/longitud de las rutas del OM antes de dereferenciar nombres controlados por el usuario. Rechazar nombres excesivamente largos obliga a los atacantes a volver a la ventana de microsegundos.
- Instrumenta el crecimiento del namespace del Object Manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadenas sospechosas de miles de componentes bajo `\BaseNamedObjects`.

## References

- [1] [Project Zero – Técnicas de explotación de Windows: ganar races con búsquedas de rutas](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Cómo utilizar Transactional NTFS](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
