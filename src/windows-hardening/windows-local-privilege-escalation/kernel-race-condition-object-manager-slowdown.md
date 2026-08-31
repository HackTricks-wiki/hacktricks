# Explotación de una Race Condition del kernel mediante Slow Paths del Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Por qué es importante ampliar la ventana de la race

Muchas LPE del kernel de Windows siguen el patrón clásico `check_state(); NtOpenX("name"); privileged_action();`. En hardware moderno, un `NtOpenEvent`/`NtOpenSection` en frío resuelve un nombre corto en ~2 µs, dejando muy poco tiempo para modificar el estado comprobado antes de que se ejecute la acción privilegiada. Al forzar deliberadamente que la búsqueda del Object Manager Namespace (OMNS) del paso 2 tarde decenas de microsegundos, el atacante obtiene tiempo suficiente para ganar de forma consistente races que, de otro modo, serían inestables, sin necesitar miles de intentos.<sup>[[1]](#references)</sup>

## Internals de la búsqueda del Object Manager en pocas palabras

* **Estructura del OMNS** – Los nombres como `\BaseNamedObjects\Foo` se resuelven directorio por directorio. Cada componente hace que el kernel busque o abra un *Object Directory* y compare cadenas Unicode. Los symbolic links (por ejemplo, las letras de unidad) pueden recorrerse durante el proceso.
* **Límite de `UNICODE_STRING`** – Las rutas del OM se almacenan en una `UNICODE_STRING` cuyo campo `Length` es un valor de 16 bits. El límite absoluto es de 65 535 bytes (32 767 codepoints UTF-16). Con prefijos como `\BaseNamedObjects\`, el atacante aún controla ≈32 000 caracteres.
* **Requisitos del atacante** – Cualquier usuario puede crear objetos dentro de directorios escribibles como `\BaseNamedObjects`. Cuando el código vulnerable usa un nombre situado allí o sigue un symbolic link que termina en ese directorio, el atacante controla el rendimiento de la búsqueda sin privilegios especiales.<sup>[[1]](#references)</sup>

## Primitiva de slowdown n.º 1 – Componente único máximo

El coste de resolver un componente es aproximadamente lineal con su longitud, porque el kernel debe realizar una comparación Unicode con cada entrada del directorio padre. Crear un event con un nombre de 32 kB aumenta inmediatamente la latencia de `NtOpenEvent` de ~2 µs a ~35 µs en Windows 11 24H2 (testbed Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notas prácticas*

- Puedes alcanzar el límite de longitud usando cualquier objeto del kernel con nombre (eventos, secciones, semáforos…).
- Los enlaces simbólicos o los puntos de análisis pueden apuntar un nombre corto de “víctima” a este componente gigante, de modo que la ralentización se aplique de forma transparente.
- Como todo reside en namespaces modificables por el usuario, el payload funciona desde un nivel de integridad de usuario estándar.<sup>[[1]](#references)</sup>

## Primitiva de ralentización n.º 2 – Directorios recursivos profundos

Una variante más agresiva asigna una cadena de miles de directorios (`\BaseNamedObjects\A\A\...\X`). Cada salto activa la lógica de resolución de directorios (comprobaciones de ACL, búsquedas hash, recuento de referencias), por lo que la latencia por nivel es mayor que la de una única comparación de cadenas. Con unos 16 000 niveles (limitados por el mismo tamaño de `UNICODE_STRING`), las mediciones empíricas superan la barrera de 35 µs alcanzada mediante componentes individuales largos.
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
* Mantén un array de handles para poder eliminar la cadena correctamente después de la explotación y evitar contaminar el namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Directorios shadow, colisiones de hash y reparses de symlink (minutos en lugar de microsegundos)

Los directorios del Object Manager admiten **shadow directories** (búsquedas alternativas) y tablas hash agrupadas para las entradas. Abusa de ambos mecanismos, junto con el límite de 64 componentes de reparse de symbolic links, para multiplicar la ralentización sin superar la longitud de `UNICODE_STRING`:

1. Crea dos directorios bajo `\BaseNamedObjects`, por ejemplo, `A` (shadow) y `A\A` (target). Crea el segundo usando el primero como shadow directory (`NtCreateDirectoryObjectEx`), de modo que las búsquedas inexistentes en `A` continúen en `A\A`.
2. Llena cada directorio con miles de **nombres con colisiones** que terminen en el mismo bucket de hash (por ejemplo, variando los dígitos finales mientras mantienes el mismo valor de `RtlHashUnicodeString`). Las búsquedas pasan a degradarse a exploraciones lineales O(n) dentro de un único directorio.
3. Construye una cadena de aproximadamente 63 **symbolic links del Object Manager** que vuelvan a analizar repetidamente el sufijo largo `A\A\…`, consumiendo el presupuesto de reparses. Cada reparse reinicia el análisis desde el principio, multiplicando el coste de las colisiones.
4. La búsqueda del componente final (`...\\0`) tarda ahora **minutos** en Windows 11 cuando hay 16 000 colisiones por directorio, lo que proporciona una victoria de race prácticamente garantizada para ataques de kernel LPE de un solo intento.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por qué importa*: Una ralentización de varios minutos convierte los LPE basados en race de una sola oportunidad en exploits deterministas.<sup>[[1]](#references)</sup>

### Notas de la repetición de pruebas de 2025 y tooling listo para usar

- James Forshaw volvió a publicar la técnica con tiempos actualizados en Windows 11 24H2 (ARM64). Las aperturas de referencia siguen siendo de ~2 µs; un componente de 32 kB eleva este valor a ~35 µs, y las cadenas shadow-dir + colisión + 63-reparse todavía alcanzan ~3 minutos, lo que confirma que las primitivas siguen funcionando en las builds actuales. El código fuente y el arnés de rendimiento se encuentran en la publicación actualizada de Project Zero.<sup>[[1]](#references)</sup>
- Puedes automatizar la configuración mediante el bundle público `symboliclink-testing-tools`: `CreateObjectDirectory.exe` para crear el par shadow/target y `NativeSymlink.exe` en un bucle para generar la cadena de 63 saltos. Esto evita escribir manualmente wrappers de `NtCreate*` y mantiene las ACLs coherentes.<sup>[[2]](#references)</sup>

## Medición de tu race window

Integra un arnés rápido en tu exploit para medir cuánto aumenta la ventana en el hardware de la víctima. El snippet siguiente abre el objeto objetivo `iterations` veces y devuelve el coste medio por apertura mediante `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Los resultados alimentan directamente tu estrategia de orquestación de la race (por ejemplo, el número de worker threads necesarios, los intervalos de sleep y con cuánta antelación debes cambiar el estado compartido).

## Flujo de explotación

1. **Localiza la apertura vulnerable** – Rastrea la ruta del kernel (mediante símbolos, ETW, hypervisor tracing o reversing) hasta encontrar una llamada `NtOpen*`/`ObOpenObjectByName` que recorra un nombre controlado por el atacante o un symbolic link en un directorio con permisos de escritura para el usuario.
2. **Sustituye ese nombre por una ruta lenta**
- Crea el componente largo o la cadena de directorios bajo `\BaseNamedObjects` (u otra raíz del OM con permisos de escritura).
- Crea un symbolic link para que el nombre que espera el kernel ahora resuelva a la ruta lenta. Puedes redirigir la búsqueda de directorios del driver vulnerable hacia tu estructura sin tocar el objetivo original.
3. **Trigger the race**
- Thread A (víctima) ejecuta el código vulnerable y queda bloqueado dentro de la búsqueda lenta.
- Thread B (atacante) cambia el estado protegido (por ejemplo, intercambia un file handle, reescribe un symbolic link o alterna la seguridad del objeto) mientras Thread A está ocupado.
- Cuando Thread A se reanuda y realiza la acción privilegiada, observa un estado obsoleto y ejecuta la operación controlada por el atacante.
4. **Limpia** – Elimina la cadena de directorios y los symbolic links para no dejar artefactos sospechosos ni romper usuarios legítimos de IPC.<sup>[[1]](#references)</sup>

## Cadena aplicada: placeholders mutables de Cloud Files + cambio de rutas del Object Manager

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), publicado como bypass para RoguePlanet (CVE-2026-50656), demuestra un patrón de explotación más amplio: hacer que un scanner privilegiado clasifique una representación de un archivo lógico y, después, cambiar tanto sus bytes como la resolución de su namespace antes de que la remediación lo utilice. El PoC combina un TOCTOU de hydration de Cloud Files, un fallback de shadow-directory del Object Manager, la captura de nombres generados por CLFS y un link a un administrative share local para convertir la limpieza de Defender en una escritura de DLL protegida.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Sustituir el contenido mediante la hydration de Cloud Files

Registra un directorio con permisos de escritura para el atacante como sync root de Cloud Files, conecta un callback `CF_CALLBACK_TYPE_FETCH_DATA` y crea un placeholder cuyo tamaño anunciado coincida con un trigger de detección determinista, como el EICAR ZIP. El primer fetch devuelve el trigger y cambia el estado del callback; los fetch posteriores devuelven el payload. Después de que el scanner haya clasificado la primera representación, obtén la transfer key y reinicia la hydration con metadata del tamaño del payload; después, fuerza la hydration hasta EOF.<sup>[[4]](#references)</sup>
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
El límite de seguridad falla si el escaneo, el veredicto y la remediación solo hacen referencia a un nombre de ruta o a una identidad de marcador de posición: ninguno garantiza que una hidratación posterior devuelva los bytes que se inspeccionaron.<sup>[[4]](#references)</sup>

### 2. Cambiar una ruta invariable mediante un fallback de shadow-directory

Crea un directorio de Object Manager de destino y un segundo directorio con `NtCreateDirectoryObjectEx`, pasando el handle del destino como su directorio de shadow/fallback. Coloca una entrada `WD_SCAN` con el mismo nombre en ambas capas de resolución: la entrada visible apunta al directorio de trabajo normal, mientras que la entrada de fallback apunta a `\CLFS\??\<working-directory>`. Proporciona a Defender únicamente la ruta invariable indicada a continuación; eliminar el enlace visible mientras la operación está activa hace que la misma cadena continúe hacia la entrada respaldada por CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Esto es distinto de usar únicamente shadow directories para ralentizar la búsqueda: el atacante cambia el **significado** de una ruta aceptada previamente sin modificar su cadena.<sup>[[4]](#references)</sup>

### 3. Capturar el nombre generado e instalar un enlace específico para el nombre de archivo

Monitoriza el directorio de trabajo con `ReadDirectoryChangesW`. En el primer `FILE_ACTION_ADDED`, elimina el enlace visible `WD_SCAN` para activar la búsqueda de respaldo. Captura el segundo nombre de archivo generado, abre ese archivo relacionado con CLFS y bloquea el rango `0..MAXLONGLONG` con `LockFileEx`. Mientras la operación privilegiada está detenida, reemplaza `WD_SCAN` en el directorio visible por un directorio real de Object Manager y crea un enlace simbólico hijo cuyo nombre se base en el nombre de archivo observado (el PoC elimina sus cuatro caracteres finales). Apúntalo al destino protegido mediante SMB local:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
El proceso sin privilegios no puede escribir por sí mismo en ese destino, pero el contexto SYSTEM de Defender puede atravesar el recurso administrativo de loopback. Combinar la observación de nombres generados con un enlace de Object Manager específico para el nombre de archivo evita tener que predecir de antemano el artefacto de remediación.<sup>[[4]](#references)</sup>

### 4. Estabilizar la race de limpieza y activar un loader privilegiado

Antes del scanning, el PoC almacena un PE válido (`ntdll.dll`) en el NTFS alternate data stream `:stream` del placeholder. Después de que la redirección crea el archivo base protegido, abre `phoneinfo.dll:stream` con acceso de ejecución y mantiene activo un mapping `PAGE_EXECUTE_READ | SEC_IMAGE` mientras se reanuda la limpieza; los objetos de archivo/sección activos limitan la eliminación o sustitución durante la race final. La hydration reiniciada ahora devuelve la payload DLL en lugar de EICAR, por lo que el archivo base protegido contiene código controlado por el atacante.<sup>[[4]](#references)</sup>

A continuación, una escritura protegida se convierte en ejecución SYSTEM colocando un `Report.wer` diseñado bajo `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` e invocando `\Microsoft\Windows\Windows Error Reporting\QueueReporting` mediante la Task Scheduler COM API. En esta cadena, el procesamiento privilegiado de WER carga la DLL plantada `C:\Windows\System32\phoneinfo.dll`; una conexión de named pipe se utiliza como señal de ejecución de la payload.<sup>[[4]](#references)</sup>

### Pivotes de detección

Las correlaciones útiles son más específicas que cualquier filename temporal individual y cubren todas las transiciones de namespace de la cadena:<sup>[[4]](#references)</sup>

- Un proveedor de Cloud Files registrado recientemente, seguido de la detección de EICAR y `CF_OPERATION_TYPE_RESTART_HYDRATION` en el mismo placeholder.
- Rutas de Object Manager que contienen `WD_TARGET_*`, `WD_SHADOW_*` o `WD_SCAN`, especialmente una ruta de scanning bajo `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Creación de archivos CLFS seguida de un exclusive whole-file lock y acceso de loopback a `\\127.0.0.1\C$\Windows\System32\*.dll` desde un security process privilegiado.
- Creación de una DLL en System32 junto con un NTFS ADS, seguida de un mapping `SEC_IMAGE` del stream.
- Una entrada de la cola de WER creada por el atacante, seguida de una ejecución manual inusual de `\Microsoft\Windows\Windows Error Reporting\QueueReporting` y de la carga de una image de la DLL plantada.

## Consideraciones operativas

- **Combinar primitives** – Puedes utilizar un nombre largo *por nivel* en una cadena de directorios para obtener una latencia aún mayor hasta agotar el tamaño de `UNICODE_STRING`.
- **Bugs de un solo intento** – La ventana ampliada (de decenas de microsegundos a minutos) hace realistas los bugs de “single trigger” cuando se combinan con CPU affinity pinning o preemption asistida por hypervisor.
- **Efectos secundarios** – El slowdown solo afecta a la ruta maliciosa, por lo que el rendimiento general del sistema permanece inalterado; los defenders rara vez lo notarán salvo que monitoricen el crecimiento del namespace.
- **Limpieza** – Conserva handles de cada directorio/objeto que crees para poder llamar después a `NtMakeTemporaryObject`/`NtClose`. De lo contrario, las cadenas de directorios sin límites podrían persistir tras los reinicios.
- **Races del file-system** – Si la ruta vulnerable finalmente se resuelve mediante NTFS, puedes colocar un Oplock (por ejemplo, `SetOpLock.exe` del mismo toolkit) sobre el archivo subyacente mientras se ejecuta el slowdown de OM, congelando el consumer durante milisegundos adicionales sin alterar el grafo de OM.<sup>[[2]](#references)</sup>

## Notas defensivas

- El código del kernel que dependa de objetos con nombre debe volver a validar el estado sensible a la seguridad *después* de la apertura, o tomar una referencia antes de la comprobación (cerrando la brecha TOCTOU).
- Aplica límites superiores a la profundidad/longitud de las rutas de OM antes de dereferenciar nombres controlados por el usuario. Rechazar nombres excesivamente largos obliga a los atacantes a volver a la ventana de microsegundos.
- Instrumenta el crecimiento del namespace del object manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadenas sospechosas de miles de componentes bajo `\BaseNamedObjects`.

## References

- [1] [Project Zero – Técnicas de explotación de Windows: ganar races con búsquedas de rutas](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
