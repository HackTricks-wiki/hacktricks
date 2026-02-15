# Explotación de condiciones de carrera del kernel mediante rutas lentas del Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Por qué ampliar la ventana de la condición de carrera importa

Muchos LPEs del kernel de Windows siguen el patrón clásico `check_state(); NtOpenX("name"); privileged_action();`. En hardware moderno, una llamada en frío a `NtOpenEvent`/`NtOpenSection` resuelve un nombre corto en ~2 µs, dejando casi no tiempo para cambiar el estado verificado antes de que ocurra la acción privilegiada. Forzando deliberadamente que la búsqueda en el Object Manager Namespace (OMNS) del paso 2 tome decenas de microsegundos, el atacante gana suficiente tiempo para ganar de forma consistente carreras que de otro modo serían inestables sin necesitar miles de intentos.

## Detalles internos de la resolución en el Object Manager en pocas palabras

* **OMNS structure** – Nombres como `\BaseNamedObjects\Foo` se resuelven componente por componente. Cada componente obliga al kernel a localizar/abrir un *Directorio de objetos* y comparar cadenas Unicode. Se pueden atravesar enlaces simbólicos (por ejemplo, letras de unidad) en el camino.
* **UNICODE_STRING limit** – Las rutas OM se llevan dentro de un `UNICODE_STRING` cuyo `Length` es un valor de 16 bits. El límite absoluto es 65 535 bytes (32 767 puntos de código UTF-16). Con prefijos como `\BaseNamedObjects\`, un atacante aún controla ≈32 000 caracteres.
* **Attacker prerequisites** – Cualquier usuario puede crear objetos bajo directorios escribibles como `\BaseNamedObjects`. Cuando el código vulnerable usa un nombre dentro de estos, o sigue un enlace simbólico que apunte allí, el atacante controla el rendimiento de la búsqueda sin privilegios especiales.

## Primitiva de ralentización #1 – Componente único máximo

El coste de resolver un componente es aproximadamente lineal con su longitud porque el kernel debe realizar una comparación Unicode contra cada entrada en el directorio padre. Crear un evento con un nombre de 32 kB de longitud aumenta inmediatamente la latencia de `NtOpenEvent` de ~2 µs a ~35 µs en Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notas prácticas*

- Puedes alcanzar el límite de longitud usando cualquier named kernel object (events, sections, semaphores…).
- Symbolic links o reparse points pueden apuntar un nombre corto “victim” a este giant component para que the slowdown se aplique de forma transparente.
- Because everything lives in user-writable namespaces, the payload funciona desde un standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Una variante más agresiva reserva una cadena de miles de directorios (`\BaseNamedObjects\A\A\...\X`). Cada salto activa la lógica de resolución de directorios (ACL checks, hash lookups, reference counting), por lo que la latencia por nivel es mayor que la de una single string compare. Con ~16 000 niveles (limitados por el mismo tamaño `UNICODE_STRING`), los tiempos empíricos superan la barrera de 35 µs alcanzada por long single components.
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
Tips:

* Alterna el carácter por nivel (`A/B/C/...`) si el directorio padre empieza a rechazar duplicados.
* Mantén un array de handles para poder borrar la cadena limpiamente tras la explotación y evitar contaminar el namespace.

## Primitiva de ralentización #3 – Shadow directories, hash collisions & symlink reparses (minutos en lugar de microsegundos)

Los object directories soportan **shadow directories** (búsquedas de fallback) y tablas hash bucketed para las entradas. Abusa de ambos junto con el límite de 64 componentes para reparse de symlink para multiplicar la ralentización sin exceder la longitud `UNICODE_STRING`:

1. Crea dos directorios bajo `\BaseNamedObjects`, p. ej. `A` (shadow) y `A\A` (target). Crea el segundo usando el primero como shadow directory (`NtCreateDirectoryObjectEx`), de modo que las búsquedas faltantes en `A` caigan en `A\A`.
2. Llena cada directorio con miles de **colliding names** que caigan en el mismo hash bucket (p. ej., variando dígitos finales mientras se mantiene el mismo valor de `RtlHashUnicodeString`). Las búsquedas ahora degradan a escaneos lineales O(n) dentro de un único directorio.
3. Construye una cadena de ~63 **object manager symbolic links** que reparseen repetidamente hacia el largo sufijo `A\A\…`, consumiendo el presupuesto de reparse. Cada reparse reinicia el análisis desde el principio, multiplicando el coste de las colisiones.
4. La búsqueda del componente final (`...\\0`) ahora toma **minutos** en Windows 11 cuando hay 16 000 colisiones por directorio, proporcionando una victoria de race prácticamente garantizada para LPEs kernel de un solo intento.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por qué importa*: Una ralentización de minutos convierte los race-based LPEs de un solo intento en exploits deterministas.

### Notas de retest de 2025 y herramientas listas para usar

- James Forshaw republicó la técnica con tiempos actualizados en Windows 11 24H2 (ARM64). Baseline opens se mantienen en ~2 µs; un componente de 32 kB eleva esto a ~35 µs, y shadow-dir + collision + 63-reparse chains aún alcanzan ~3 minutos, confirmando que los primitives sobreviven a las builds actuales. Source code y perf harness están en la publicación actualizada de Project Zero.
- Puedes scriptar la configuración usando el bundle público `symboliclink-testing-tools`: `CreateObjectDirectory.exe` para spawnear el par shadow/target y `NativeSymlink.exe` en un bucle para emitir la cadena de 63 saltos. Esto evita wrappers `NtCreate*` escritos a mano y mantiene las ACLs consistentes.

## Midiendo tu ventana de race

Inserta un harness rápido dentro de tu exploit para medir cuánto se amplía la ventana en el hardware de la víctima. El snippet de abajo abre el objeto objetivo `iterations` veces y devuelve el coste promedio por apertura usando `QueryPerformanceCounter`.
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
Los resultados se incorporan directamente a tu estrategia de orquestación de la condición de carrera (p. ej., número de hilos necesarios, intervalos de espera, qué tan pronto necesitas cambiar el estado compartido).

## Flujo de explotación

1. **Localiza el open vulnerable** – Rastrea la ruta en el kernel (vía símbolos, ETW, trazado por hypervisor o ingeniería inversa) hasta encontrar una llamada `NtOpen*`/`ObOpenObjectByName` que recorra un nombre controlado por el atacante o un enlace simbólico en un directorio escribible por el usuario.
2. **Sustituye ese nombre por una ruta lenta**
- Crea el componente largo o la cadena de directorios bajo `\BaseNamedObjects` (u otra raíz OM escribible).
- Crea un enlace simbólico de modo que el nombre que espera el kernel ahora resuelva hacia la ruta lenta. Puedes apuntar la búsqueda de directorio del driver vulnerable a tu estructura sin tocar el objetivo original.
3. **Desencadenar la condición de carrera**
- Thread A (víctima) ejecuta el código vulnerable y queda bloqueado dentro de la búsqueda lenta.
- Thread B (atacante) cambia el estado protegido (p. ej., intercambia un handle de archivo, reescribe un enlace simbólico, alterna la seguridad del objeto) mientras Thread A está ocupado.
- Cuando Thread A se reanuda y realiza la acción privilegiada, observa un estado obsoleto y ejecuta la operación controlada por el atacante.
4. **Limpieza** – Elimina la cadena de directorios y los enlaces simbólicos para evitar dejar artefactos sospechosos o romper usuarios legítimos de IPC.

## Consideraciones operativas

- **Combina primitivas** – Puedes usar un nombre largo *por nivel* en una cadena de directorios para aumentar aún más la latencia hasta agotar el tamaño de `UNICODE_STRING`.
- **Bugs de un solo disparo** – La ventana ampliada (decenas de microsegundos a minutos) hace realistas los bugs de “single trigger” cuando se combinan con pinning de afinidad de CPU o preemptión asistida por hypervisor.
- **Efectos secundarios** – La desaceleración solo afecta la ruta maliciosa, por lo que el rendimiento general del sistema permanece sin cambios; los defensores rara vez lo notarán a menos que monitoricen el crecimiento del espacio de nombres.
- **Limpieza** – Conserva handles para cada directorio/objeto que crees para poder llamar a `NtMakeTemporaryObject`/`NtClose` después. De lo contrario, las cadenas de directorios sin límite podrían persistir tras reinicios.
- **Races en el sistema de archivos** – Si la ruta vulnerable acaba resolviéndose a través de NTFS, puedes encadenar un Oplock (p. ej., `SetOpLock.exe` del mismo toolkit) sobre el archivo subyacente mientras corre la desaceleración del OM, congelando al consumidor por milisegundos adicionales sin alterar el grafo del OM.

## Notas defensivas

- El código del kernel que depende de objetos nombrados debería revalidar el estado sensible a seguridad *después* del open, o tomar una referencia antes de la comprobación (cerrando la brecha TOCTOU).
- Aplica límites superiores en la profundidad/longitud de las rutas del OM antes de desreferenciar nombres controlados por el usuario. Rechazar nombres excesivamente largos obliga a los atacantes a volver a la ventana de microsegundos.
- Instrumenta el crecimiento del espacio de nombres del object manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadenas sospechosas de miles de componentes bajo `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
