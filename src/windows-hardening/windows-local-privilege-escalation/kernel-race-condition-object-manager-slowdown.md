# Explotación de condiciones de carrera del kernel mediante rutas lentas del Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Por qué ampliar la ventana de la condición de carrera es importante

Muchas LPEs del kernel de Windows siguen el patrón clásico `check_state(); NtOpenX("name"); privileged_action();`. En hardware moderno un `NtOpenEvent`/`NtOpenSection` en frío resuelve un nombre corto en ~2 µs, dejando casi ningún tiempo para cambiar el estado verificado antes de que ocurra la acción privilegiada. Forzando deliberadamente que la búsqueda en el Object Manager Namespace (OMNS) en el paso 2 tome decenas de microsegundos, el atacante obtiene suficiente tiempo para ganar de forma consistente carreras que de otro modo serían inestables sin necesitar miles de intentos.

## Internos de la resolución del Object Manager en pocas palabras

* **OMNS structure** – Nombres como `\BaseNamedObjects\Foo` se resuelven directorio por directorio. Cada componente hace que el kernel encuentre/abra un *Object Directory* y compare cadenas Unicode. Pueden recorrerse enlaces simbólicos (p. ej., letras de unidad) en el trayecto.
* **UNICODE_STRING limit** – Las rutas del OM se transportan dentro de un `UNICODE_STRING` cuyo `Length` es un valor de 16 bits. El límite absoluto es 65 535 bytes (32 767 puntos de código UTF-16). Con prefijos como `\BaseNamedObjects\`, un atacante aún controla ≈32 000 caracteres.
* **Attacker prerequisites** – Cualquier usuario puede crear objetos bajo directorios escribibles como `\BaseNamedObjects`. Cuando el código vulnerable usa un nombre dentro de ese directorio, o sigue un enlace simbólico que termina allí, el atacante controla el rendimiento de la búsqueda sin privilegios especiales.

## Primitiva de ralentización #1 – Componente único máximo

El coste de resolver un componente es aproximadamente lineal con su longitud porque el kernel debe realizar una comparación Unicode contra cada entrada en el directorio padre. Crear un evento con un nombre de 32 kB aumenta inmediatamente la latencia de `NtOpenEvent` de ~2 µs a ~35 µs en Windows 11 24H2 (banco de pruebas Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notas prácticas*

- Puedes alcanzar el límite de longitud usando cualquier objeto kernel con nombre (events, sections, semaphores…).
- Los enlaces simbólicos o reparse points pueden apuntar un nombre corto de “víctima” a este componente gigante para que la ralentización se aplique de forma transparente.
- Dado que todo vive en namespaces escribibles por el usuario, el payload funciona desde un nivel de integridad de usuario estándar.

## Slowdown primitive #2 – Deep recursive directories

Una variante más agresiva asigna una cadena de miles de directorios (`\BaseNamedObjects\A\A\...\X`). Cada salto desencadena la lógica de resolución de directorios (ACL checks, hash lookups, reference counting), por lo que la latencia por nivel es mayor que la de una única comparación de cadenas. Con ~16 000 niveles (limitado por el mismo tamaño de `UNICODE_STRING`), los tiempos empíricos superan la barrera de 35 µs alcanzada por componentes únicos largos.
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
* Mantén un arreglo de handles para que puedas eliminar la cadena limpiamente después de la explotación y evitar contaminar el namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutos en lugar de microsegundos)

Object directories support **shadow directories** (búsquedas alternativas) and bucketed hash tables for entries. Abuse both plus the 64-component symbolic-link reparse limit to multiply slowdown without exceeding the `UNICODE_STRING` length:

1. Crea dos directorios bajo `\BaseNamedObjects`, p. ej. `A` (shadow) y `A\A` (target). Crea el segundo usando el primero como el shadow directory (`NtCreateDirectoryObjectEx`), de modo que las búsquedas que no existan en `A` se deriven a `A\A`.
2. Llena cada directorio con miles de **colliding names** que caigan en el mismo hash bucket (por ejemplo, variando dígitos finales mientras se mantiene el mismo valor de `RtlHashUnicodeString`). Las búsquedas ahora se degradan a barridos lineales O(n) dentro de un solo directorio.
3. Construye una cadena de ~63 **object manager symbolic links** que reparsen repetidamente hacia el largo sufijo `A\A\…`, consumiendo el reparse budget. Cada reparse reinicia el parsing desde arriba, multiplicando el coste de las collisions.
4. La búsqueda del componente final (`...\\0`) ahora toma **minutos** en Windows 11 cuando 16 000 collisions están presentes por directorio, proporcionando una victoria en la carrera prácticamente garantizada para one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por qué importa*: Una ralentización de varios minutos convierte los one-shot race-based LPEs en exploits deterministas.

## Measuring your race window

Incorpora un pequeño harness dentro de tu exploit para medir cuánto crece la ventana en el hardware de la víctima. El snippet a continuación abre el objeto objetivo `iterations` veces y devuelve el coste medio por apertura usando `QueryPerformanceCounter`.
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
The results feed directly into your race orchestration strategy (e.g., number of worker threads needed, sleep intervals, how early you need to flip the shared state).

## Exploitation workflow

1. **Locate the vulnerable open** – Traza la ruta del kernel (vía symbols, ETW, hypervisor tracing, o reversing) hasta encontrar una llamada `NtOpen*`/`ObOpenObjectByName` que recorra un nombre controlado por el atacante o un symbolic link en un directorio escribible por el usuario.
2. **Replace that name with a slow path**
- Crea el componente largo o la cadena de directorios bajo `\BaseNamedObjects` (u otra OM root escribible).
- Crea un symbolic link de modo que el nombre que el kernel espera ahora se resuelva al slow path. Puedes apuntar la directory lookup del driver vulnerable a tu estructura sin tocar el objetivo original.
3. **Trigger the race**
- Thread A (victim) ejecuta el código vulnerable y se bloquea dentro del slow lookup.
- Thread B (attacker) flips the guarded state (p. ej., swaps a file handle, rewrites a symbolic link, toggles object security) mientras Thread A está ocupado.
- Cuando Thread A se reanuda y realiza la acción privilegiada, observa un estado stale y ejecuta la operación controlada por el atacante.
4. **Clean up** – Elimina la cadena de directorios y los symbolic links para evitar dejar artefactos sospechosos o romper usuarios legítimos de IPC.

## Operational considerations

- **Combine primitives** – Puedes usar un nombre largo *por nivel* en una cadena de directorios para lograr una latencia aún mayor hasta agotar el tamaño de `UNICODE_STRING`.
- **One-shot bugs** – La ventana ampliada (decenas de microsegundos a minutos) hace que bugs de “single trigger” sean realistas cuando se combinan con CPU affinity pinning o hypervisor-assisted preemption.
- **Side effects** – La slowdown solo afecta el malicious path, por lo que el rendimiento general del sistema permanece sin cambios; los defensores raramente notarán a menos que monitoreen el crecimiento del namespace.
- **Cleanup** – Mantén handles a cada directorio/objeto que crees para poder llamar a `NtMakeTemporaryObject`/`NtClose` después. Las cadenas de directorios sin límite pueden persistir tras reinicios si no se limpian.

## Defensive notes

- El código del kernel que depende de named objects debería revalidar el estado sensible a seguridad *después* del open, o tomar una referencia antes de la verificación (cerrando la brecha TOCTOU).
- Impone límites superiores en la profundidad/longitud del OM path antes de desreferenciar nombres controlados por el usuario. Rechazar nombres excesivamente largos obliga a los atacantes a volver a la ventana de microsegundos.
- Instrumenta el crecimiento del namespace del object manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadenas sospechosas de miles de componentes bajo `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
