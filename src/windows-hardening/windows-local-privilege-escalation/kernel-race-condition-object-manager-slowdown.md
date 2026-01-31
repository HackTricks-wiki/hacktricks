# Explotación de condiciones de carrera del kernel mediante rutas lentas del Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Por qué importa ampliar la ventana de la carrera

Muchas LPEs del kernel de Windows siguen el patrón clásico `check_state(); NtOpenX("name"); privileged_action();`. En hardware moderno, una llamada fría a `NtOpenEvent`/`NtOpenSection` resuelve un nombre corto en ~2 µs, dejando casi ningún tiempo para cambiar el estado verificado antes de que ocurra la acción privilegiada. Forzando deliberadamente que la búsqueda en el Object Manager Namespace (OMNS) en el paso 2 tarde decenas de microsegundos, el atacante gana tiempo suficiente para ganar consistentemente carreras que de otro modo serían inestables sin necesitar miles de intentos.

## Resumen interno de la resolución del Object Manager

* **Estructura OMNS** – Nombres como `\BaseNamedObjects\Foo` se resuelven directorio por directorio. Cada componente hace que el kernel encuentre/abra un *Object Directory* y compare cadenas Unicode. Se pueden recorrer enlaces simbólicos (p. ej., letras de unidad) en el camino.
* **Límite de UNICODE_STRING** – Las rutas del OM se transportan dentro de un `UNICODE_STRING` cuyo `Length` es un valor de 16 bits. El límite absoluto es 65 535 bytes (32 767 puntos de código UTF-16). Con prefijos como `\BaseNamedObjects\`, el atacante aún controla ≈32 000 caracteres.
* **Requisitos previos del atacante** – Cualquier usuario puede crear objetos bajo directorios que permitan escritura como `\BaseNamedObjects`. Cuando el código vulnerable usa un nombre en su interior, o sigue un enlace simbólico que apunte allí, el atacante controla el rendimiento de la búsqueda sin privilegios especiales.

## Primitiva de ralentización #1 – Componente único máximo

El coste de resolver un componente es aproximadamente lineal con su longitud porque el kernel debe realizar una comparación Unicode contra cada entrada en el directorio padre. Crear un evento con un nombre de 32 kB aumenta inmediatamente la latencia de `NtOpenEvent` de ~2 µs a ~35 µs en Windows 11 24H2 (Snapdragon X Elite testbed).
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
- Symbolic links or reparse points pueden apuntar un nombre corto “victim” a este componente gigante para que el slowdown se aplique de forma transparente.
- Como todo reside en user-writable namespaces, el payload funciona con un standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Una variante más agresiva asigna una cadena de miles de directorios (`\BaseNamedObjects\A\A\...\X`). Cada salto desencadena la lógica de resolución de directorios (ACL checks, hash lookups, reference counting), por lo que la latencia por nivel es mayor que la de una sola comparación de cadenas. Con ~16 000 niveles (limitados por el mismo `UNICODE_STRING`), los tiempos empíricos superan la barrera de 35 µs lograda por componentes largos individuales.
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
* Mantén un array de handles para poder eliminar la cadena limpiamente después de la explotación y así evitar contaminar el namespace.

## Primitiva de ralentización #3 – Shadow directories, hash collisions & symlink reparses (minutos en lugar de microsegundos)

Los directorios de objetos soportan **shadow directories** (búsquedas de fallback) y tablas hash por buckets para las entradas. Abusa de ambos junto con el límite de reparse de enlaces simbólicos de 64 componentes para multiplicar la desaceleración sin exceder la longitud de `UNICODE_STRING`:

1. Crea dos directorios bajo `\BaseNamedObjects`, p. ej. `A` (shadow) y `A\A` (target). Crea el segundo usando el primero como shadow directory (`NtCreateDirectoryObjectEx`), de modo que las búsquedas no encontradas en `A` pasen a `A\A`.
2. Llena cada directorio con miles de **colliding names** que caigan en el mismo hash bucket (p. ej., variando dígitos finales mientras se mantiene el mismo valor de `RtlHashUnicodeString`). Las búsquedas ahora degradan a escaneos lineales O(n) dentro de un solo directorio.
3. Construye una cadena de ~63 **object manager symbolic links** que vuelvan a reparsear en el largo sufijo `A\A\…`, consumiendo el presupuesto de reparse. Cada reparse reinicia el parsing desde el principio, multiplicando el coste por colisión.
4. La búsqueda del componente final (`...\\0`) ahora toma **minutos** en Windows 11 cuando hay 16 000 colisiones por directorio, ofreciendo una victoria de race prácticamente garantizada para LPEs de kernel de un solo disparo.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por qué importa*: Una ralentización de varios minutos convierte LPEs race-based de one-shot en exploits deterministas.

## Midiendo tu ventana de race

Inserta un harness rápido dentro de tu exploit para medir cuánto se amplía la ventana en el hardware de la víctima. El fragmento siguiente abre el objeto objetivo `iterations` veces y devuelve el coste medio por apertura usando `QueryPerformanceCounter`.
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
Los resultados alimentan directamente tu estrategia de orquestación de la condición de carrera (p. ej., número de hilos de trabajo necesarios, intervalos de espera, cuán pronto necesitas cambiar el estado compartido).

## Exploitation workflow

1. **Locate the vulnerable open** – Traza la ruta del kernel (via symbols, ETW, hypervisor tracing, or reversing) hasta encontrar una llamada `NtOpen*`/`ObOpenObjectByName` que recorra un nombre controlado por el atacante o un enlace simbólico en un directorio escribible por el usuario.
2. **Replace that name with a slow path**
- Crea el componente largo o la cadena de directorios bajo `\BaseNamedObjects` (o otra raíz OM escribible).
- Crea un enlace simbólico de modo que el nombre que espera el kernel ahora resuelva a la ruta lenta. Puedes apuntar la búsqueda de directorio del driver vulnerable a tu estructura sin tocar el objetivo original.
3. **Trigger the race**
- Hilo A (víctima) ejecuta el código vulnerable y se bloquea dentro de la búsqueda lenta.
- Hilo B (atacante) cambia el estado protegido (p. ej., intercambia un handle de archivo, reescribe un enlace simbólico, alterna la seguridad del objeto) mientras Hilo A está ocupado.
- Cuando Hilo A se reanuda y realiza la acción privilegiada, observa estado obsoleto y ejecuta la operación controlada por el atacante.
4. **Clean up** – Elimina la cadena de directorios y los enlaces simbólicos para evitar dejar artefactos sospechosos o romper usuarios legítimos de IPC.

## Operational considerations

- **Combine primitives** – Puedes usar un nombre largo *por nivel* en una cadena de directorios para aumentar aún más la latencia hasta agotar el tamaño de `UNICODE_STRING`.
- **One-shot bugs** – La ventana ampliada (decenas de microsegundos a minutos) hace realistas los bugs de “single trigger” cuando se combinan con CPU affinity pinning o hypervisor-assisted preemption.
- **Side effects** – La ralentización solo afecta la ruta maliciosa, por lo que el rendimiento general del sistema permanece sin cambios; los defensores rara vez lo notarán a menos que supervisen el crecimiento del namespace.
- **Cleanup** – Mantén handles de cada directorio/objeto que crees para poder llamar a `NtMakeTemporaryObject`/`NtClose` después. De lo contrario, cadenas de directorios sin límite pueden persistir tras reinicios.

## Defensive notes

- El código del kernel que depende de objetos nombrados debería revalidar el estado sensible a seguridad *después* del open, o tomar una referencia antes de la comprobación (cerrando la brecha TOCTOU).
- Imponer límites superiores en la profundidad/longitud de la ruta OM antes de desreferenciar nombres controlados por el usuario. Rechazar nombres excesivamente largos obliga a los atacantes a volver a la ventana de microsegundos.
- Instrumenta el crecimiento del namespace del object manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadenas sospechosas de miles de componentes bajo `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
