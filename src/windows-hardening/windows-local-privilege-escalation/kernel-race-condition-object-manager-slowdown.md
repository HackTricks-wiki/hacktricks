# Explotación de condiciones de carrera del kernel mediante rutas lentas del Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Por qué ampliar la ventana de la condición de carrera es importante

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. En hardware moderno un `NtOpenEvent`/`NtOpenSection` con caché fría resuelve un nombre corto en ~2 µs, dejando casi ningún tiempo para cambiar el estado comprobado antes de que ocurra la acción segura. Al forzar deliberadamente que la búsqueda en el Object Manager Namespace (OMNS) en el paso 2 tarde decenas de microsegundos, el atacante obtiene tiempo suficiente para ganar consistentemente carreras poco fiables sin necesitar miles de intentos.

## Funcionamiento interno de la resolución del Object Manager, en pocas palabras

* **OMNS structure** – Nombres como `\BaseNamedObjects\Foo` se resuelven directorio por directorio. Cada componente hace que el kernel encuentre/abra un *Object Directory* y compare cadenas Unicode. Se pueden atravesar enlaces simbólicos (p. ej., letras de unidad) en la ruta.
* **UNICODE_STRING limit** – Las rutas OM se transportan dentro de un `UNICODE_STRING` cuyo `Length` es un valor de 16 bits. El límite absoluto es 65 535 bytes (32 767 codepoints UTF-16). Con prefijos como `\BaseNamedObjects\`, un atacante aún controla ≈32 000 caracteres.
* **Attacker prerequisites** – Cualquier usuario puede crear objetos bajo directorios escribibles como `\BaseNamedObjects`. Cuando el código vulnerable usa un nombre dentro de ellos, o sigue un enlace simbólico que apunte ahí, el atacante controla el rendimiento de la resolución sin privilegios especiales.

## Slowdown primitive #1 – Single maximal component

El coste de resolver un componente es aproximadamente lineal con su longitud porque el kernel debe realizar una comparación Unicode contra cada entrada en el directorio padre. Crear un evento con un nombre de 32 kB incrementa inmediatamente la latencia de `NtOpenEvent` de ~2 µs a ~35 µs en Windows 11 24H2 (Snapdragon X Elite testbed).
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
- Symbolic links or reparse points can point a short “victim” name to this giant component so the slowdown is applied transparently.
- Because everything lives in user-writable namespaces, the payload works from a standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Una variante más agresiva asigna una cadena de miles de directorios (`\BaseNamedObjects\A\A\...\X`). Cada salto dispara la lógica de resolución de directorios (ACL checks, hash lookups, reference counting), por lo que la latencia por nivel es mayor que la de una única comparación de cadenas. Con ~16 000 niveles (limitados por el mismo `UNICODE_STRING`), los tiempos empíricos superan la barrera de 35 µs alcanzada por componentes únicos largos.
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

* Alterna el carácter por nivel (`A/B/C/...`) si el directorio padre comienza a rechazar duplicados.
* Mantén un handle array para que puedas eliminar la cadena limpiamente después de la explotación y evitar contaminar el namespace.

## Midiendo tu ventana de la condición de carrera

Inserta un pequeño harness dentro de tu exploit para medir cuánto se amplía la ventana en el hardware de la víctima. El fragmento abajo abre el objeto objetivo `iterations` veces y devuelve el costo promedio por apertura usando `QueryPerformanceCounter`.
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
Los resultados se incorporan directamente a tu estrategia de orquestación de race (p. ej., número de hilos necesarios, intervalos de espera, cuán pronto necesitas cambiar el estado compartido).

## Flujo de explotación

1. **Locate the vulnerable open** – Traza la ruta del kernel (vía símbolos, ETW, hypervisor tracing, o reversing) hasta encontrar una llamada `NtOpen*`/`ObOpenObjectByName` que recorra un nombre controlado por el atacante o un symbolic link en un directorio escribible por el usuario.
2. **Replace that name with a slow path**
- Crea el componente largo o la cadena de directorios bajo `\BaseNamedObjects` (o otra raíz OM escribible).
- Crea un symbolic link de modo que el nombre que espera el kernel ahora resuelva a la ruta lenta. Puedes apuntar la búsqueda de directorio del driver vulnerable a tu estructura sin tocar el objetivo original.
3. **Trigger the race**
- Thread A (victim) ejecuta el código vulnerable y se bloquea dentro de la slow lookup.
- Thread B (attacker) cambia el guarded state (p. ej., intercambia un file handle, reescribe un symbolic link, alterna la security del objeto) mientras Thread A está ocupado.
- Cuando Thread A se reanuda y realiza la acción privilegiada, observa estado obsoleto y ejecuta la operación controlada por el atacante.
4. **Clean up** – Borra la cadena de directorios y los symbolic links para evitar dejar artefactos sospechosos o romper usuarios legítimos de IPC.

## Consideraciones operativas

- **Combine primitives** – Puedes usar un nombre largo *por nivel* en una cadena de directorios para aumentar aún más la latencia hasta agotar el tamaño de `UNICODE_STRING`.
- **One-shot bugs** – La ventana ampliada (decenas de microsegundos) hace que los bugs de “single trigger” sean realistas cuando se combinan con CPU affinity pinning o hypervisor-assisted preemption.
- **Side effects** – El slowdown solo afecta la ruta maliciosa, por lo que el rendimiento general del sistema no se ve afectado; los defensores rara vez notarán algo a menos que monitoricen el crecimiento del namespace.
- **Cleanup** – Mantén handles de cada directorio/objeto que crees para poder llamar a `NtMakeTemporaryObject`/`NtClose` después. De lo contrario, las cadenas de directorios sin límite pueden persistir tras reinicios.

## Notas defensivas

- El código del kernel que depende de objetos nombrados debería revalidar el estado sensible a la seguridad *después* del open, o tomar una referencia antes de la comprobación (cerrando la brecha TOCTOU).
- Impone límites superiores en la profundidad/longitud de rutas OM antes de desreferenciar nombres controlados por el usuario. Rechazar nombres excesivamente largos obliga a los atacantes de nuevo a la ventana de microsegundos.
- Instrumenta el crecimiento del namespace del object manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadenas sospechosas de miles de componentes bajo `\BaseNamedObjects`.

## Referencias

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
