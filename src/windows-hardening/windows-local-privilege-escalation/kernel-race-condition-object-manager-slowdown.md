# Explotación de una Race Condition del Kernel mediante Slow Paths del Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Por qué es importante ampliar la ventana de la race

Muchas LPE del kernel de Windows siguen el patrón clásico `check_state(); NtOpenX("name"); privileged_action();`. En hardware moderno, un `NtOpenEvent`/`NtOpenSection` en frío resuelve un nombre corto en aproximadamente 2 µs, dejando casi nada de tiempo para cambiar el estado comprobado antes de que se produzca la acción privilegiada. Al forzar deliberadamente que la búsqueda del Object Manager Namespace (OMNS) del paso 2 tarde decenas de microsegundos, el atacante obtiene tiempo suficiente para ganar de forma consistente races que, de otro modo, serían inestables, sin necesitar miles de intentos.<sup>[[1]](#references)</sup>

## Internals de la búsqueda del Object Manager en pocas palabras

* **Estructura del OMNS** – Los nombres como `\BaseNamedObjects\Foo` se resuelven directorio por directorio. Cada componente hace que el kernel encuentre/abra un *Object Directory* y compare cadenas Unicode. Los Symbolic links (por ejemplo, las letras de unidad) pueden atravesarse durante el proceso.
* **Límite de UNICODE_STRING** – Las rutas del OM se almacenan en una `UNICODE_STRING` cuyo `Length` es un valor de 16 bits. El límite absoluto es de 65 535 bytes (32 767 codepoints UTF-16). Con prefijos como `\BaseNamedObjects\`, el atacante todavía controla aproximadamente 32 000 caracteres.
* **Requisitos del atacante** – Cualquier usuario puede crear objetos dentro de directorios con permisos de escritura, como `\BaseNamedObjects`. Cuando el código vulnerable utiliza un nombre situado ahí, o sigue un symbolic link que termina allí, el atacante controla el rendimiento de la búsqueda sin privilegios especiales.<sup>[[1]](#references)</sup>

## Primitive de ralentización n.º 1 – Componente único maximal

El coste de resolver un componente es aproximadamente lineal respecto a su longitud, porque el kernel debe realizar una comparación Unicode con cada entrada del directorio padre. Crear un evento con un nombre de 32 kB aumenta inmediatamente la latencia de `NtOpenEvent` de aproximadamente 2 µs a aproximadamente 35 µs en Windows 11 24H2 (entorno de pruebas Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notas prácticas*

- Puedes alcanzar el límite de longitud usando cualquier kernel object con nombre (events, sections, semaphores…).
- Los symbolic links o reparse points pueden apuntar desde un nombre corto de “victim” a este componente gigante, de modo que la ralentización se aplica de forma transparente.
- Como todo reside en namespaces modificables por el usuario, el payload funciona desde un nivel de integridad de usuario estándar.<sup>[[1]](#references)</sup>

## Primitiva de ralentización n.º 2 – Directorios recursivos profundos

Una variante más agresiva asigna una cadena de miles de directorios (`\BaseNamedObjects\A\A\...\X`). Cada salto activa la lógica de resolución de directorios (comprobaciones de ACL, búsquedas hash, conteo de referencias), por lo que la latencia por nivel es mayor que la de una única comparación de cadenas. Con unos 16 000 niveles (limitados por el mismo tamaño de `UNICODE_STRING`), las mediciones empíricas superan la barrera de 35 µs alcanzada mediante componentes individuales largos.
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

* Alterna el carácter por nivel (`A/B/C/...`) si el directorio principal empieza a rechazar duplicados.
* Mantén un array de handles para poder eliminar la cadena limpiamente después de la explotación y evitar contaminar el namespace.<sup>[[1]](#references)</sup>

## Primitiva de slowdown n.º 3 – Shadow directories, hash collisions y symlink reparses (minutos en lugar de microsegundos)

Los directorios de Object Manager admiten **shadow directories** (búsquedas de fallback) y tablas hash organizadas en buckets para las entradas. Abusa de ambos mecanismos, junto con el límite de 64 componentes de reparse de symbolic links, para multiplicar el slowdown sin superar la longitud de `UNICODE_STRING`:

1. Crea dos directorios bajo `\BaseNamedObjects`, por ejemplo `A` (shadow) y `A\A` (target). Crea el segundo usando el primero como shadow directory (`NtCreateDirectoryObjectEx`), de modo que las búsquedas inexistentes en `A` continúen en `A\A`.
2. Rellena cada directorio con miles de **colliding names** que terminen en el mismo hash bucket (por ejemplo, variando los dígitos finales mientras mantienes el mismo valor de `RtlHashUnicodeString`). Las búsquedas se degradan a scans lineales O(n) dentro de un solo directorio.
3. Construye una cadena de aproximadamente 63 **symbolic links de Object Manager** que hagan reparse repetidamente hacia el sufijo largo `A\A\…`, consumiendo el presupuesto de reparse. Cada reparse reinicia el parsing desde el principio, multiplicando el coste de las colisiones.
4. La búsqueda del componente final (`...\\0`) tarda ahora **minutos** en Windows 11 cuando hay 16 000 colisiones por directorio, lo que proporciona una victoria de race prácticamente garantizada para kernel LPEs de un solo intento.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Por qué importa*: Una ralentización de varios minutos convierte los LPEs basados en race de exploits de una sola oportunidad en exploits deterministas.<sup>[[1]](#references)</sup>

### Notas de las pruebas de 2025 y tooling listo para usar

- James Forshaw volvió a publicar la técnica con timings actualizados en Windows 11 24H2 (ARM64). Las aperturas baseline siguen siendo de ~2 µs; un componente de 32 kB eleva este valor a ~35 µs, y las cadenas shadow-dir + collision + 63-reparse todavía alcanzan ~3 minutos, lo que confirma que las primitivas sobreviven en las builds actuales. El código fuente y el perf harness están en el post actualizado de Project Zero.<sup>[[1]](#references)</sup>
- Puedes automatizar la configuración mediante el bundle público `symboliclink-testing-tools`: `CreateObjectDirectory.exe` para crear el par shadow/target y `NativeSymlink.exe` en un bucle para generar la cadena de 63 saltos. Esto evita escribir wrappers `NtCreate*` manualmente y mantiene las ACLs consistentes.<sup>[[2]](#references)</sup>

## Medir tu ventana de race

Integra un harness rápido en tu exploit para medir cuánto aumenta la ventana en el hardware de la víctima. El siguiente snippet abre el objeto target `iterations` veces y devuelve el coste medio por apertura mediante `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Los resultados alimentan directamente tu estrategia de orquestación de la race (p. ej., el número de hilos worker necesarios, los intervalos de espera y con cuánta antelación debes cambiar el estado compartido).

## Flujo de explotación

1. **Localiza la apertura vulnerable** – Traza la ruta del kernel (mediante símbolos, ETW, tracing del hypervisor o reversing) hasta encontrar una llamada `NtOpen*`/`ObOpenObjectByName` que recorra un nombre controlado por el atacante o un symbolic link en un directorio escribible por el usuario.
2. **Reemplaza ese nombre por un slow path**
- Crea el componente largo o la cadena de directorios bajo `\BaseNamedObjects` (u otra raíz OM escribible).
- Crea un symbolic link para que el nombre que espera el kernel ahora resuelva al slow path. Puedes dirigir la búsqueda de directorio del driver vulnerable hacia tu estructura sin tocar el objetivo original.
3. **Activa la race**
- El hilo A (víctima) ejecuta el código vulnerable y se bloquea dentro de la búsqueda lenta.
- El hilo B (atacante) cambia el estado protegido (p. ej., intercambia un file handle, reescribe un symbolic link o cambia la seguridad del objeto) mientras el hilo A está ocupado.
- Cuando el hilo A continúa y realiza la acción privilegiada, observa un estado obsoleto y ejecuta la operación controlada por el atacante.
4. **Limpia** – Elimina la cadena de directorios y los symbolic links para evitar dejar artefactos sospechosos o interrumpir a usuarios legítimos de IPC.<sup>[[1]](#references)</sup>

## Consideraciones operativas

- **Combina primitives** – Puedes usar un nombre largo *por nivel* en una cadena de directorios para obtener una latencia aún mayor hasta agotar el tamaño de `UNICODE_STRING`.
- **Bugs one-shot** – La ventana ampliada (de decenas de microsegundos a minutos) hace realistas los bugs de “single trigger” cuando se combinan con el anclaje de afinidad de CPU o la preempción asistida por hypervisor.
- **Efectos secundarios** – El slowdown solo afecta a la ruta maliciosa, por lo que el rendimiento general del sistema permanece intacto; los defenders rara vez lo notarán a menos que monitoricen el crecimiento del namespace.
- **Limpieza** – Conserva handles de cada directorio/objeto que crees para poder llamar después a `NtMakeTemporaryObject`/`NtClose`. De lo contrario, las cadenas de directorios sin límites pueden persistir tras los reinicios.
- **File-system races** – Si la ruta vulnerable finalmente resuelve a través de NTFS, puedes colocar un Oplock (p. ej., `SetOpLock.exe` del mismo toolkit) sobre el archivo subyacente mientras se ejecuta el slowdown del OM, congelando el consumer durante milisegundos adicionales sin modificar el grafo del OM.<sup>[[2]](#references)</sup>

## Notas defensivas

- El código del kernel que dependa de objetos con nombre debe volver a validar el estado sensible a la seguridad *después* de la apertura, o tomar una referencia antes de la comprobación (cerrando la brecha TOCTOU).
- Aplica límites superiores a la profundidad/longitud de las rutas del OM antes de dereferenciar nombres controlados por el usuario. Rechazar nombres excesivamente largos obliga a los atacantes a volver a la ventana de microsegundos.
- Instrumenta el crecimiento del namespace del object manager (ETW `Microsoft-Windows-Kernel-Object`) para detectar cadenas sospechosas de miles de componentes bajo `\BaseNamedObjects`.

## Referencias

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
