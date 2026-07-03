# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) es un pequeño **shellcode loader para debugging** de Windows: asigna memoria RWX, copia el blob, imprime la dirección base / punto de entrada, y transfiere la ejecución allí. Esto es útil cuando la muestra es **raw shellcode**, una **decrypted stage extraída de malware**, o un **position-independent blob** que no tiene un PE header.

El snippet de abajo mantiene la idea original, pero usa **`%p` para punteros impresos** para que la compilación x64 no trunque direcciones mientras intentas adjuntar un debugger o rebase el blob en tu herramienta de RE.

## Build

La forma más simple de compilar el proyecto original es desde un **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
También puedes pegar el código en un pequeño proyecto C de Visual Studio / VS Code y compilarlo allí.

## Patrones de uso útiles
```bash
# Execute from the beginning of the blob
BlobRunner.exe shellcode.bin

# Start from a known offset inside the blob
BlobRunner.exe shellcode.bin --offset 0x100

# Don't stop before transferring execution
BlobRunner.exe shellcode.bin --nopause

# Force an access violation and let the configured JIT debugger catch it
BlobRunner.exe shellcode.bin --jit
```
- En **x86**, BlobRunner pausa y luego realiza un salto directo al punto de entrada del blob.
- En **x64**, crea un **hilo suspendido**, así que puedes romper en la dirección de inicio del hilo antes de reanudar la ejecución.
- `--offset` es especialmente útil cuando el blob volcado comienza con un **decoder / unpacking stub** y ya conoces el punto de entrada real.

## Notas prácticas

### Corrige las direcciones impresas en laboratorios x64

El código antiguo de BlobRunner imprime direcciones mediante casts como `(int)(size_t)lpvBase` y `%08x` / `%016x`. En flujos de trabajo de 64 bits esto puede truncar la mitad superior del puntero y hacer incómoda la rebasing / breakpoint placement. El fragmento de abajo ya lo corrige imprimiendo valores **`%p`** directamente.

### `--jit` es útil para breakpoints en la primera instrucción

`--jit` quita el acceso de ejecución del primer byte del shellcode y permite que Windows genere una **access violation** cuando el blob empieza a ejecutarse. Esto es útil cuando quieres que el **configured JIT debugger** (por ejemplo x64dbg) capture el primer intento de ejecución en lugar de intentar adjuntarte manualmente a tiempo. Después de que el debugger se detenga, restaura los permisos de ejecución y continúa.

Un flujo práctico de **x64dbg** es:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Los dos primeros comandos registran x64dbg como el depurador JIT, y `setpagerights` restaura los permisos de ejecución en la región impresa por BlobRunner después de que el depurador detecta la access violation.

### Time-travel el shellcode en lugar de hacer single-stepping live

Un workflow reciente y muy práctico es grabar BlobRunner bajo **TTD** y luego inspeccionar el trace en **Binary Ninja** / **WinDbg**. Esto es ideal cuando el blob se descifra solo, resuelve APIs dinámicamente o realiza varias etapas de corta duración. Desde **Binary Ninja 4.1**, el soporte de TTD ya no es solo de calidad beta: puede manejar reverse-debugging y simplificar directamente desde Binary Ninja el workflow de WinDbg / TTD.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Lo importante es **anotar la dirección base asignada impresa por BlobRunner** y luego **rebase** la vista del shellcode a esa dirección antes de reproducir el trace. También ten en cuenta que Microsoft documenta la grabación de TTD como **invasive**: ejecútala desde un prompt **elevated**, espera una desaceleración notable y mantén corta la ventana de grabación para evitar archivos trace enormes.

### Si el blob necesita datos companion, usa un PE wrapper en su lugar

Algunos shellcode esperan un **second blob**, un **mapped file** o algún otro **structured content** que exista en memoria. BlobRunner es intencionalmente minimal, así que para estos casos un runner como **SCLauncher** puede ser más conveniente porque puede:

- pausar antes de la ejecución,
- insertar un breakpoint `INT3`,
- cargar **additional content** en memoria,
- memory-map ese contenido extra, o
- envolver el shellcode dentro de un temporal **PE** para facilitar el análisis en tools que prefieren ejecutables normales.

Example:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Para flujos de trabajo complementarios como **jmp2it**, emulación de **Cutter**, o tracing de shellcode basado en **scdbg**, revisa la [parent shellcode reversing page](README.md).

## Source code

Las únicas líneas modificadas del [original code](https://github.com/OALabs/BlobRunner) son las líneas de impresión de punteros usadas para evitar la truncation de direcciones x64.
Para compilarlo, solo **crea un proyecto C/C++ en Visual Studio Code, copia y pega el código y compílalo**.
```c
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>

#ifdef _WIN64
#include <WinBase.h>
#endif

// Define bool
#pragma warning(disable:4996)
#define true 1
#define false 0

const char* _version = "0.0.5";

const char* _banner = " __________.__        ___.  __________\n"
" \\______   \\  |   ____\\_ |__\\______   \\__ __  ____   ____   ___________     \n"
"  |    |  _/  |  /  _ \\| __ \\|       _/  |  \\/    \\ /    \\_/ __ \\_  __ \\  \n"
"  |    |   \\  |_(  <_> ) \\_\\ \\    |   \\  |  /   |  \\   |  \\  ___/|  | \\/ \n"
"  |______  /____/\\____/|___  /____|_  /____/|___|  /___|  /\\___  >__|          \n"
"         \\/                \\/       \\/           \\/     \\/     \\/    \n\n"
"                                                                     %s    \n\n";


void banner() {
system("cls");
printf(_banner, _version);
return;
}

LPVOID process_file(char* inputfile_name, bool jit, int offset, bool debug) {
LPVOID lpvBase;
FILE* file;
unsigned long fileLen;
char* buffer;
DWORD dummy;

file = fopen(inputfile_name, "rb");

if (!file) {
printf(" [!] Error: Unable to open %s\n", inputfile_name);

return (LPVOID)NULL;
}

printf(" [*] Reading file...\n");
fseek(file, 0, SEEK_END);
fileLen = ftell(file); //Get Length

printf(" [*] File Size: 0x%04x\n", fileLen);
fseek(file, 0, SEEK_SET); //Reset

fileLen += 1;

buffer = (char*)malloc(fileLen); //Create Buffer
fread(buffer, fileLen, 1, file);
fclose(file);

printf(" [*] Allocating Memory...");

lpvBase = VirtualAlloc(NULL, fileLen, 0x3000, 0x40);

printf(".Allocated!\n");
printf(" [*]   |-Base: %p\n", lpvBase);
printf(" [*] Copying input data...\n");

CopyMemory(lpvBase, buffer, fileLen);
return lpvBase;
}

void execute(LPVOID base, int offset, bool nopause, bool jit, bool debug)
{
LPVOID shell_entry;

#ifdef _WIN64
DWORD   thread_id;
HANDLE  thread_handle;
const char msg[] = " [*] Navigate to the Thread Entry and set a breakpoint. Then press any key to resume the thread.\n";
#else
const char msg[] = " [*] Navigate to the EP and set a breakpoint. Then press any key to jump to the shellcode.\n";
#endif

shell_entry = (LPVOID)((UINT_PTR)base + offset);

#ifdef _WIN64

printf(" [*] Creating Suspended Thread...\n");
thread_handle = CreateThread(
NULL,          // Attributes
0,             // Stack size (Default)
shell_entry,         // Thread EP
NULL,          // Arguments
0x4,           // Create Suspended
&thread_id);   // Thread identifier

if (thread_handle == NULL) {
printf(" [!] Error Creating thread...");
return;
}
printf(" [*] Created Thread: [%d]\n", thread_id);
printf(" [*] Thread Entry: %p\n", shell_entry);

#endif

if (nopause == false) {
printf("%s", msg);
getchar();
}
else
{
if (jit == true) {
// Force an exception by making the first byte not executable.
// This will cause
DWORD oldp;

printf(" [*] Removing EXECUTE access to trigger exception...\n");

VirtualProtect(shell_entry, 1 , PAGE_READWRITE, &oldp);
}
}

#ifdef _WIN64
printf(" [*] Resuming Thread..\n");
ResumeThread(thread_handle);
#else
printf(" [*] Entry: %p\n", shell_entry);
printf(" [*] Jumping to shellcode\n");
__asm jmp shell_entry;
#endif
}

void print_help() {
printf(" [!] Error: No file!\n\n");
printf("     Required args: <inputfile>\n\n");
printf("     Optional Args:\n");
printf("         --offset <offset> The offset to jump into.\n");
printf("         --nopause         Don't pause before jumping to shellcode. Danger!!! \n");
printf("         --jit             Forces an exception by removing the EXECUTE permission from the alloacted memory.\n");
printf("         --debug           Verbose logging.\n");
printf("         --version         Print version and exit.\n\n");
}

int main(int argc, char* argv[])
{
LPVOID base;
int i;
int offset = 0;
bool nopause = false;
bool debug = false;
bool jit = false;
char* nptr;

banner();

if (argc < 2) {
print_help();
return -1;
}

printf(" [*] Using file: %s \n", argv[1]);

for (i = 2; i < argc; i++) {
if (strcmp(argv[i], "--offset") == 0) {
printf(" [*] Parsing offset...\n");
i = i + 1;
if (strncmp(argv[i], "0x", 2) == 0) {
offset = strtol(argv[i], &nptr, 16);
}
else {
offset = strtol(argv[i], &nptr, 10);
}
}
else if (strcmp(argv[i], "--nopause") == 0) {
nopause = true;
}
else if (strcmp(argv[i], "--jit") == 0) {
jit = true;
nopause = true;
}
else if (strcmp(argv[i], "--debug") == 0) {
debug = true;
}
else if (strcmp(argv[i], "--version") == 0) {
printf("Version: %s", _version);
}
else {
printf("[!] Warning: Unknown arg: %s\n", argv[i]);
}
}

base = process_file(argv[1], jit, offset, debug);
if (base == NULL) {
printf(" [!] Exiting...");
return -1;
}
printf(" [*] Using offset: 0x%08x\n", offset);
execute(base, offset, nopause, jit, debug);
printf("Pausing - Press any key to quit.\n");
getchar();
return 0;
}
```
## Referencias

- [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
