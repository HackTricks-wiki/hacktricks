# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) é um pequeno **shellcode loader for debugging** do Windows: ele aloca memória RWX, copia o blob, imprime o endereço base / ponto de entrada e transfere a execução para lá. Isso é útil quando o sample é **raw shellcode**, um **decrypted stage extracted from malware** ou um **position-independent blob** que não tem um cabeçalho PE.

O snippet abaixo mantém a ideia original, mas usa **`%p` para ponteiros impressos** para que a build x64 não trunque endereços enquanto você está tentando anexar um debugger ou rebasear o blob na sua RE tool.

## Build

A forma mais simples de compilar o projeto original é a partir de um **Visual Studio Developer Command Prompt**:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Você também pode colar o código em um pequeno projeto C no Visual Studio / VS Code e compilá-lo lá.

## Padrões de uso úteis
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
- Em **x86**, BlobRunner pausa e depois faz um salto direto para o blob entry point.
- Em **x64**, ele cria uma **suspended thread**, então você pode quebrar no thread start address antes de retomar a execução.
- `--offset` é especialmente útil quando o dumped blob começa com um **decoder / unpacking stub** e você já conhece o real entry point.

## Notas práticas

### Corrija os endereços impressos em labs x64

O código antigo do BlobRunner imprime endereços via casts como `(int)(size_t)lpvBase` e `%08x` / `%016x`. Em workflows 64-bit, isso pode truncar a metade alta do ponteiro e tornar o rebasing / breakpoint placement chato. O snippet abaixo já corrige isso ao imprimir valores **`%p`** diretamente.

### `--jit` é útil para breakpoints na primeira instrução

`--jit` remove o execute access do primeiro byte do shellcode e faz o Windows gerar uma **access violation** quando o blob começa a executar. Isso é útil quando você quer que o **configured JIT debugger** (por exemplo x64dbg) capture a primeira tentativa de execução em vez de você ter que correr manualmente para anexar. Depois que o debugger quebrar, restaure os execute rights e continue.

Um fluxo prático no **x64dbg** é:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Os dois primeiros comandos registram o x64dbg como o depurador JIT, e `setpagerights` restaura os direitos de execução na região impressa pelo BlobRunner depois que o debugger captura a access violation.

### Faça time-travel no shellcode em vez de executá-lo live passo a passo

Um fluxo de trabalho recente e muito prático é gravar o BlobRunner no **TTD** e então inspecionar o trace no **Binary Ninja** / **WinDbg**. Isso é ótimo quando o blob se auto-decripta, resolve APIs dinamicamente ou executa várias etapas de curta duração. Desde o **Binary Ninja 4.1**, o suporte a TTD não é mais apenas beta: ele pode conduzir reverse-debugging e simplificar diretamente do Binary Ninja o fluxo de trabalho do WinDbg / TTD.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
A parte importante é **anotar o endereço base alocado impresso pelo BlobRunner** e então **rebase** a view do shellcode para esse endereço antes de reproduzir o trace. Note também que a Microsoft documenta a gravação com TTD como **invasive**: execute-a a partir de um prompt **elevated**, espere uma desaceleração perceptível e mantenha a janela de gravação curta para evitar arquivos de trace enormes.

### Se o blob precisar de dados auxiliares, use um wrapper PE em vez disso

Alguns shellcodes esperam que exista em memória um **second blob**, um **mapped file** ou outro **structured content**. O BlobRunner é intencionalmente minimalista, então, para esses casos, um runner como o **SCLauncher** pode ser mais conveniente porque ele pode:

- pausar antes da execução,
- inserir um breakpoint `INT3`,
- carregar **additional content** na memória,
- memory-map desse conteúdo extra, ou
- envolver o shellcode dentro de um **PE** temporário para facilitar a análise em tools que preferem executáveis normais.

Example:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Para fluxos de trabalho complementares, como **jmp2it**, emulação do **Cutter** ou tracing de shellcode baseado em **scdbg**, consulte a [parent shellcode reversing page](README.md).

## Source code

As únicas linhas modificadas do [código original](https://github.com/OALabs/BlobRunner) são as linhas de impressão de ponteiros usadas para evitar a truncação de endereços x64.
Para compilá-lo, basta **criar um projeto C/C++ no Visual Studio Code, copiar e colar o código e compilá-lo**.
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
## Referências

- [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
