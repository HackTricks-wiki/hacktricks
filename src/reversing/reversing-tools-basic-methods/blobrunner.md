# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner), debugging için kullanılan küçük bir Windows **shellcode loader**'ıdır: RWX belleği ayırır, blob'u kopyalar, base address / entry point'i yazdırır ve yürütmeyi oraya aktarır. Bu araç, örnek **raw shellcode**, **malware'den çıkarılmış şifresi çözülmüş bir stage** veya PE header içermeyen **position-independent blob** olduğunda kullanışlıdır.

Aşağıdaki snippet özgün fikri korur; ancak debugger'a bağlanmaya veya blob'u RE tool'unuzda yeniden base etmeye çalışırken x64 build'in adresleri kesmemesi için yazdırılan pointer'lar için **`%p`** kullanır.

## Derleme

Özgün projeyi build etmenin en basit yolu bir **Visual Studio Developer Command Prompt** kullanmaktır:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Kodu ayrıca küçük bir Visual Studio / VS Code C projesine yapıştırıp orada derleyebilirsiniz.

## Yararlı kullanım kalıpları
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
- **x86** üzerinde BlobRunner duraklar ve ardından blob giriş noktasına doğrudan atlama gerçekleştirir.
- **x64** üzerinde bir **suspended thread** oluşturur; böylece yürütmeye devam etmeden önce thread başlangıç adresinde durabilirsiniz.
- `--offset`, dump alınan blob **decoder / unpacking stub** ile başlıyorsa ve gerçek giriş noktasını zaten biliyorsanız özellikle kullanışlıdır.

## Uygulama notları

### x64 lab'lerinde yazdırılan adresleri düzeltme

Eski BlobRunner kodu, `(int)(size_t)lpvBase` gibi cast'ler ve `%08x` / `%016x` kullanarak adresleri yazdırır. 64-bit iş akışlarında bu, pointer'ın üst yarısının kesilmesine ve rebase / breakpoint yerleştirme işlemlerinin zahmetli hale gelmesine neden olabilir. Aşağıdaki snippet, `%p` değerlerini doğrudan yazdırarak bu sorunu zaten düzeltir.

### `--jit`, ilk instruction breakpoint'leri için kullanışlıdır

`--jit`, shellcode'un ilk byte'ından execute erişimini kaldırır ve blob yürütülmeye başladığında Windows'un bir **access violation** oluşturmasını sağlar. Bu, manuel olarak attach olmak için yarışmak yerine yapılandırılmış JIT debugger'ın (örneğin x64dbg) ilk yürütme girişimini yakalamasını istediğinizde kullanışlıdır. Debugger durduktan sonra execute haklarını geri yükleyin ve devam edin.

Uygulanabilir bir **x64dbg** akışı şöyledir:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
İlk iki komut x64dbg'yi JIT debugger olarak kaydeder; `setpagerights` ise debugger access violation'ı yakaladıktan sonra BlobRunner tarafından yazdırılan bölgedeki execute haklarını geri yükler.

### Shellcode'u canlı olarak single-step etmek yerine time-travel kullanın

Çok pratik ve güncel bir workflow, BlobRunner'ı **TTD** altında kaydetmek ve ardından trace'i **Binary Ninja** / **WinDbg** içinde incelemektir. Bu, blob kendini decrypt ettiğinde, API'leri dinamik olarak çözdüğünde veya kısa ömürlü birkaç aşama gerçekleştirdiğinde oldukça kullanışlıdır. **Binary Ninja 4.1** sürümünden beri TTD desteği artık yalnızca beta kalitesinde değildir: reverse-debugging işlemini gerçekleştirebilir ve WinDbg / TTD workflow'unu doğrudan Binary Ninja içinden kolaylaştırabilir.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Önemli kısım, **BlobRunner tarafından yazdırılan ayrılmış base address'i not etmek** ve trace'i yeniden oynatmadan önce shellcode görünümünü bu adrese **rebase etmektir**. Ayrıca Microsoft, TTD recording işleminin **invasive** olduğunu belirtir: işlemi **elevated** bir prompt üzerinden çalıştırın, fark edilir bir yavaşlama bekleyin ve çok büyük trace dosyaları oluşmasını önlemek için recording window'u kısa tutun.<sup>[[1]](#references)</sup>

### Blob companion data gerektiriyorsa bunun yerine bir PE wrapper kullanın

Bazı shellcode'lar bellekte **ikinci bir blob'un**, **mapped file'ın** veya başka bir **structured content'in** bulunmasını bekler. BlobRunner kasıtlı olarak minimal olduğundan, bu durumlarda **SCLauncher** gibi bir runner daha kullanışlı olabilir; çünkü aşağıdakileri yapabilir:<sup>[[2]](#references)</sup>

- execution öncesinde pause yapma,
- bir `INT3` breakpoint ekleme,
- belleğe **additional content** yükleme,
- bu additional content'i memory-map etme veya
- shellcode'u, normal executable'ları tercih eden araçlarda daha kolay analiz edilebilmesi için geçici bir **PE** içine sarma.

Örnek:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
**jmp2it**, **Cutter** emulation veya **scdbg** tabanlı shellcode izleme gibi tamamlayıcı workflow'lar için [parent shellcode reversing page](README.md) sayfasına bakın.

## Kaynak kodu

[original code](https://github.com/OALabs/BlobRunner) içindeki yalnızca değiştirilmiş satırlar, x64 adreslerinin kesilmesini önlemek için kullanılan pointer-printing satırlarıdır.  
Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve build edin**.
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
## Referanslar

- [1] [Binary Ninja ile Shellcode'u Time Travel Debugging kullanarak analiz etme](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [SCLauncher ile Shellcode analizi](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)

{{#include ../../banners/hacktricks-training.md}}
