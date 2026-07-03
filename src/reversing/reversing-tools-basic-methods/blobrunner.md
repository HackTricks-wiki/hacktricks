# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) hata ayıklama için küçük bir Windows **shellcode loader**'dır: RWX memory ayırır, blob'u kopyalar, base address / entry point'i yazdırır ve yürütmeyi oraya aktarır. Bu, örnek **raw shellcode** olduğunda, malware'den çıkarılmış **decrypted stage** olduğunda veya bir PE header'ı olmayan **position-independent blob** olduğunda kullanışlıdır.

Aşağıdaki snippet orijinal fikri korur, ancak yazdırılan pointer'lar için **`%p`** kullanır; böylece x64 build, bir debugger bağlamaya veya blob'u RE tool'unuzda rebase etmeye çalışırken adresleri kırpmaz.

## Build

Orijinal projeyi build etmenin en basit yolu bir **Visual Studio Developer Command Prompt** üzerinden yapmaktır:
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Kodu küçük bir Visual Studio / VS Code C projesine de yapıştırabilir ve orada derleyebilirsiniz.

## Useful usage patterns
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
- **x86**’da, BlobRunner duraklar ve ardından blob giriş noktasına doğrudan bir jump yapar.
- **x64**’te, bir **suspended thread** oluşturur; böylece yürütmeyi sürdürmeden önce thread start address üzerinde break alabilirsin.
- `--offset`, dumped blob bir **decoder / unpacking stub** ile başlıyorsa ve gerçek giriş noktasını zaten biliyorsan özellikle kullanışlıdır.

## Pratik notlar

### x64 lab’lerinde yazdırılan address’leri düzeltin

Eski BlobRunner code, address’leri `(int)(size_t)lpvBase` ve `%08x` / `%016x` gibi casts üzerinden yazdırır. 64-bit workflows’ta bu, pointer’ın üst yarısını truncate edebilir ve rebasing / breakpoint placement işlemlerini can sıkıcı hale getirebilir. Aşağıdaki snippet bunu zaten **`%p`** values değerlerini doğrudan yazdırarak düzeltir.

### `--jit`, ilk-instruction breakpoint’leri için kullanışlıdır

`--jit`, shellcode’un ilk byte’ından execute access’i kaldırır ve blob çalışmaya başladığında Windows’un bir **access violation** yükseltmesine izin verir. Bu, debugger’a elle yetişmeye çalışmak yerine ilk execution denemesini **configured JIT debugger**’ın (örneğin x64dbg) yakalamasını istediğinde kullanışlıdır. Debugger break aldıktan sonra, execute rights’ı geri yükle ve devam et.

Pratik bir **x64dbg** akışı şöyledir:
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
İlk iki komut, x64dbg'yi JIT debugger olarak kaydeder ve `setpagerights`, debugger access violation yakaladıktan sonra BlobRunner tarafından yazdırılan bölge üzerindeki execute rights'ı geri yükler.

### Shellcode'u canlı single-step yapmak yerine zaman içinde geri sarın

Çok pratik bir yeni workflow, BlobRunner'ı **TTD** altında kaydetmek ve ardından trace'i **Binary Ninja** / **WinDbg** içinde incelemektir. Bu, blob kendi kendini decrypt ettiğinde, API'leri dinamik olarak resolve ettiğinde veya birkaç kısa ömürlü stage gerçekleştirdiğinde çok faydalıdır. **Binary Ninja 4.1**'den beri TTD desteği artık sadece beta kalitesinde değildir: reverse-debugging'i yönetebilir ve WinDbg / TTD workflow'unu doğrudan Binary Ninja içinden basitleştirebilir.
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
Önemli kısım, **BlobRunner tarafından yazdırılan ayrılmış base address’i not etmek** ve ardından trace’i yeniden oynatmadan önce shellcode görünümünü o adrese **rebase** etmektir. Ayrıca Microsoft, TTD kaydını **invasive** olarak belgeler: bunu **elevated** bir prompt’tan çalıştırın, belirgin yavaşlama bekleyin ve büyük trace dosyalarından kaçınmak için kayıt penceresini kısa tutun.

### Eğer blob companion data gerektiriyorsa, bunun yerine bir PE wrapper kullanın

Bazı shellcode’lar bellekte bir **ikinci blob**, bir **mapped file** veya başka bir **structured content** bulunmasını bekler. BlobRunner bilerek minimaldir, bu yüzden bu tür durumlarda **SCLauncher** gibi bir runner daha kullanışlı olabilir; çünkü şunları yapabilir:

- execution öncesinde duraklatmak,
- bir `INT3` breakpoint eklemek,
- belleğe **additional content** yüklemek,
- bu extra content’i memory-map etmek, veya
- shellcode’u, normal executables’ı tercih eden araçlarda daha kolay analiz için geçici bir **PE** içine sarmak.

Örnek:
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
jmp2it, **Cutter** emülasyonu veya **scdbg** tabanlı shellcode izleme gibi tamamlayıcı iş akışları için [parent shellcode reversing page](README.md) sayfasına bakın.

## Source code

[original code](https://github.com/OALabs/BlobRunner) içindeki tek değiştirilmiş satırlar, x64 adres kırpılmasını önlemek için kullanılan pointer-printing satırlarıdır.
Derlemek için sadece **Visual Studio Code içinde bir C/C++ project oluşturun, kodu kopyalayıp yapıştırın ve build edin**.
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

- [Binary Ninja ile Shellcode Zaman Yolculuğu Hata Ayıklaması](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [SCLauncher ile Shellcode Analizi](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
