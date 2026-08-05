# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) est un petit **shellcode loader Windows pour le débogage** : il alloue de la mémoire RWX, y copie le blob, affiche l'adresse de base / le point d'entrée, puis y transfère l'exécution. C'est pratique lorsque l'échantillon est du **shellcode brut**, une **étape déchiffrée extraite d'un malware**, ou un **blob position-independent** qui ne possède pas d'en-tête PE.

L'extrait ci-dessous conserve l'idée originale, mais utilise **`%p` pour afficher les pointeurs** afin que la compilation x64 ne tronque pas les adresses pendant que vous essayez d'attacher un débogueur ou de rebaser le blob dans votre outil de RE.

## Compilation

La manière la plus simple de compiler le projet original consiste à utiliser une **Visual Studio Developer Command Prompt** :
```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```
Vous pouvez également coller le code dans un petit projet C Visual Studio / VS Code et le compiler.

## Modèles d’utilisation utiles
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
- En **x86**, BlobRunner se met en pause, puis effectue un saut direct vers le point d’entrée du blob.
- En **x64**, il crée un **thread suspendu**, ce qui permet de placer un breakpoint sur l’adresse de démarrage du thread avant de reprendre l’exécution.
- `--offset` est particulièrement utile lorsque le blob dumpé commence par un **stub de décodage / décompression** et que vous connaissez déjà le véritable point d’entrée.

## Notes pratiques

### Corriger les adresses affichées dans les labs x64

Les anciennes versions du code de BlobRunner affichent les adresses via des casts tels que `(int)(size_t)lpvBase` et `%08x` / `%016x`. Dans les workflows 64 bits, cela peut tronquer la moitié supérieure du pointeur et compliquer le rebasage / placement des breakpoints. Le snippet ci-dessous corrige déjà ce problème en affichant directement les valeurs **`%p`**.

### `--jit` est utile pour les breakpoints sur la première instruction

`--jit` supprime les droits d’exécution du premier byte du shellcode et permet à Windows de déclencher une **violation d’accès** lorsque le blob commence à s’exécuter. Cette option est utile lorsque vous voulez que le **debugger JIT configuré** (par exemple x64dbg) intercepte la première tentative d’exécution au lieu de devoir vous dépêcher de vous attacher manuellement. Une fois que le debugger s’est arrêté, restaurez les droits d’exécution et poursuivez l’exécution.

Un workflow **x64dbg** pratique est le suivant :
```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```
Les deux premières commandes enregistrent x64dbg comme débogueur JIT, et `setpagerights` restaure les droits d’exécution sur la région affichée par BlobRunner après que le débogueur a intercepté la violation d’accès.

### Remonter dans le temps lors de l’exécution du shellcode au lieu de l’exécuter pas à pas en direct

Un workflow récent très pratique consiste à enregistrer BlobRunner sous **TTD**, puis à inspecter la trace dans **Binary Ninja** / **WinDbg**. Cette méthode est particulièrement utile lorsque le blob se déchiffre lui-même, résout dynamiquement les API ou exécute plusieurs étapes de courte durée. Depuis **Binary Ninja 4.1**, la prise en charge de TTD n’est plus simplement en version bêta : elle permet le reverse-debugging et simplifie directement le workflow WinDbg / TTD depuis Binary Ninja.<sup>[[1]](#references)</sup>
```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```
L’élément important est de **noter l’adresse de base allouée affichée par BlobRunner**, puis de **rebaser** la vue du shellcode sur cette adresse avant de rejouer la trace. Notez également que Microsoft décrit l’enregistrement TTD comme **invasif** : lancez-le depuis une invite **élevée**, prévoyez un ralentissement notable et limitez la durée d’enregistrement afin d’éviter des fichiers de trace volumineux.

### Si le blob nécessite des données associées, utilisez plutôt un wrapper PE

Certains shellcodes s’attendent à ce qu’un **second blob**, un **fichier mappé** ou un autre **contenu structuré** soit présent en mémoire. BlobRunner est volontairement minimal ; dans ces cas, un runner tel que **SCLauncher** peut être plus pratique, car il peut :<sup>[[2]](#references)</sup>

- se mettre en pause avant l’exécution,
- insérer un point d’arrêt **INT3**,
- charger du **contenu supplémentaire** en mémoire,
- mapper ce contenu supplémentaire en mémoire, ou
- encapsuler le shellcode dans un **PE** temporaire pour faciliter l’analyse dans les outils qui privilégient les exécutables classiques.

Exemple :
```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```
Pour les workflows complémentaires tels que **jmp2it**, l’émulation avec **Cutter** ou le traçage de shellcode basé sur **scdbg**, consultez la [page parent sur le reversing de shellcode](README.md).

## Code source

Les seules lignes modifiées par rapport au [code original](https://github.com/OALabs/BlobRunner) sont les lignes d’affichage des pointeurs utilisées pour éviter la troncature des adresses x64.
Pour le compiler, il suffit de **créer un projet C/C++ dans Visual Studio Code, de copier-coller le code, puis de le compiler**.
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
## Références

- [1] [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
