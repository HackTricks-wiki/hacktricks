# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) is a tiny Windows **shellcode loader for debugging**: it allocates RWX memory, copies the blob, prints the base address / entry point, and transfers execution there. This is handy when the sample is **raw shellcode**, a **decrypted stage extracted from malware**, or a **position-independent blob** that does not have a PE header.

The snippet below keeps the original idea, but uses **`%p` for printed pointers** so the x64 build doesn't truncate addresses while you are trying to attach a debugger or rebase the blob in your RE tool.

## Build

The simplest way to build the original project is from a **Visual Studio Developer Command Prompt**:

```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```

You can also paste the code into a small Visual Studio / VS Code C project and compile it there.

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

- In **x86**, BlobRunner pauses and then performs a direct jump to the blob entry point.
- In **x64**, it creates a **suspended thread**, so you can break on the thread start address before resuming execution.
- `--offset` is especially useful when the dumped blob starts with a **decoder / unpacking stub** and you already know the real entry point.

## Practical notes

### Fix the printed addresses in x64 labs

Older BlobRunner code prints addresses via casts such as `(int)(size_t)lpvBase` and `%08x` / `%016x`. In 64-bit workflows this can truncate the high half of the pointer and make rebasing / breakpoint placement annoying. The snippet below already fixes that by printing **`%p`** values directly.

### `--jit` is useful for first-instruction breakpoints

`--jit` removes execute access from the first byte of the shellcode and lets Windows raise an **access violation** when the blob starts executing. This is useful when you want the **configured JIT debugger** (for example x64dbg) to catch the first execution attempt instead of manually racing to attach. After the debugger breaks, restore execute rights and continue.

A practical **x64dbg** flow is:

```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```

The first two commands register x64dbg as the JIT debugger, and `setpagerights` restores execute rights on the region printed by BlobRunner after the debugger catches the access violation.

### Time-travel the shellcode instead of single-stepping it live

A very practical recent workflow is to record BlobRunner under **TTD** and then inspect the trace in **Binary Ninja** / **WinDbg**. This is great when the blob decrypts itself, resolves APIs dynamically, or performs several short-lived stages. Since **Binary Ninja 4.1**, TTD support is no longer just beta quality: it can drive reverse-debugging and simplify the WinDbg / TTD workflow directly from Binary Ninja.

```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```

The important part is to **note the allocated base address printed by BlobRunner** and then **rebase** the shellcode view to that address before replaying the trace. Also note that Microsoft documents TTD recording as **invasive**: run it from an **elevated** prompt, expect noticeable slowdown, and keep the recording window short to avoid massive trace files.

### If the blob needs companion data, use a PE wrapper instead

Some shellcode expects a **second blob**, a **mapped file**, or some other **structured content** to exist in memory. BlobRunner is intentionally minimal, so for these cases a runner such as **SCLauncher** can be more convenient because it can:

- pause before execution,
- insert an `INT3` breakpoint,
- load **additional content** into memory,
- memory-map that extra content, or
- wrap the shellcode inside a temporary **PE** for easier analysis in tools that prefer normal executables.

Example:

```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```

For complementary workflows such as **jmp2it**, **Cutter** emulation, or **scdbg**-based shellcode tracing, check the [parent shellcode reversing page](README.md).

## Source code

The only modified lines from the [original code](https://github.com/OALabs/BlobRunner) are the pointer-printing lines used to avoid x64 address truncation.  
In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.

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



## References

- [Time Travel Debugging Shellcode with Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [Analyzing Shellcode with SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
