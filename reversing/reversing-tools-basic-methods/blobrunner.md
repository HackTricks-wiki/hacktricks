# Blobrunner

The only modified line from the [original code](https://github.com/OALabs/BlobRunner) is the line 10.  
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
	printf(" [*]   |-Base: 0x%08x\n", (int)(size_t)lpvBase);
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
	printf(" [*] Thread Entry: 0x%016x\n", (int)(size_t)shell_entry);

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
	printf(" [*] Entry: 0x%08x\n", (int)(size_t)shell_entry);
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

