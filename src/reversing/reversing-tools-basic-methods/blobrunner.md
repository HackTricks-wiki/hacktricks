# Blobrunner

{{#include ../../banners/hacktricks-training.md}}

[**BlobRunner**](https://github.com/OALabs/BlobRunner) là một **shellcode loader dùng để debug** nhỏ gọn trên Windows: nó cấp phát vùng nhớ RWX, sao chép blob vào đó, in địa chỉ cơ sở / entry point rồi chuyển quyền thực thi đến đó. Công cụ này rất hữu ích khi mẫu là **raw shellcode**, một **stage đã giải mã được trích xuất từ malware**, hoặc một **blob độc lập vị trí** không có PE header.

Đoạn mã bên dưới giữ nguyên ý tưởng ban đầu, nhưng dùng **`%p` để in các con trỏ** nhằm tránh bản dựng x64 cắt cụt địa chỉ khi bạn đang cố gắng gắn debugger hoặc rebase blob trong RE tool.

## Xây dựng

Cách đơn giản nhất để build project gốc là dùng **Visual Studio Developer Command Prompt**:

```bash
cl blobrunner.c
cl /Feblobrunner64.exe /Foblobrunner64.out blobrunner.c
```

Bạn cũng có thể dán code vào một dự án C nhỏ trong Visual Studio / VS Code rồi biên dịch tại đó.

## Các mẫu sử dụng hữu ích

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

- Trong **x86**, BlobRunner tạm dừng rồi thực hiện một lệnh nhảy trực tiếp đến entry point của blob.
- Trong **x64**, nó tạo một **suspended thread**, vì vậy bạn có thể đặt breakpoint tại địa chỉ bắt đầu của thread trước khi tiếp tục thực thi.
- `--offset` đặc biệt hữu ích khi blob được dump bắt đầu bằng **decoder / unpacking stub** và bạn đã biết entry point thực sự.

## Ghi chú thực tế

### Sửa các địa chỉ được in ra trong lab x64

Các phiên bản BlobRunner cũ in địa chỉ qua những phép ép kiểu như `(int)(size_t)lpvBase` và `%08x` / `%016x`. Trong quy trình làm việc 64-bit, cách này có thể làm mất nửa trên của con trỏ và khiến việc rebasing / đặt breakpoint trở nên phiền phức. Đoạn mã bên dưới đã khắc phục điều đó bằng cách in trực tiếp các giá trị **`%p`**.

### `--jit` hữu ích khi đặt breakpoint ở lệnh đầu tiên

`--jit` bỏ quyền thực thi khỏi byte đầu tiên của shellcode và để Windows phát sinh **access violation** khi blob bắt đầu thực thi. Tính năng này hữu ích khi bạn muốn **JIT debugger đã cấu hình** (ví dụ x64dbg) bắt lần thử thực thi đầu tiên, thay vì phải nhanh tay attach. Sau khi debugger dừng lại, khôi phục quyền thực thi rồi tiếp tục.

Một quy trình **x64dbg** thực tế như sau:

```text
setjit
setjitauto on
BlobRunner.exe shellcode.bin --jit
setpagerights <region>, ExecuteReadWrite
```

Hai lệnh đầu tiên đăng ký x64dbg làm JIT debugger, còn `setpagerights` khôi phục quyền thực thi trên vùng mà BlobRunner in ra sau khi debugger bắt được access violation.

### Dịch chuyển thời gian trong shellcode thay vì single-step trực tiếp

Một workflow rất thiết thực gần đây là ghi lại BlobRunner bằng **TTD**, sau đó kiểm tra trace trong **Binary Ninja** / **WinDbg**. Cách này rất hữu ích khi blob tự giải mã, phân giải API động hoặc thực hiện nhiều stage tồn tại trong thời gian ngắn. Kể từ **Binary Ninja 4.1**, hỗ trợ TTD không còn chỉ ở mức beta: nó có thể thực hiện reverse-debugging và đơn giản hóa workflow WinDbg / TTD trực tiếp từ Binary Ninja.<sup>[[1]](#references)</sup>

```bash
TTD.exe .\blobrunner.exe .\shellcode.bin
```

Phần quan trọng là **ghi lại địa chỉ cơ sở được BlobRunner cấp phát và in ra**, sau đó **rebase** chế độ xem shellcode về địa chỉ đó trước khi phát lại trace. Cũng lưu ý rằng Microsoft mô tả việc ghi TTD là **xâm lấn**: hãy chạy từ một cửa sổ nhắc lệnh **được nâng quyền**, dự kiến hiệu năng sẽ giảm đáng kể và giữ khoảng thời gian ghi ngắn để tránh tạo các tệp trace khổng lồ.<sup>[[1]](#references)</sup>

### Nếu blob cần dữ liệu đi kèm, hãy dùng PE wrapper

Một số shellcode cần có **blob thứ hai**, **tệp được ánh xạ** hoặc một loại **nội dung có cấu trúc** khác trong bộ nhớ. BlobRunner được thiết kế tối giản, nên trong những trường hợp này, một runner như **SCLauncher** có thể tiện hơn vì nó có thể:<sup>[[2]](#references)</sup>

- tạm dừng trước khi thực thi,
- chèn breakpoint `INT3`,
- nạp **nội dung bổ sung** vào bộ nhớ,
- ánh xạ nội dung bổ sung đó vào bộ nhớ, hoặc
- bọc shellcode bên trong một **PE** tạm thời để dễ phân tích hơn bằng các công cụ ưu tiên tệp thực thi thông thường.

Ví dụ:

```bash
SCLauncher.exe -f=shellcode.bin -pause -d=config.bin -mm
SCLauncher.exe -f=shellcode.bin -pe -64 -ep=0x120
```

Đối với các quy trình bổ trợ như **jmp2it**, mô phỏng **Cutter** hoặc truy vết shellcode dựa trên **scdbg**, hãy xem [trang reversing shellcode chính](README.md).

## Mã nguồn

Các dòng duy nhất được chỉnh sửa so với [mã nguồn gốc](https://github.com/OALabs/BlobRunner) là những dòng in con trỏ, nhằm tránh bị cắt cụt địa chỉ x64.  
Để biên dịch, chỉ cần **tạo một dự án C/C++ trong Visual Studio Code, sao chép và dán mã rồi build**.

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

- [1] [Debugging Shellcode bằng Time Travel với Binary Ninja](https://www.lrqa.com/en/cyber-labs/time-travel-debugging-shellcode-with-binary-ninja/)
- [2] [Phân tích Shellcode bằng SCLauncher](https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher)
{{#include ../../banners/hacktricks-training.md}}
