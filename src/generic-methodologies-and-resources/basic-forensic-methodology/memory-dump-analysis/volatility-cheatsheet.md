# Volatility - Bảng tra cứu

{{#include ../../../banners/hacktricks-training.md}}

Nếu bạn cần một công cụ tự động hóa việc phân tích bộ nhớ với nhiều cấp độ quét khác nhau và chạy song song nhiều plugin Volatility3, bạn có thể dùng autoVolatility3:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)

```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```

Nếu bạn muốn một công cụ **nhanh và điên rồ** có thể chạy song song nhiều plugin Volatility, bạn có thể dùng: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)

```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```

## Cài đặt

### volatility3

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```

### volatility2

{{#tabs}}
{{#tab name="Method1"}}

```
Download the executable from https://www.volatilityfoundation.org/26
```

{{#endtab}}

{{#tab name="Method 2"}}

```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```

{{#endtab}}
{{#endtabs}}

## Volatility Commands

Truy cập tài liệu chính thức tại [Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Lưu ý về plugin “list” và “scan”

Plugin `list` duyệt các cấu trúc do kernel duy trì nên chạy nhanh, nhưng có thể bỏ sót các đối tượng bị malware gỡ liên kết. Plugin `scan` như `psscan` tìm kiếm chữ ký đối tượng trong bộ nhớ; chúng có thể khôi phục các tiến trình đã kết thúc hoặc bị gỡ liên kết, nhưng chạy chậm hơn và có thể tạo kết quả dương tính giả khi các cấu trúc còn sót lại bị hỏng.<sup>[[8]](#references)</sup>

## OS Profiles

### Volatility3

Volatility 3 yêu cầu các bảng symbol cho hệ điều hành mục tiêu. README của dự án liệt kê các gói cho Windows, Mac và Linux; đặt chúng trong `volatility3/symbols` hoặc trong thư mục `symbols` nằm cạnh tệp thực thi. Các symbol Windows còn thiếu có thể được tải về và tạo tự động, trong khi các bảng cho Mac và Linux có thể cần được tạo riêng.<sup>[[9]](#references)</sup>

Các gói bảng symbol cho nhiều hệ điều hành có thể **tải xuống** tại:

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### External Profile

Bạn có thể lấy danh sách các profile được hỗ trợ bằng cách chạy:

```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```

Nếu muốn sử dụng một **profile mới mà bạn đã tải xuống** (ví dụ profile Linux), bạn cần tạo cấu trúc thư mục sau ở một vị trí nào đó: _plugins/overlays/linux và đặt tệp zip chứa profile vào thư mục này. Sau đó, lấy danh sách các profile bằng cách dùng:

```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```

Bạn có thể **tải xuống các profile Linux và Mac** từ [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

Trong chunk trước, bạn có thể thấy profile có tên là `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, và bạn có thể dùng nó để thực thi một lệnh như sau:

```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```

#### Khám phá Profile

```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```

#### **Sự khác biệt giữa imageinfo và kdbgscan**

[Ghi chú về nhận dạng image của Andrea Fortuna](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/) giải thích rằng `imageinfo` đưa ra các profile được đề xuất, trong khi `kdbgscan` quét các chữ ký KDBG và thực hiện kiểm tra tính hợp lý để xác định các profile tiềm năng cùng địa chỉ KDBG. Kết quả của nó phụ thuộc một phần vào việc Volatility có tìm được DTB hay không, vì vậy hãy truyền vào một profile đã biết hoặc được đề xuất khi chạy lệnh này.<sup>[[1]](#references)</sup>

Khi có nhiều ứng viên được trả về, hãy so sánh số lượng process và module của chúng: ứng viên không có process hoặc module nào kém đáng tin hơn ứng viên có danh sách tương ứng. Hãy xem đây là bước kiểm tra tính hợp lý, không phải bằng chứng xác nhận profile là chính xác.<sup>[[1]](#references)</sup>

```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```

#### KDBG

`KdDebuggerDataBlock`, được Volatility biết đến với tên KDBG, là cấu trúc `_KDDEBUGGER_DATA64` bao gồm `PsActiveProcessHead`, nút đầu của danh sách tiến trình được dùng để liệt kê tiến trình.<sup>[[2]](#references)</sup>

## Thông tin hệ điều hành

```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```

Plugin `banners.Banners` có thể được dùng trong **vol3 để thử tìm linux banners** trong dump.

## Hashes/Mật khẩu

Trích xuất hash SAM, [thông tin xác thực được cache của domain](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) và [lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets).

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```

{{#endtab}}
{{#endtabs}}

## Memory Dump

Memory dump của một process sẽ **trích xuất mọi thứ** về trạng thái hiện tại của process. Module **procdump** chỉ **trích xuất** **code**.

```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```

## Tiến trình

### Liệt kê tiến trình

Cố gắng tìm các tiến trình **đáng ngờ** (theo tên) hoặc các **tiến trình** con **không mong đợi** (ví dụ: cmd.exe là tiến trình con của iexplorer.exe).\
Có thể hữu ích khi **so sánh** kết quả của pslist với psscan để xác định các tiến trình ẩn.

{{#tabs}}
{{#tab name="vol3"}}

```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```

{{#endtab}}
{{#endtabs}}

### Dump proc

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```

{{#endtab}}
{{#endtabs}}

### Dòng lệnh

Có lệnh nào đáng ngờ được thực thi không?

{{#tabs}}
{{#tab name="vol3"}}

```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```

{{#endtab}}
{{#endtabs}}

Các lệnh được thực thi trong `cmd.exe` do **`conhost.exe`** quản lý (hoặc **`csrss.exe`** trên các hệ thống trước Windows 7). Điều này có nghĩa là nếu kẻ tấn công chấm dứt **`cmd.exe`** trước khi thu thập memory dump, vẫn có thể khôi phục lịch sử lệnh của phiên từ bộ nhớ của **`conhost.exe`**. Để thực hiện việc này, nếu phát hiện hoạt động bất thường trong các module của console, cần dump bộ nhớ của tiến trình **`conhost.exe`** tương ứng. Sau đó, bằng cách tìm kiếm **strings** trong dump này, có thể trích xuất các dòng lệnh đã sử dụng trong phiên.

### Môi trường

Lấy các biến môi trường của từng tiến trình đang chạy. Có thể có một số giá trị đáng chú ý.

{{#tabs}}
{{#tab name="vol3"}}

```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```

{{#endtab}}
{{#endtabs}}

### Đặc quyền của token

Kiểm tra các token đặc quyền trong những dịch vụ bất thường.\
Có thể hữu ích nếu liệt kê các tiến trình đang sử dụng token đặc quyền.

{{#tabs}}
{{#tab name="vol3"}}

```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```

{{#endtab}}
{{#endtabs}}

### SIDs

Kiểm tra từng SSID thuộc sở hữu của một tiến trình.\
Có thể hữu ích khi liệt kê các tiến trình sử dụng SID đặc quyền (và các tiến trình sử dụng một số service SID).

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```

{{#endtab}}
{{#endtabs}}

### Handles

Hữu ích để biết một **process có handle** (đã mở) tới những file, key, thread, process... nào khác

{{#tabs}}
{{#tab name="vol3"}}

```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```

{{#endtab}}
{{#endtabs}}

### DLLs

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```

{{#endtab}}
{{#endtabs}}

### Strings theo từng process

Volatility cho phép chúng ta kiểm tra một string thuộc về process nào.

{{#tabs}}
{{#tab name="vol3"}}

```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```

{{#endtab}}
{{#endtabs}}

Nó cũng cho phép tìm kiếm chuỗi bên trong một tiến trình bằng module yarascan:

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```

{{#endtab}}
{{#endtabs}}

### UserAssist

Các giá trị registry `UserAssist` ghi lại những chương trình được khởi chạy thông qua Windows Explorer, bao gồm số lần thực thi và dấu thời gian chạy lần cuối; các lần khởi chạy bằng dòng lệnh không được ghi lại trong những khóa này.<sup>[[3]](#references)</sup>

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```

{{#endtab}}

{{#tab name="vol2"}}

```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```

{{#endtab}}
{{#endtabs}}

## Dịch vụ

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```

{{#endtab}}
{{#endtabs}}

## Mạng

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```

{{#endtab}}
{{#endtabs}}

## Hive Registry

### In các hive khả dụng

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```

{{#endtab}}
{{#endtabs}}

### Lấy một giá trị

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```

{{#endtab}}
{{#endtabs}}

### Bản dump

```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```

## Hệ thống tệp

### Gắn kết

{{#tabs}}
{{#tab name="vol3"}}

```bash
#See vol2
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```

{{#endtab}}
{{#endtabs}}

### Quét/dump

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```

{{#endtab}}
{{#endtabs}}

### Bảng tệp chính

{{#tabs}}
{{#tab name="vol3"}}

```bash
# I couldn't find any plugin to extract this information in volatility3
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```

{{#endtab}}
{{#endtabs}}

Trên NTFS, MFT có ít nhất một mục cho mỗi tệp trên ổ đĩa, bao gồm cả chính nó. Metadata và nội dung của tệp được lưu trong các mục MFT hoặc tại những vị trí mà các mục đó mô tả; xem [tài liệu của Microsoft](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table).<sup>[[4]](#references)</sup>

### Khóa/chứng chỉ SSL

{{#tabs}}
{{#tab name="vol3"}}

```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```

{{#endtab}}
{{#endtabs}}

## Phần mềm độc hại

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```

{{#endtab}}
{{#endtabs}}

### Quét bằng yara

Dùng script này để tải xuống và hợp nhất tất cả các quy tắc yara về malware từ github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Tạo thư mục _**rules**_ rồi chạy script. Thao tác này sẽ tạo một tệp có tên _**malware_rules.yar**_ chứa tất cả các quy tắc yara về malware.

{{#tabs}}
{{#tab name="vol3"}}

```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```

{{#endtab}}
{{#endtabs}}

## KHÁC

### Plugin bên ngoài

Nếu muốn sử dụng plugin bên ngoài, hãy đảm bảo các thư mục liên quan đến plugin được dùng làm tham số đầu tiên.

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
 volatilitye --plugins="/tmp/plugins/" [...]
```

{{#endtab}}
{{#endtabs}}

#### Autoruns

Tải xuống tại [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)

```
 volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```

### Mutexes

{{#tabs}}
{{#tab name="vol3"}}

```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```

{{#endtab}}
{{#endtabs}}

### Liên kết tượng trưng

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```

{{#endtab}}
{{#endtabs}}

### Bash

Có thể **đọc lịch sử bash từ bộ nhớ.** Bạn cũng có thể trích xuất tệp _.bash_history_, nhưng nếu tính năng này bị tắt thì bạn sẽ mừng vì có thể dùng module volatility này

{{#tabs}}
{{#tab name="vol3"}}

```
./vol.py -f file.dmp linux.bash.Bash
```

{{#endtab}}

{{#tab name="vol2"}}

```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```

{{#endtab}}
{{#endtabs}}

### Dòng thời gian

{{#tabs}}
{{#tab name="vol3"}}

```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```

{{#endtab}}

{{#tab name="vol2"}}

```
volatility --profile=Win7SP1x86_23418 -f timeliner
```

{{#endtab}}
{{#endtabs}}

### Trình điều khiển

{{#tabs}}
{{#tab name="vol3"}}

```
./vol.py -f file.dmp windows.driverscan.DriverScan
```

{{#endtab}}

{{#tab name="vol2"}}

```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```

{{#endtab}}
{{#endtabs}}

### Lấy clipboard

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```

### Lấy lịch sử IE

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```

### Lấy văn bản từ Notepad

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```

### Ảnh chụp màn hình

```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```

### Bản ghi khởi động chính (MBR)

```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```

Trên các hệ thống dựa trên BIOS, MBR ở sector 0 chứa mã khởi động chính và bảng phân vùng. Microsoft ghi rõ rằng `bootsect /mbr` cập nhật mã mà không thay đổi bảng đó.<sup>[[7]](#references)</sup>

## References

- [1] [Volatility, ghi chú nhanh của tôi (Phần 1): Nhận dạng ảnh](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [2] [Tìm Kernel Debugger Block](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [3] [Các khóa UserAssist của Windows](https://www.aldeid.com/wiki/Windows-userassist-keys)
- [4] [Master File Table (hệ thống tệp cục bộ) - ứng dụng Win32](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [5] [PC dựa trên UEFI, protective MBR: đó là gì? - Microsoft Community](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)
- [6] [Hướng dẫn: Các plugin Volatility dùng để phân tích malware](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)
- [7] [Các tùy chọn dòng lệnh Bootsect](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bootsect-command-line-options?view=windows-11)
- [8] [Hướng dẫn - Các plugin Volatility và phân tích malware](https://tomchop.me/posts/volatility-plugin-malware-analysis/)
- [9] [README của Volatility 3](https://github.com/volatilityfoundation/volatility3/blob/develop/README.md)
{{#include ../../../banners/hacktricks-training.md}}
