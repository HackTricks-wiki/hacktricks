# SeManageVolumePrivilege：用于任意文件读取的原始卷访问

{{#include ../../banners/hacktricks-training.md}}

## 概述

Windows 用户权限：执行卷维护任务（常量：SeManageVolumePrivilege）。

持有该权限的用户可以执行低级卷操作，例如碎片整理、创建/删除卷以及维护 IO。对攻击者而言，关键在于此权限允许打开原始卷设备句柄（例如 \\.\C:），并发起绕过 NTFS 文件 ACL 的直接磁盘 I/O。借助原始访问，即使某个文件被 DACL 拒绝访问，也可以复制该卷上任意文件的字节，方法包括离线解析文件系统结构，或使用能够在块/簇级别读取数据的工具。

默认：服务器和域控制器上的 Administrators。<sup>[[1]](#references)</sup>

## 滥用场景

- 通过读取磁盘设备绕过 ACL，任意读取文件（例如窃取受系统保护的敏感材料，如 %ProgramData%\Microsoft\Crypto\RSA\MachineKeys 和 %ProgramData%\Microsoft\Crypto\Keys 下的 machine private keys、registry hives、DPAPI masterkeys、SAM，以及通过 VSS 获取 ntds.dit 等）。
- 通过直接从原始设备复制字节，绕过锁定或需要特权的路径（C:\Windows\System32\…）。
- 在 AD CS 环境中，窃取 CA 的 key material（machine key store），以铸造“Golden Certificates”，并通过 PKINIT 冒充任意域主体。请参阅下面的链接。<sup>[[2]](#references)</sup>

注意：除非依赖 helper tools，否则仍然需要 NTFS 结构解析器。许多现成工具已将原始访问进行了抽象封装。

## 实用技术

- 打开原始卷句柄并读取 clusters：

<details>
<summary>点击展开</summary>
```powershell
# PowerShell – read first MB from C: raw device (requires SeManageVolumePrivilege)
$fs = [System.IO.File]::Open("\\.\\C:",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf,0,$buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\\temp\\c_first_mb.bin", $buf)
```

```csharp
// C# (compile with Add-Type) – read an arbitrary offset of \\.\nusing System;
using System.IO;
class R {
static void Main(string[] a){
using(var fs = new FileStream("\\\\.\\C:", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)){
fs.Position = 0x100000; // seek
var buf = new byte[4096];
fs.Read(buf,0,buf.Length);
File.WriteAllBytes("C:\\temp\\blk.bin", buf);
}
}
}
```
</details>

- 使用支持 NTFS 的工具从 raw volume 恢复特定文件：
- RawCopy/RawCopy64（对正在使用的文件执行 sector-level copy）
- FTK Imager 或 The Sleuth Kit（只读 imaging，然后 carve 文件）
- vssadmin/diskshadow + shadow copy，然后从 snapshot 中复制目标文件（如果可以创建 VSS；通常需要 admin，但持有 SeManageVolumePrivilege 的同一批 operators 通常也能使用）

典型的敏感路径：
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY（local secrets）
- C:\Windows\NTDS\ntds.dit（domain controllers – via shadow copy）
- C:\Windows\System32\CertSrv\CertEnroll\（CA certificates/CRLs；private keys 位于上面的 machine key store）

## AD CS 关联：Forging a Golden Certificate

如果可以从 machine key store 读取 Enterprise CA 的 private key，就可以为任意 principals forge client-auth certificates，并通过 PKINIT/Schannel 进行 authenticate。这通常称为 Golden Certificate。<sup>[[2]](#references)</sup> See:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

（Section：“Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”。）

## Detection and hardening

- 严格限制 SeManageVolumePrivilege（Perform volume maintenance tasks）的分配对象，仅授予 trusted admins。
- 监控 Sensitive Privilege Use，以及对 \\.\C:、\\.\PhysicalDrive0 等 device objects 的 process handle opens。
- 优先使用由 HSM/TPM-backed 的 CA keys，或使用 DPAPI-NG，以便 raw file reads 无法以可用形式恢复 key material。
- 保持 uploads、temp 和 extraction paths 不可执行并相互隔离（这是一种常与此 post-exploitation chain 配合使用的 web context defense）。

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
