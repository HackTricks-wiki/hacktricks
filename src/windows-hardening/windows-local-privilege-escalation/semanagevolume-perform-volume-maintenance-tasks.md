# SeManageVolumePrivilege：滥用卷维护与 raw-access 验证

{{#include ../../banners/hacktricks-training.md}}

## 概述

Windows 用户权限：执行卷维护任务（常量：SeManageVolumePrivilege）。

该权限允许执行碎片整理以及创建或删除卷等卷维护操作。Microsoft 警告称，持有者可能能够将文件扩展到包含其他数据的存储区域中，随后读取或修改所获取的字节。<sup>[[1]](#references)</sup>

不要将拥有 `SeManageVolumePrivilege` 等同于必然具备 raw-disk access。Microsoft 文档指出，通过 `CreateFile` 打开物理磁盘或卷以进行直接访问需要管理权限，正常的对象/设备访问检查仍然适用。在特定 build 或产品上，在声称可以任意读取文件之前，应测试该 token、设备 ACL、请求的 access、share flags 以及卷状态是否允许获取 raw handle。<sup>[[3]](#references)</sup>

默认：服务器和 domain controller 上的 Administrators。<sup>[[1]](#references)</sup>

## 滥用场景

- 如果该账户确实能够获取可读取的 raw-volume handle，则支持 NTFS 的 parser 可以绕过逐文件 ACL，从已分配的 clusters 中恢复受保护或被锁定的文件。
- 可能的目标包括 `C:\Windows\System32` 下被锁定或受 ACL 保护的内容、registry hives、DPAPI master keys、SAM，以及——如果可通过 snapshot 或 offline volume 单独访问——`ntds.dit`。
- 在 certificate services hosts 上，有用的 software-key 位置包括 `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` 和 `%ProgramData%\Microsoft\Crypto\Keys`；恢复文件只有在其 key material 可导出且也能够被解密时才有用。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- 在 AD CS host 上，成功恢复的**可导出/由 software-backed 的** CA private key 可能会启用 Golden Certificate abuse。由硬件支持或不可导出的 key 设计会改变这一路径。<sup>[[2]](#references)</sup>

注意：除非依赖 helper tools，否则仍然需要用于解析 NTFS structures 的 parser。许多现成工具会抽象 raw access。

## 实用技术

- 打开 raw volume handle 并读取 clusters：

<details>
<summary>点击展开</summary>
```powershell
# Validation attempt: current Windows versions normally require an administrative token
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

- 使用支持 NTFS 的工具从 raw volume 中恢复特定文件：
- RawCopy/RawCopy64（对正在使用的文件进行 sector-level copy）
- FTK Imager 或 The Sleuth Kit（只读 imaging，然后 carve 文件）
- vssadmin/diskshadow + shadow copy，然后从 snapshot 中复制目标文件（如果可以创建 VSS；通常需要 admin，但持有 SeManageVolumePrivilege 的同一类 operators 通常也可以使用）

典型的敏感路径：
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY（local secrets）
- C:\Windows\NTDS\ntds.dit（domain controllers – 通过 shadow copy）
- C:\Windows\System32\CertSrv\CertEnroll\（CA certs/CRLs；private keys 位于上面的 machine key store 中）

## AD CS 关联：Forging a Golden Certificate

如果可以从 machine key store 中读取 Enterprise CA 的 private key，就可以为任意 principals forge client-auth certificates，并通过 PKINIT/Schannel 进行 authenticate。这通常称为 Golden Certificate。<sup>[[2]](#references)</sup> 参见：

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

（章节：“Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”。）

## Detection and hardening

- 严格限制 SeManageVolumePrivilege（Perform volume maintenance tasks）的分配范围，仅授予可信的 admins。
- 监控 Sensitive Privilege Use，以及对 \\.\C:、\\.\PhysicalDrive0 等 device objects 的 process handle opens。
- 优先使用配置正确、由 HSM 或 TPM-backed 且 non-exportable 的 CA keys，这样仅复制 key-container file 不足以恢复可用的 private-key material。
- 对于 CA-key path 之外的 application secrets，DPAPI 或 DPAPI-NG 可以通过将 copied data file 保护到 user、machine、group 或其他 authorized principal，使其不足以直接使用。这无法保护 compromised principal 已经能够访问的 plaintext。<sup>[[4]](#references)</sup>
- 确保 uploads、temp 和 extraction paths 不可执行并相互隔离（这是一种常与该 chain post-exploitation 配合使用的 web context defense）。

## References

- [1] [Microsoft – 执行卷维护任务 (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate（使用 SeManageVolumePrivilege 读取 CA key → Golden Certificate）](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` physical disks and volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation and DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
