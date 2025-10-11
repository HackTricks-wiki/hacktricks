# SeManageVolumePrivilege: 原始卷访问以进行任意文件读取

{{#include ../../banners/hacktricks-training.md}}

## 概述

Windows 用户权限：执行卷维护任务（常量：SeManageVolumePrivilege）。

持有该权限的用户可以执行低级卷操作，例如磁盘碎片整理、创建/删除卷以及维护型 IO。对于攻击者而言，这个权限尤为关键，因为它允许打开原始卷设备句柄（例如 \\.\C:）并发出直接的磁盘 I/O，从而绕过 NTFS 文件 ACLs。通过原始访问，可以复制卷上任何文件的字节，即使被 DACL 阻止，也可以通过离线解析文件系统结构或利用在块/簇级别读取的工具来实现。

默认：服务器和域控制器上的 Administrators 组。

## 滥用场景

- 通过读取磁盘设备绕过 ACLs 进行任意文件读取（例如，外泄受系统保护的敏感材料，如位于 %ProgramData%\Microsoft\Crypto\RSA\MachineKeys 和 %ProgramData%\Microsoft\Crypto\Keys 下的机器私钥、注册表 hives、DPAPI masterkeys、SAM、通过 VSS 获取的 ntds.dit 等）。
- 通过直接从原始设备复制字节来绕过被锁定/受限路径（C:\Windows\System32\…）。
- 在 AD CS 环境中，外泄 CA 的密钥材料（机器密钥存储）以铸造 “Golden Certificates”，并通过 PKINIT 模拟任何域主体。见下方链接。

注意：除非依赖辅助工具，否则仍需要用于解析 NTFS 结构的解析器。许多现成工具已封装了对原始访问的抽象。

## 实用技术

- 打开原始卷句柄并读取簇：

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

- 使用支持 NTFS 的工具从原始卷中恢复特定文件：
- RawCopy/RawCopy64（对正在使用的文件进行扇区级复制）
- FTK Imager or The Sleuth Kit（只读镜像，然后从中 carve 出文件）
- vssadmin/diskshadow + shadow copy，然后从快照中复制目标文件（如果你能创建 VSS；通常需要管理员权限，但通常对拥有 SeManageVolumePrivilege 的同一类操作员可用）

典型的敏感目标路径：
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS 关联：伪造 Golden Certificate

如果你能从 machine key store 读取 Enterprise CA 的私钥，就可以为任意主体伪造 client‑auth 证书，并通过 PKINIT/Schannel 进行认证。这通常被称为 Golden Certificate。参见：

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## 检测与加固

- 严格限制 SeManageVolumePrivilege (Perform volume maintenance tasks) 的分配，仅限可信管理员。
- 监控 Sensitive Privilege Use 和进程对设备对象（如 \\.\C:, \\.\PhysicalDrive0）的句柄打开。
- 优先使用 HSM/TPM 支持的 CA 密钥或 DPAPI-NG，以便原始文件读取无法以可用形式恢复密钥材料。
- 保持上传、临时和提取路径为不可执行并相互隔离（这是在 web 场景下常与此类利用链后期配套的防御措施）。

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
