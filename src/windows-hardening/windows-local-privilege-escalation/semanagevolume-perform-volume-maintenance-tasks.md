# SeManageVolumePrivilege: 原始卷访问以进行任意文件读取

{{#include ../../banners/hacktricks-training.md}}

## 概述

Windows 用户权限：Perform volume maintenance tasks (constant: SeManageVolumePrivilege)。

持有者可以执行低级卷操作，例如碎片整理、创建/删除卷以及维护 IO。对攻击者来说关键的是，此权限允许打开原始卷设备句柄（例如 \\.\C:）并发出直接磁盘 I/O，从而绕过 NTFS 文件 ACLs。通过原始访问，你可以读取卷上任意文件的字节，即使 DACL 拒绝，也可以通过离线解析文件系统结构或利用以块/簇级别读取的工具来复制文件内容。

默认：服务器和域控制器上的 Administrators。

## 滥用场景

- 通过读取磁盘设备进行任意文件读取以绕过 ACLs（例如，exfiltrate 受系统保护的敏感材料，如位于 %ProgramData%\Microsoft\Crypto\RSA\MachineKeys 和 %ProgramData%\Microsoft\Crypto\Keys 下的 machine private keys、注册表 hives、DPAPI masterkeys、SAM、通过 VSS 的 ntds.dit 等）。
- 绕过被锁定/受限路径（C:\Windows\System32\…），直接从原始设备复制字节。
- 在 AD CS 环境中，exfiltrate CA 的密钥材料（machine key store）以伪造“Golden Certificates”，并通过 PKINIT 冒充任何域主体。见下方链接。

注意：除非依赖辅助工具，否则你仍需要一个用于解析 NTFS 结构的解析器。许多现成工具会对原始访问进行抽象处理。

## 实用技巧

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

- 使用支持 NTFS 的工具从原始卷恢复特定文件：
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
- vssadmin/diskshadow + shadow copy, then copy target file from the snapshot (if you can create VSS; often requires admin but commonly available to the same operators that hold SeManageVolumePrivilege)

典型的敏感目标路径：
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS 关联: Forging a Golden Certificate

If you can read the Enterprise CA’s private key from the machine key store, you can forge client‑auth certificates for arbitrary principals and authenticate via PKINIT/Schannel. This is often referred to as a Golden Certificate. See:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## 检测与加固

- 严格限制 SeManageVolumePrivilege (Perform volume maintenance tasks) 的分配，只授予受信任的管理员。
- 监控敏感权限使用以及对设备对象（如 \\.\C:, \\.\PhysicalDrive0）的进程句柄打开。
- 优先使用 HSM/TPM 支持的 CA 密钥或 DPAPI-NG，以防通过原始文件读取恢复到可用形式的密钥材料。
- 保持上传、临时和解压路径为不可执行且相互隔离（这是在 web 场景下常与此类链路后利用配对的防御措施）。

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
