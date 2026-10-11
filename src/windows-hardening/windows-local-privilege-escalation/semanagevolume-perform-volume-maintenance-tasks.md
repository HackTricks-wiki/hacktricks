# SeManageVolumePrivilege：滥用卷维护权限与原始访问验证

{{#include ../../banners/hacktricks-training.md}}

## 概述

Windows 用户权限：执行卷维护任务（常量：SeManageVolumePrivilege）。

该权限允许执行卷维护操作，例如碎片整理以及创建或删除卷。Microsoft 警告称，持有此权限的用户可能能够将文件扩展到包含其他数据的存储区域，然后读取或修改获取到的字节。<sup>[[1]](#references)</sup>

不要将拥有 `SeManageVolumePrivilege` 等同于必然拥有原始磁盘访问权限。Microsoft 文档指出，通过 `CreateFile` 打开物理磁盘或卷以进行直接访问需要管理员权限，并且仍会执行常规的对象/设备访问检查。在特定的系统版本或产品上，声称能够任意读取文件前，应先测试令牌、设备 ACL、请求的访问权限、共享标志和卷状态是否允许获取原始句柄。<sup>[[3]](#references)</sup>

默认：服务器和域控制器上的 Administrators。<sup>[[1]](#references)</sup>

## 滥用场景

- 如果账户确实能获取可读的原始卷句柄，支持 NTFS 的解析器便可绕过逐文件 ACL，从已分配的簇中恢复受保护或锁定的文件。
- 可能的目标包括 `C:\Windows\System32` 下被锁定或受 ACL 保护的内容、注册表配置单元、DPAPI 主密钥、SAM，以及——在可通过快照或脱机卷单独访问的情况下——`ntds.dit`。
- 在证书服务主机上，有用的软件密钥位置包括 `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` 和 `%ProgramData%\Microsoft\Crypto\Keys`；只有当密钥材料可导出且能够解密时，恢复文件才有用。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- 在 AD CS 主机上，成功恢复**可导出/由软件支持的** CA 私钥可能会导致 Golden Certificate 滥用。硬件支持或不可导出的密钥设计会改变这条路径。<sup>[[2]](#references)</sup>
- 某些卷维护工具会在操作获准时使用 `FSCTL_SD_GLOBAL_CHANGE` 替换文件系统 ACL 项。这会更改访问控制，而不是被动读取原始块；它可能影响卷的大部分区域，因此必须根据实际令牌和设备行为进行验证。[工具源码](https://github.com/CsEnox/SeManageVolumeExploit)展示了这一特定机制；仅仅拥有此权限并不能证明操作会成功。
- 通过更改 ACL 获得文件访问权限，并不会解密 EFS 加密文件。要获取明文，仍需要匹配的用户私钥或恢复私钥。同样，使用 [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) 导出由软件支持的 CA 密钥，取决于密钥是否可在本地使用、可导出且可访问。

注意：除非依赖辅助工具，否则仍需要解析器来处理 NTFS 结构。许多现成工具已封装了原始访问操作。

## 实用技术

- 打开原始卷句柄并读取簇：

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

- 使用支持 NTFS 的工具从原始卷中恢复特定文件：
  - RawCopy/RawCopy64（对正在使用的文件进行扇区级复制）
  - FTK Imager 或 The Sleuth Kit（以只读方式创建映像，然后 carve 文件）
  - vssadmin/diskshadow + 卷影副本，然后从快照中复制目标文件（如果可以创建 VSS；通常需要管理员权限，但通常持有 SeManageVolumePrivilege 的同一批操作者也可以使用）

常见的敏感目标路径：
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY（本地机密）
- C:\Windows\NTDS\ntds.dit（域控制器 – 通过卷影副本）
- C:\Windows\System32\CertSrv\CertEnroll\（CA 证书/CRL；私钥位于上述机器密钥存储区）

## AD CS 关联：伪造 Golden Certificate

如果你可以读取机器密钥存储区中的 Enterprise CA 私钥，就可以为任意主体伪造客户端身份验证证书，并通过 PKINIT/Schannel 进行身份验证。这通常称为 Golden Certificate。<sup>[[2]](#references)</sup> 参见：

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

（章节：“使用窃取的 CA 证书伪造证书（Golden Certificate）– DPERSIST1”。）

## 检测与加固

- 严格限制 SeManageVolumePrivilege（Perform volume maintenance tasks）的分配，仅授予可信管理员。
- 监控敏感特权使用情况，以及对 \\.\C:、\\.\PhysicalDrive0 等设备对象的进程句柄打开操作。
- 优先使用配置妥当、由 HSM 或 TPM 支持且不可导出的 CA 密钥，这样复制密钥容器文件不足以恢复可用的私钥材料。
- 对于 CA 密钥路径之外的应用程序机密，DPAPI 或 DPAPI-NG 可以将其保护到用户、计算机、组或其他授权主体，从而使复制数据文件不足以获取机密。这无法保护已能被受攻击主体访问的明文。<sup>[[4]](#references)</sup>
- 确保上传、临时和解压路径不可执行且彼此隔离（这是一种 Web 上下文防御措施，通常与此 post‑exploitation 攻击链配合使用）。

## References

- [1] [Microsoft – 执行卷维护任务 (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate（使用 SeManageVolumePrivilege 读取 CA 密钥 → Golden Certificate）](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` 物理磁盘和卷](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - 加密 API：下一代和 DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
