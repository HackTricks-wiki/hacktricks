# Interesting Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

### **Windows Version and Owner Info**

- Located at **`Software\Microsoft\Windows NT\CurrentVersion`**, you will find the Windows verzija, Service Pack, vreme instalacije i ime registrovanog vlasnika na jednostavan način.

### **Computer Name**

- Ime računara se nalazi pod **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Time Zone Setting**

- Vremenska zona sistema se čuva u **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Access Time Tracking**

- Po defaultu, praćenje poslednjeg vremena pristupa je isključeno (**`NtfsDisableLastAccessUpdate=1`**). Da biste ga omogućili, koristite:
`fsutil behavior set disablelastaccess 0`

### Windows Versions and Service Packs

- **Windows verzija** označava izdanje (npr. Home, Pro) i njegovu verziju (npr. Windows 10, Windows 11), dok su **Service Packs** ažuriranja koja uključuju ispravke i, ponekad, nove funkcije.

### Enabling Last Access Time

- Omogućavanje praćenja poslednjeg vremena pristupa omogućava vam da vidite kada su datoteke poslednji put otvorene, što može biti ključno za forenzičku analizu ili praćenje sistema.

### Network Information Details

- Registry sadrži opsežne podatke o mrežnim konfiguracijama, uključujući **tipove mreža (bežične, kablovske, 3G)** i **kategorije mreža (Javna, Privatna/Domaća, Domen/Rad)**, što je od vitalnog značaja za razumevanje mrežnih bezbednosnih postavki i dozvola.

### Client Side Caching (CSC)

- **CSC** poboljšava pristup offline datotekama keširanjem kopija deljenih datoteka. Različita podešavanja **CSCFlags** kontrolišu kako i koje datoteke se keširaju, utičući na performanse i korisničko iskustvo, posebno u okruženjima sa povremenom povezanošću.

### AutoStart Programs

- Programi navedeni u raznim `Run` i `RunOnce` registry ključevima automatski se pokreću pri pokretanju, utičući na vreme podizanja sistema i potencijalno predstavljajući tačke interesa za identifikaciju malvera ili neželjenog softvera.

### Shellbags

- **Shellbags** ne samo da čuvaju podešavanja za prikaz foldera, već takođe pružaju forenzičke dokaze o pristupu folderima čak i ako folder više ne postoji. Oni su neprocenjivi za istrage, otkrivajući aktivnost korisnika koja nije očigledna kroz druge načine.

### USB Information and Forensics

- Detalji pohranjeni u registry o USB uređajima mogu pomoći u praćenju koji su uređaji bili povezani sa računarom, potencijalno povezujući uređaj sa osetljivim prenosima datoteka ili incidentima neovlašćenog pristupa.

### Volume Serial Number

- **Volume Serial Number** može biti ključan za praćenje specifične instance datotečnog sistema, korisno u forenzičkim scenarijima gde je potrebno utvrditi poreklo datoteke preko različitih uređaja.

### **Shutdown Details**

- Vreme gašenja i broj (potonji samo za XP) se čuvaju u **`System\ControlSet001\Control\Windows`** i **`System\ControlSet001\Control\Watchdog\Display`**.

### **Network Configuration**

- Za detaljne informacije o mrežnim interfejsima, pogledajte **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Prva i poslednja vremena mrežne veze, uključujući VPN veze, beleže se pod raznim putanjama u **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Shared Folders**

- Deljeni folderi i podešavanja su pod **`System\ControlSet001\Services\lanmanserver\Shares`**. Podešavanja Client Side Caching (CSC) određuju dostupnost offline datoteka.

### **Programs that Start Automatically**

- Putanje kao što su **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** i slični unosi pod `Software\Microsoft\Windows\CurrentVersion` detaljno opisuju programe postavljene da se pokreću pri pokretanju.

### **Searches and Typed Paths**

- Istraživanja u Exploreru i unesene putanje se prate u registry pod **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** za WordwheelQuery i TypedPaths, respektivno.

### **Recent Documents and Office Files**

- Nedavne datoteke i Office datoteke koje su pristupane beleže se u `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` i specifičnim putanjama verzije Office-a.

### **Most Recently Used (MRU) Items**

- MRU liste, koje ukazuju na nedavne putanje datoteka i komande, čuvaju se u raznim `ComDlg32` i `Explorer` podključevima pod `NTUSER.DAT`.

### **User Activity Tracking**

- Funkcija User Assist beleži detaljne statistike korišćenja aplikacija, uključujući broj pokretanja i vreme poslednjeg pokretanja, na **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Shellbags Analysis**

- Shellbags, koji otkrivaju detalje o pristupu folderima, čuvaju se u `USRCLASS.DAT` i `NTUSER.DAT` pod `Software\Microsoft\Windows\Shell`. Koristite **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** za analizu.

### **USB Device History**

- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** i **`HKLM\SYSTEM\ControlSet001\Enum\USB`** sadrže bogate detalje o povezanim USB uređajima, uključujući proizvođača, naziv proizvoda i vremenske oznake povezivanja.
- Korisnik povezan sa specifičnim USB uređajem može se precizno odrediti pretraživanjem `NTUSER.DAT` hives za **{GUID}** uređaja.
- Poslednji montirani uređaj i njegov broj serije volumena mogu se pratiti kroz `System\MountedDevices` i `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, respektivno.

This guide condenses the crucial paths and methods for accessing detailed system, network, and user activity information on Windows systems, aiming for clarity and usability.

{{#include ../../../banners/hacktricks-training.md}}
