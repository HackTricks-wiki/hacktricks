# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM est l’un des transports de **lateral movement** les plus pratiques dans les environnements Windows, car il fournit un shell distant via **WS-Man/HTTP(S)** sans avoir recours aux astuces de création de services SMB. Si la cible expose **5985/5986** et que votre principal est autorisé à utiliser le remoting, vous pouvez souvent passer très rapidement de « identifiants valides » à « shell interactif ».

Pour l’énumération du **protocole/service**, les listeners, l’activation de WinRM, `Invoke-Command` et l’utilisation générique d’un client, consultez :

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Pourquoi les opérateurs apprécient WinRM

- Utilise **HTTP/HTTPS** au lieu de SMB/RPC : il fonctionne donc souvent dans les environnements où l’exécution de type PsExec est bloquée.
- Avec **Kerberos**, il évite d’envoyer des identifiants réutilisables à la cible.
- Fonctionne sans difficulté avec les outils **Windows**, **Linux** et **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Le remoting PowerShell interactif lance **`wsmprovhost.exe`** sur la cible dans le contexte de l’utilisateur authentifié, ce qui diffère sur le plan opérationnel de l’exécution par service.

## Modèle d’accès et prérequis

En pratique, la réussite du lateral movement via WinRM dépend de **trois** éléments :

1. La cible dispose d’un **listener WinRM** (`5985`/`5986`) et de règles de pare-feu qui autorisent l’accès.
2. Le compte peut **s’authentifier** auprès du endpoint.
3. Le compte est autorisé à **ouvrir une session de remoting**.

Voici quelques moyens courants d’obtenir cet accès :

- Être **administrateur local** sur la cible.
- Appartenir au groupe **Remote Management Users** sur les systèmes récents ou à **WinRMRemoteWMIUsers__** sur les systèmes/composants qui prennent encore en compte ce groupe.
- Disposer de droits de remoting explicitement délégués via les descripteurs de sécurité locaux ou des modifications des ACL de PowerShell remoting.

Si vous contrôlez déjà une machine avec des droits d’administration, n’oubliez pas que vous pouvez également **déléguer l’accès WinRM sans appartenir au groupe des administrateurs** à l’aide des techniques décrites ici :

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Particularités de l’authentification importantes pour le lateral movement

- **Kerberos exige un nom d’hôte/FQDN**. Si vous vous connectez par adresse IP, le client utilise généralement **NTLM/Negotiate**.
- Dans un **workgroup** ou certains cas limites entre domaines de confiance, NTLM nécessite généralement soit **HTTPS**, soit que la cible soit ajoutée à **TrustedHosts** sur le client.
- Avec des comptes locaux via Negotiate dans un workgroup, les restrictions UAC à distance peuvent bloquer l’accès, sauf si le compte Administrator intégré est utilisé ou si `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting utilise par défaut le SPN **`HTTP/<host>`**. Dans les environnements où **`HTTP/<host>`** est déjà associé à un autre compte de service, Kerberos WinRM peut échouer avec `0x80090322` ; utilisez un SPN précisant le port ou passez à **`WSMAN/<host>`** si ce SPN existe.<sup>[[3]](#references)</sup>

Si vous obtenez des identifiants valides lors d’une attaque par password spraying, les tester via WinRM est souvent le moyen le plus rapide de vérifier s’ils permettent d’obtenir un shell :

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

### Cas particulier de Kerberos : `HTTP` vs `WSMAN`

Lorsque le SPN **`HTTP/<host>`** par défaut entraîne des échecs Kerberos, essayez plutôt de demander/utiliser un ticket **`WSMAN/<host>`**. Cela se produit dans des environnements d’entreprise renforcés ou atypiques où **`HTTP/<host>`** est déjà associé à un autre compte de service.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Cette méthode est également utile après un abus de **RBCD / S4U**, lorsque vous avez spécifiquement forgé ou demandé un ticket de service **WSMAN** plutôt qu’un ticket `HTTP` générique.

### Authentification par certificat

WinRM prend également en charge l’**authentification par certificat client**, mais le certificat doit être associé à un **compte local** sur la cible. Du point de vue offensif, cela compte lorsque :

- vous avez déjà volé/exporté un certificat client valide et sa clé privée, associés à WinRM ;
- vous avez exploité **AD CS / Pass-the-Certificate** pour obtenir un certificat pour un principal, puis vous pivotez vers une autre méthode d’authentification ;
- vous opérez dans des environnements qui évitent délibérément l’administration à distance par mot de passe.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

L’authentification WinRM par certificat client est beaucoup moins courante que l’authentification par mot de passe/hash/Kerberos, mais lorsqu’elle est disponible, elle peut fournir une voie de **lateral movement sans mot de passe** qui résiste à la rotation des mots de passe.

### Python / automatisation avec `pypsrp`

Si vous avez besoin d’automatisation plutôt que d’un shell opérateur, `pypsrp` permet d’utiliser WinRM/PSRP depuis Python et prend en charge **NTLM**, **l’authentification par certificat**, **Kerberos** et **CredSSP**.<sup>[[2]](#references)</sup>

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


Si vous avez besoin d’un contrôle plus précis que celui offert par le wrapper `Client` de haut niveau, les API `WSMan` + `RunspacePool` de plus bas niveau sont utiles pour résoudre deux problèmes courants rencontrés par les opérateurs :

- imposer **`WSMAN`** comme service/SPN Kerberos au lieu de l’attente par défaut **`HTTP`** utilisée par de nombreux clients PowerShell ;
- se connecter à un **endpoint PSRP non défini par défaut**, comme une configuration de session **JEA** / personnalisée, plutôt qu’à `Microsoft.PowerShell`.

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

Une authentification WinRM réussie ne signifie **pas** toujours que vous accédez à l’endpoint `Microsoft.PowerShell` par défaut, sans restriction. Les environnements matures peuvent exposer des **configurations de session personnalisées** ou des endpoints **JEA**, avec leurs propres ACL et leur propre comportement d’exécution sous une autre identité.<sup>[[1]](#references)</sup>

Si vous avez déjà obtenu l’exécution de code sur un hôte Windows et souhaitez comprendre quelles surfaces de remoting sont disponibles, énumérez les endpoints enregistrés :

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Lorsqu’un endpoint utile existe, ciblez-le explicitement plutôt que le shell par défaut :

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Implications pratiques en offensive :

- Un endpoint **restreint** peut suffire au lateral movement s'il expose juste les cmdlets/fonctions nécessaires au contrôle des services, à l'accès aux fichiers, à la création de processus ou à l'exécution arbitraire de commandes .NET / externes.
- Un rôle **JEA mal configuré** est particulièrement intéressant s'il expose des commandes dangereuses comme `Start-Process`, des jokers trop larges, des fournisseurs accessibles en écriture ou des fonctions proxy personnalisées permettant de contourner les restrictions prévues.
- Les endpoints s'appuyant sur des comptes virtuels **RunAs** ou des **gMSA** modifient le contexte de sécurité effectif des commandes exécutées. En particulier, un endpoint adossé à un gMSA peut fournir une **identité réseau au second saut**, même lorsqu'une session WinRM normale se heurte au problème classique de délégation.

Pour un endpoint restreint personnalisé, examinez séparément les permissions effectives sur les commandes et les scripts : une courte liste `Get-Command` ne prouve pas à elle seule qu'un fichier `.ps1` existant ne peut pas être exécuté. Les [capacités de rôle JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) définissent explicitement les chemins de script qui peuvent être invoqués ; d'autres endpoints personnalisés peuvent appliquer des règles de session différentes. Si un script autorisé utilise une `SecureString` stockée pour créer des identifiants destinés à un autre hôte, un blob créé sans clé explicite utilise [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) et nécessite généralement le contexte de l'utilisateur et de la machine qui l'a protégé pour être déchiffré. Vérifiez l'ACL du script, les conditions d'invocation, l'identité d'exécution et les droits des identifiants en aval avant de considérer une source modifiable ou un blob copié comme une voie d'escalade entre hôtes. N'affichez pas la valeur protégée lors d'une énumération passive.

Pour une fonction personnalisée JEA qui accepte un chemin de fichier, examinez ensemble l'ACL de l'endpoint enregistré, la capacité de rôle associée et l'identité d'exécution effective. L'appelant peut être en mode `NoLanguage` alors que le corps de la fonction s'exécute dans le mode de langage par défaut du système ; un compte virtuel peut également disposer de droits d'administrateur local. Si la fonction vérifie un répertoire autorisé à l'aide d'un préfixe de chaîne brut, puis lit le chemin fourni, les composants `..` peuvent mener en dehors de ce répertoire. La limite est le chemin résolu sous l'identité de la fonction, et non le mode de langage de l'appelant ou le préfixe apparent. Confirmez que la fonction est accessible et que la validation porte sur le chemin final avant de considérer un fichier `.psrc` ou `.pssc` lisible comme une découverte de lecture de fichier privilégiée. Consultez les recommandations de Microsoft sur les [capacités de rôle JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) et les [considérations de sécurité](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Mouvement latéral WinRM natif à Windows

### `winrs.exe`

`winrs.exe` est intégré à Windows et pratique lorsque vous souhaitez **exécuter des commandes via WinRM de manière native** sans ouvrir de session PowerShell Remoting interactive :

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Deux options sont faciles à oublier et importantes en pratique :

- `/noprofile` est souvent nécessaire lorsque le principal distant n’est **pas** un administrateur local.
- `/allowdelegate` permet au shell distant d’utiliser vos identifiants auprès d’un **troisième hôte** (par exemple, lorsque la commande doit accéder à `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Sur le plan opérationnel, `winrs.exe` entraîne généralement une chaîne de processus distante similaire à :

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Cela mérite d’être retenu, car cette méthode diffère de l’exécution basée sur les services et des sessions PSRP interactives.

### `winrm.cmd` / WS-Man COM au lieu de PowerShell remoting

Vous pouvez également exécuter des commandes via le **transport WinRM** sans utiliser `Enter-PSSession`, en invoquant des classes WMI via WS-Man. Le transport reste ainsi WinRM, tandis que le mécanisme d’exécution à distance devient **WMI `Win32_Process.Create`** :

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Cette approche est utile lorsque :

- La journalisation PowerShell est fortement surveillée.
- Vous voulez le **transport WinRM**, mais pas un workflow classique de PS remoting.
- Vous développez ou utilisez des outils personnalisés autour de l’objet COM **`WSMan.Automation`**.

## Relais NTLM vers WinRM (WS-Man)

Lorsque le relais SMB est bloqué par la signature et que le relais LDAP est limité, **WS-Man/WinRM** peut rester une cible de relais intéressante. Les versions modernes de `ntlmrelayx.py` incluent des serveurs de relais WinRM et peuvent relayer vers des cibles **`wsman://`** ou **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Deux remarques pratiques :

- Le relay est particulièrement utile lorsque la cible accepte **NTLM** et que le principal relayé est autorisé à utiliser WinRM.
- Le code récent d’Impacket gère spécifiquement les requêtes **`WSMANIDENTIFY: unauthenticated`**, afin que les sondes de type `Test-WSMan` n’interrompent pas le flux du relay.

Pour les contraintes multi-hop après avoir obtenu une première session WinRM, consultez :

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Remarques sur l’OPSEC et la détection

- Le **remoting PowerShell interactif** crée généralement **`wsmprovhost.exe`** sur la cible.
- **`winrs.exe`** crée généralement **`winrshost.exe`**, puis le processus enfant demandé.
- Les points de terminaison **JEA** personnalisés peuvent exécuter des actions en tant que comptes virtuels **`WinRM_VA_*`** ou en tant que **gMSA** configuré, ce qui modifie la télémétrie et le comportement du second hop par rapport à un shell exécuté dans le contexte d’un utilisateur classique.<sup>[[1]](#references)</sup>
- Si vous utilisez PSRP plutôt que `cmd.exe` brut, attendez-vous à des événements de connexion réseau, à des événements du service WinRM et à la journalisation opérationnelle/de blocs de script PowerShell.
- Si vous n’avez besoin que d’exécuter une seule commande, `winrs.exe` ou une exécution WinRM ponctuelle peut être plus discrète qu’une longue session de remoting interactive.
- Si Kerberos est disponible, privilégiez **FQDN + Kerberos** plutôt que IP + NTLM pour réduire les problèmes de confiance et éviter les modifications gênantes de `TrustedHosts` côté client.

## References

- [1] [Microsoft : Considérations de sécurité JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [README de pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft : Erreur `0x80090322` lors de la connexion de PowerShell à un serveur distant via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
