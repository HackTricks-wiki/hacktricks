# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM est l’un des transports de **lateral movement** les plus pratiques dans les environnements Windows, car il vous donne un shell distant via **WS-Man/HTTP(S)** sans avoir besoin des astuces de création de service SMB. Si la cible expose **5985/5986** et que votre principal est autorisé à utiliser le remoting, vous pouvez souvent passer de « valid creds » à « interactive shell » très rapidement.

Pour l’**énumération du protocole/service**, les listeners, l’activation de WinRM, `Invoke-Command`, et l’utilisation générique du client, consultez :

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Utilise **HTTP/HTTPS** au lieu de SMB/RPC, donc il fonctionne souvent là où l’exécution de type PsExec est bloquée.
- Avec **Kerberos**, il évite d’envoyer des credentials réutilisables à la cible.
- Fonctionne proprement depuis les outils **Windows**, **Linux** et **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Le chemin de remoting PowerShell interactif lance **`wsmprovhost.exe`** sur la cible sous le contexte de l’utilisateur authentifié, ce qui est opérationnellement différent de l’exécution basée sur un service.

## Access model and prerequisites

En pratique, un lateral movement WinRM réussi dépend de **trois** éléments :

1. La cible possède un **WinRM listener** (`5985`/`5986`) et des règles de pare-feu qui autorisent l’accès.
2. Le compte peut **s’authentifier** sur l’endpoint.
3. Le compte est autorisé à **ouvrir une session de remoting**.

Façons courantes d’obtenir cet accès :

- **Local Administrator** sur la cible.
- Appartenance à **Remote Management Users** sur les systèmes plus récents ou à **WinRMRemoteWMIUsers__** sur les systèmes/composants qui prennent encore en charge ce groupe.
- Droits explicites de remoting délégués via des descripteurs de sécurité locaux / des changements d’ACL de PowerShell remoting.

Si vous contrôlez déjà une machine avec des droits admin, rappelez-vous que vous pouvez aussi **déléguer l’accès WinRM sans appartenance complète au groupe admin** en utilisant les techniques décrites ici :

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**. Si vous vous connectez par IP, le client bascule généralement vers **NTLM/Negotiate**.
- En cas de **workgroup** ou de situations trans-trust particulières, NTLM nécessite souvent soit **HTTPS**, soit que la cible soit ajoutée à **TrustedHosts** sur le client.
- Avec des **local accounts** via Negotiate dans un workgroup, les restrictions UAC remote peuvent empêcher l’accès sauf si le compte Administrator intégré est utilisé ou si `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting utilise par défaut le SPN **`HTTP/<host>`**. Dans les environnements où **`HTTP/<host>`** est déjà enregistré pour un autre service account, WinRM Kerberos peut échouer avec `0x80090322`; utilisez un SPN qualifié par le port ou basculez vers **`WSMAN/<host>`** lorsque ce SPN existe.

Si vous obtenez des credentials valides lors d’un password spraying, les valider via WinRM est souvent la façon la plus rapide de vérifier s’ils donnent accès à un shell :

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

`evil-winrm` reste l’option interactive la plus pratique depuis Linux car il prend en charge les **passwords**, les **NT hashes**, les **Kerberos tickets**, les **client certificates**, le transfert de fichiers et le chargement en mémoire de PowerShell/.NET.
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

Lorsque le SPN par défaut **`HTTP/<host>`** provoque des échecs Kerberos, essayez de demander/utiliser à la place un ticket **`WSMAN/<host>`**. Cela se produit dans des configurations d’entreprise durcies ou inhabituelles où **`HTTP/<host>`** est déjà associé à un autre compte de service.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Ceci est aussi utile après un abus de **RBCD / S4U** lorsque vous avez spécifiquement forgé ou demandé un ticket de service **WSMAN** plutôt qu’un ticket `HTTP` générique.

### Authentification basée sur un certificat

WinRM prend aussi en charge l’**authentification par certificat client**, mais le certificat doit être mappé sur la cible à un **compte local**. D’un point de vue offensif, cela est important lorsque :

- vous avez déjà volé/exporté un certificat client valide et une clé privée déjà mappés pour WinRM ;
- vous avez abusé de **AD CS / Pass-the-Certificate** pour obtenir un certificat pour un principal puis basculer vers un autre chemin d’authentification ;
- vous opérez dans des environnements qui évitent délibérément le remoting basé sur mot de passe.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM est bien moins courant que l’authentification par password/hash/Kerberos, mais lorsqu’il existe, il peut fournir une voie de **lateral movement sans mot de passe** qui survit à la rotation des mots de passe.

### Python / automation with `pypsrp`

Si vous avez besoin d’automation plutôt que d’un shell opérateur, `pypsrp` vous donne WinRM/PSRP depuis Python avec le support de **NTLM**, **certificate auth**, **Kerberos** et **CredSSP**.
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
## Mouvement latéral WinRM natif à Windows

### `winrs.exe`

`winrs.exe` est intégré et utile lorsque vous souhaitez une **exécution de commandes WinRM native** sans ouvrir une session de remoting PowerShell interactive :
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Opérationnellement, `winrs.exe` aboutit généralement à une chaîne de processus distants similaire à :
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
C’est utile de s’en souvenir car cela diffère de l’exec basé sur les services et des sessions PSRP interactives.

### `winrm.cmd` / WS-Man COM instead of PowerShell remoting

Vous pouvez aussi exécuter via le **transport WinRM** sans `Enter-PSSession` en invoquant des classes WMI sur WS-Man. Cela conserve le transport WinRM tandis que le primitive d’exécution à distance devient **WMI `Win32_Process.Create`** :
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Cette approche est utile lorsque :

- La journalisation PowerShell est fortement surveillée.
- Vous voulez le **WinRM transport** mais pas un workflow classique de remoting PS.
- Vous construisez ou utilisez des outils custom autour de l’objet COM **`WSMan.Automation`**.

## NTLM relay vers WinRM (WS-Man)

Lorsque le SMB relay est bloqué par le signing et que le LDAP relay est contraint, **WS-Man/WinRM** peut encore être une cible de relay attrayante. `ntlmrelayx.py` moderne inclut des **WinRM relay servers** et peut relayer vers des cibles **`wsman://`** ou **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Deux notes pratiques :

- Relay est surtout utile lorsque la cible accepte **NTLM** et que le principal relayé est autorisé à utiliser WinRM.
- Le code récent d’Impacket gère spécifiquement les requêtes **`WSMANIDENTIFY: unauthenticated`** afin que les probes de type `Test-WSMan` ne cassent pas le flux de relay.

Pour les contraintes multi-hop après avoir obtenu une première session WinRM, consulte :

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Notes OPSEC et détection

- Le remoting PowerShell interactif crée généralement **`wsmprovhost.exe`** sur la cible.
- **`winrs.exe`** crée généralement **`winrshost.exe`**, puis le processus enfant demandé.
- Attendez-vous à de la télémétrie de **network logon**, à des événements du service WinRM, et à la journalisation PowerShell operational/script-block si vous utilisez PSRP plutôt que `cmd.exe` brut.
- Si vous n’avez besoin que d’une seule commande, `winrs.exe` ou une exécution WinRM en une seule fois peut être plus discret qu’une session de remoting interactive de longue durée.
- Si Kerberos est disponible, privilégiez **FQDN + Kerberos** plutôt que IP + NTLM afin de réduire à la fois les problèmes de confiance et les modifications client maladroites de `TrustedHosts`.

## Références

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
