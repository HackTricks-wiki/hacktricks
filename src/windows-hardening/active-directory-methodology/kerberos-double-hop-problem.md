# Problème Kerberos Double Hop

{{#include ../../banners/hacktricks-training.md}}


## Introduction

Le problème Kerberos "Double Hop" apparaît lorsqu'un attaquant tente d'utiliser l'**authentification Kerberos** sur deux **hops**, par exemple en utilisant **PowerShell**/**WinRM**.

Quand une **authentification** s'effectue via **Kerberos**, les **credentials** ne sont **pas** mis en cache en **mémoire.** Par conséquent, si vous exécutez mimikatz vous **ne trouverez pas les credentials** de l'utilisateur sur la machine même s'il exécute des processus.

Ceci s'explique par les étapes suivantes lors d'une connexion avec Kerberos :

1. User1 fournit ses credentials et le **domain controller** renvoie un Kerberos **TGT** à User1.
2. User1 utilise le **TGT** pour demander un **service ticket** afin de **se connecter** à Server1.
3. User1 **se connecte** à **Server1** et fournit le **service ticket**.
4. **Server1** n'a **pas** en cache les **credentials** de User1 ni le **TGT** de User1. Par conséquent, lorsque User1 depuis Server1 tente de se connecter à un second serveur, il **ne peut pas s'authentifier**.

### Unconstrained Delegation

Si l'**unconstrained delegation** est activée sur le PC, cela ne se produira pas car le **Server** obtiendra un **TGT** pour chaque utilisateur qui y accède. De plus, si unconstrained delegation est utilisée vous pourrez probablement **compromettre le Domain Controller** à partir de cela.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Une autre façon d'éviter ce problème, qui est [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), est **Credential Security Support Provider**. D'après Microsoft :

> CredSSP authentication delegates the user credentials from the local computer to a remote computer. This practice increases the security risk of the remote operation. If the remote computer is compromised, when credentials are passed to it, the credentials can be used to control the network session.

Il est fortement recommandé de désactiver **CredSSP** sur les systèmes de production, les réseaux sensibles et des environnements similaires en raison des préoccupations de sécurité. Pour déterminer si **CredSSP** est activé, la commande `Get-WSManCredSSP` peut être exécutée. Cette commande permet de **vérifier l'état de CredSSP** et peut même être exécutée à distance, à condition que **WinRM** soit activé.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** conserve le TGT de l'utilisateur sur le poste d'origine tout en permettant à la session RDP de demander de nouveaux tickets de service Kerberos sur le saut suivant. Activez **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** et sélectionnez **Require Remote Credential Guard**, puis connectez-vous avec `mstsc.exe /remoteGuard /v:server1` au lieu de revenir à CredSSP.

Microsoft a cassé RCG pour l'accès multi-saut sur Windows 11 22H2+ jusqu'aux **mises à jour cumulatives d'avril 2024** (KB5036896/KB5036899/KB5036894). Patchez le client et le serveur intermédiaire, sinon le second saut échouera toujours. Vérification rapide des hotfix :
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
With those builds installed, the RDP hop can satisfy downstream Kerberos challenges without exposing reusable secrets on the first server.

## Contournements

### Invoke Command

Pour résoudre le problème de double hop, une méthode impliquant un `Invoke-Command` imbriqué est présentée. Cela ne règle pas le problème directement mais offre un contournement sans nécessiter de configurations spéciales. L'approche permet d'exécuter une commande (`hostname`) sur un serveur secondaire via une commande PowerShell lancée depuis une machine d'attaque initiale ou via une PS-Session préalablement établie avec le premier serveur. Voici comment c'est fait :
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativement, il est conseillé d'établir une PS-Session avec le premier serveur et d'exécuter `Invoke-Command` en utilisant `$cred` pour centraliser les tâches.

### Register PSSession Configuration

Une solution pour contourner le double hop consiste à utiliser `Register-PSSessionConfiguration` avec `Enter-PSSession`. Cette méthode nécessite une approche différente de `evil-winrm` et permet d'obtenir une session qui ne souffre pas de la limitation du double hop.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Pour les administrateurs locaux sur une cible intermédiaire, port forwarding permet d'envoyer des requêtes vers un serveur final. En utilisant `netsh`, une règle peut être ajoutée pour le port forwarding, ainsi qu'une Windows firewall rule pour autoriser le forwarded port.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` peut être utilisé pour relayer des requêtes WinRM, potentiellement comme une option moins détectable si la surveillance de PowerShell est un problème. La commande ci‑dessous illustre son utilisation :
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

L'installation d'OpenSSH sur le premier serveur permet un contournement du problème de double-hop, particulièrement utile pour les scénarios de jump box. Cette méthode nécessite l'installation via la CLI et la configuration d'OpenSSH pour Windows. Lorsqu'il est configuré pour l'authentification par mot de passe (Password Authentication), cela permet au serveur intermédiaire d'obtenir un TGT au nom de l'utilisateur.

#### OpenSSH Installation Steps

1. Téléchargez et déplacez le fichier zip de la dernière release d'OpenSSH sur le serveur cible.
2. Décompressez et exécutez le script `Install-sshd.ps1`.
3. Ajoutez une règle de pare-feu pour ouvrir le port 22 et vérifiez que les services SSH sont en cours d'exécution.

Pour résoudre les erreurs `Connection reset`, il peut être nécessaire de mettre à jour les permissions pour accorder à tout le monde les droits de lecture et d'exécution sur le répertoire OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Avancé)

**LSA Whisperer** (2024) rend accessible l'appel de package `msv1_0!CacheLogon` afin que vous puissiez pré-remplir une *ouverture de session réseau* existante avec un NT hash connu au lieu de créer une nouvelle session avec `LogonUser`. En injectant le hash dans l'ouverture de session que WinRM/PowerShell a déjà ouverte sur le saut #1, cet hôte peut s'authentifier au saut #2 sans stocker d'identifiants explicites ni générer d'événements 4624 supplémentaires.

1. Obtenez l'exécution de code dans LSASS (soit en désactivant/abusant de PPL, soit en exécutant sur une VM de laboratoire que vous contrôlez).
2. Énumérez les sessions de logon (p. ex. `lsa.exe sessions`) et capturez le LUID correspondant à votre contexte de remoting.
3. Précalculez le NT hash et fournissez-le à `CacheLogon`, puis supprimez-le une fois terminé.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Après le cache seed, relancez `Invoke-Command`/`New-PSSession` depuis le hop #1 : LSASS réutilisera le hash injecté pour satisfaire les challenges Kerberos/NTLM pour le second hop, contournant proprement la contrainte de double hop. Le compromis est une télémétrie plus importante (exécution de code dans LSASS) — conservez cette méthode pour des environnements à haute friction où CredSSP/RCG sont interdits.

## Références

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
