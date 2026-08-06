# Problème du Double Hop Kerberos

{{#include ../../banners/hacktricks-training.md}}


## Introduction

Le problème du « Double Hop » Kerberos apparaît lorsqu'un attaquant tente d'utiliser l'**authentification Kerberos sur deux** **hops**, par exemple avec **PowerShell**/**WinRM**.

Lorsqu'une **authentification** s'effectue via **Kerberos**, les **credentials** **ne sont pas** mis en cache en **mémoire.** Par conséquent, si vous exécutez mimikatz, vous **ne trouverez pas les credentials** de l'utilisateur sur la machine, même s'il exécute des processus.

Cela s'explique par les étapes suivantes lors d'une connexion avec Kerberos :<sup>[[1]](#references)</sup>

1. User1 fournit ses credentials et le **contrôleur de domaine** renvoie un **TGT** Kerberos à User1.
2. User1 utilise le **TGT** pour demander un **service ticket** afin de se **connecter** à Server1.
3. User1 se **connecte** à **Server1** et fournit le **service ticket**.
4. **Server1** ne dispose pas des **credentials** de User1 en cache ni du **TGT** de User1. Par conséquent, lorsque User1 tente depuis Server1 de se connecter à un second serveur, il **ne peut pas s'authentifier**.

### Unconstrained Delegation

Si l'**unconstrained delegation** est activée sur le PC, cela ne se produira pas, car le **Server** **obtiendra** le **TGT** de chaque utilisateur qui y accède. De plus, si l'unconstrained delegation est utilisée, vous pourrez probablement **compromettre le contrôleur de domaine** depuis celui-ci.\
[**Plus d'informations sur la page consacrée à l'unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Une autre manière d'éviter ce problème, qui est [**particulièrement peu sécurisée**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), est d'utiliser **Credential Security Support Provider**. D'après Microsoft :

> L'authentification CredSSP délègue les credentials de l'utilisateur de l'ordinateur local à un ordinateur distant. Cette pratique augmente le risque de sécurité lié à l'opération distante. Si l'ordinateur distant est compromis lorsque les credentials lui sont transmis, ceux-ci peuvent être utilisés pour contrôler la session réseau.

Il est fortement recommandé de désactiver **CredSSP** sur les systèmes de production, les réseaux sensibles et les environnements similaires en raison des problèmes de sécurité. Pour déterminer si **CredSSP** est activé, la commande `Get-WSManCredSSP` peut être exécutée. Cette commande permet de **vérifier l'état de CredSSP** et peut même être exécutée à distance, à condition que **WinRM** soit activé.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** conserve le TGT de l'utilisateur sur le poste de travail d'origine tout en permettant à la session RDP de demander de nouveaux tickets de service Kerberos au niveau du hop suivant. Activez **Configuration ordinateur > Modèles d'administration > Système > Délégation des informations d'identification > Restreindre la délégation des informations d'identification aux serveurs distants** et sélectionnez **Exiger Remote Credential Guard**, puis connectez-vous avec `mstsc.exe /remoteGuard /v:server1` au lieu de revenir à CredSSP.

Microsoft a cassé RCG pour l'accès multi-hop sur Windows 11 22H2 et versions ultérieures jusqu'aux **mises à jour cumulatives d'avril 2024** (KB5036896/KB5036899/KB5036894). Appliquez les correctifs au client et au serveur intermédiaire, sinon le second hop échouera toujours.<sup>[[5]](#references)</sup> Vérification rapide du hotfix :
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Avec ces builds installées, le hop RDP peut satisfaire les challenges Kerberos en aval sans exposer de secrets réutilisables sur le premier serveur.

## Contournements

### Invoke Command

Pour résoudre le problème du double hop, une méthode utilisant un `Invoke-Command` imbriqué est présentée. Elle ne résout pas directement le problème, mais fournit un contournement sans nécessiter de configurations spéciales. Cette approche permet d’exécuter une commande (`hostname`) sur un serveur secondaire via une commande PowerShell exécutée depuis une machine d’attaque initiale ou via une PS-Session précédemment établie avec le premier serveur. Voici comment procéder :<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativement, l’établissement d’une PS-Session avec le premier serveur et l’exécution de `Invoke-Command` avec `$cred` sont suggérés pour centraliser les tâches.

### Enregistrer la configuration PSSession

Une solution pour contourner le problème du double hop consiste à utiliser `Register-PSSessionConfiguration` avec `Enter-PSSession`. Cette méthode nécessite une approche différente de celle d’`evil-winrm` et permet d’établir une session qui n’est pas affectée par la limitation du double hop.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Pour les administrateurs locaux d'une cible intermédiaire, le port forwarding permet d'envoyer des requêtes vers un serveur final. Avec `netsh`, une règle peut être ajoutée pour le port forwarding, ainsi qu'une règle du pare-feu Windows autorisant le port transféré.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` peut être utilisé pour transférer des requêtes WinRM, ce qui constitue potentiellement une option moins détectable si la surveillance de PowerShell est un sujet de préoccupation.<sup>[[2]](#references)</sup> La commande ci-dessous en démontre l’utilisation :
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

L’installation d’OpenSSH sur le premier serveur permet de contourner le problème du double-hop, ce qui est particulièrement utile dans les scénarios de jump box. Cette méthode nécessite l’installation et la configuration d’OpenSSH pour Windows via la CLI. Lorsqu’il est configuré avec Password Authentication, cela permet au serveur intermédiaire d’obtenir un TGT au nom de l’utilisateur.<sup>[[2]](#references)</sup>

#### Étapes d’installation d’OpenSSH

1. Téléchargez la dernière archive zip d’OpenSSH et déplacez-la vers le serveur cible.
2. Décompressez-la et exécutez le script `Install-sshd.ps1`.
3. Ajoutez une règle de pare-feu pour ouvrir le port 22 et vérifiez que les services SSH sont en cours d’exécution.

Pour résoudre les erreurs `Connection reset`, il peut être nécessaire de mettre à jour les permissions afin d’autoriser tout le monde à lire et à exécuter des fichiers dans le répertoire OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Avancé)

**LSA Whisperer** (2024) expose l’appel de package `msv1_0!CacheLogon`, ce qui permet d’injecter un hash NT connu dans un *network logon* existant au lieu de créer une nouvelle session avec `LogonUser`. En injectant le hash dans la session de logon que WinRM/PowerShell a déjà ouverte sur le hop #1, cette machine peut s’authentifier auprès du hop #2 sans stocker d’identifiants explicites ni générer d’événements 4624 supplémentaires.<sup>[[6]](#references)</sup>

1. Obtenez une exécution de code dans LSASS (désactivez/abusez PPL ou exécutez l’opération sur une VM de lab que vous contrôlez).
2. Énumérez les sessions de logon (par exemple, `lsa.exe sessions`) et récupérez le LUID correspondant à votre contexte de remoting.
3. Pré-calculez le hash NT et transmettez-le à `CacheLogon`, puis effacez-le une fois terminé.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Après l’amorçage du cache, relancez `Invoke-Command`/`New-PSSession` depuis le hop #1 : LSASS réutilisera le hash injecté pour répondre aux challenges Kerberos/NTLM du second hop, contournant ainsi proprement la contrainte du double hop. Le compromis est une télémétrie plus importante (exécution de code dans LSASS) ; gardez donc cette méthode pour les environnements à forte friction où CredSSP/RCG sont interdits.

## Références

- [1] [Comprendre le double hop Kerberos - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Solutions de contournement du double hop Kerberos](https://posts.slayerlabs.com/double-hop/)
- [3] [Une autre solution au remoting PowerShell multi-hop](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Résoudre le problème du multi-hop PowerShell sans utiliser CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [9 avril 2024 — KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
