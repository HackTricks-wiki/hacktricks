{{#include ../../../banners/hacktricks-training.md}}

## smss.exe

**Gestionnaire de session**.\
La session 0 démarre **csrss.exe** et **wininit.exe** (**services** **OS**) tandis que la session 1 démarre **csrss.exe** et **winlogon.exe** (**session** **utilisateur**). Cependant, vous ne devriez voir **qu'un seul processus** de ce **binaire** sans enfants dans l'arborescence des processus.

De plus, des sessions autres que 0 et 1 peuvent signifier que des sessions RDP sont en cours.

## csrss.exe

**Processus de sous-système d'exécution client/serveur**.\
Il gère les **processus** et les **threads**, rend l'**API** **Windows** disponible pour d'autres processus et **mappe les lettres de lecteur**, crée des **fichiers temporaires** et gère le **processus** de **shutdown**.

Il y en a un **en cours d'exécution dans la session 0 et un autre dans la session 1** (donc **2 processus** dans l'arborescence des processus). Un autre est créé **par nouvelle session**.

## winlogon.exe

**Processus de connexion Windows**.\
Il est responsable de la **connexion**/**déconnexion** des utilisateurs. Il lance **logonui.exe** pour demander le nom d'utilisateur et le mot de passe, puis appelle **lsass.exe** pour les vérifier.

Ensuite, il lance **userinit.exe** qui est spécifié dans **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** avec la clé **Userinit**.

De plus, le registre précédent devrait avoir **explorer.exe** dans la clé **Shell** ou cela pourrait être abusé comme une **méthode de persistance de malware**.

## wininit.exe

**Processus d'initialisation Windows**. \
Il lance **services.exe**, **lsass.exe** et **lsm.exe** dans la session 0. Il ne devrait y avoir qu'un seul processus.

## userinit.exe

**Application de connexion Userinit**.\
Charge le **ntduser.dat dans HKCU** et initialise l'**environnement** **utilisateur** et exécute des **scripts de connexion** et des **GPO**.

Il lance **explorer.exe**.

## lsm.exe

**Gestionnaire de session local**.\
Il travaille avec smss.exe pour manipuler les sessions utilisateur : connexion/déconnexion, démarrage de shell, verrouillage/déverrouillage du bureau, etc.

Après W7, lsm.exe a été transformé en service (lsm.dll).

Il ne devrait y avoir qu'un seul processus dans W7 et parmi eux un service exécutant la DLL.

## services.exe

**Gestionnaire de contrôle des services**.\
Il **charge** les **services** configurés pour **démarrage automatique** et les **drivers**.

C'est le processus parent de **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** et bien d'autres.

Les services sont définis dans `HKLM\SYSTEM\CurrentControlSet\Services` et ce processus maintient une base de données en mémoire des informations sur les services qui peuvent être interrogées par sc.exe.

Notez comment **certains** **services** vont s'exécuter dans un **processus à part** et d'autres vont **partager un processus svchost.exe**.

Il ne devrait y avoir qu'un seul processus.

## lsass.exe

**Sous-système d'autorité de sécurité locale**.\
Il est responsable de l'**authentification** des utilisateurs et crée les **tokens** de **sécurité**. Il utilise des paquets d'authentification situés dans `HKLM\System\CurrentControlSet\Control\Lsa`.

Il écrit dans le **journal** **d'événements** **de sécurité** et il ne devrait y avoir qu'un seul processus.

Gardez à l'esprit que ce processus est fortement attaqué pour extraire des mots de passe.

## svchost.exe

**Processus hôte de service générique**.\
Il héberge plusieurs services DLL dans un seul processus partagé.

En général, vous constaterez que **svchost.exe** est lancé avec le drapeau `-k`. Cela lancera une requête au registre **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** où il y aura une clé avec l'argument mentionné dans -k qui contiendra les services à lancer dans le même processus.

Par exemple : `-k UnistackSvcGroup` lancera : `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Si le **drapeau `-s`** est également utilisé avec un argument, alors svchost est demandé à **lancer uniquement le service spécifié** dans cet argument.

Il y aura plusieurs processus de `svchost.exe`. Si l'un d'eux **n'utilise pas le drapeau `-k`**, alors c'est très suspect. Si vous constatez que **services.exe n'est pas le parent**, c'est également très suspect.

## taskhost.exe

Ce processus agit comme un hôte pour les processus s'exécutant à partir de DLL. Il charge également les services qui s'exécutent à partir de DLL.

Dans W8, cela s'appelle taskhostex.exe et dans W10 taskhostw.exe.

## explorer.exe

C'est le processus responsable du **bureau de l'utilisateur** et du lancement de fichiers via des extensions de fichiers.

**Un seul** processus devrait être créé **par utilisateur connecté.**

Cela est exécuté à partir de **userinit.exe** qui devrait être terminé, donc **aucun parent** ne devrait apparaître pour ce processus.

# Détection des processus malveillants

- Est-il exécuté à partir du chemin attendu ? (Aucun binaire Windows ne s'exécute à partir d'un emplacement temporaire)
- Communique-t-il avec des IP étranges ?
- Vérifiez les signatures numériques (les artefacts Microsoft devraient être signés)
- Est-il correctement orthographié ?
- S'exécute-t-il sous le SID attendu ?
- Le processus parent est-il celui attendu (le cas échéant) ?
- Les processus enfants sont-ils ceux attendus ? (pas de cmd.exe, wscript.exe, powershell.exe..?)

{{#include ../../../banners/hacktricks-training.md}}
