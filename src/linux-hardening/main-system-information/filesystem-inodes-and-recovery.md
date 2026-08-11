# Sistema de arquivos, inodes e recuperação

{{#include ../../banners/hacktricks-training.md}}

O abuso do sistema de arquivos geralmente consiste em confundir a relação entre um caminho visível e o objeto por trás dele.

Imagens de disco podem ocultar outro sistema de arquivos.<sup>[[1]](#references)</sup> Montagens com permissão de escrita podem ser consumidas por jobs privilegiados.

Hardlinks podem expor o mesmo inode por meio de um nome diferente.<sup>[[3]](#references)</sup> Arquivos excluídos ainda podem ser lidos por meio de um descritor de arquivo aberto.<sup>[[5]](#references)[[6]](#references)</sup>

Esta página concentra-se na técnica, não em um lab ou alvo específico.

## Imagens de disco e montagens Loop

Um arquivo comum pode conter um sistema de arquivos completo, portanto uma imagem de disco pode expor uma segunda árvore de sistema de arquivos quando montada.<sup>[[1]](#references)</sup>

Imagens de backup, dispositivos de bloco copiados, artefatos de VM ou blobs renomeados podem conter credenciais, scripts, chaves SSH, arquivos de configuração ou flags, mesmo quando não parecem úteis externamente.

Identifique imagens prováveis com `file` para classificar um candidato, `blkid` para verificar metadados reconhecidos do sistema de arquivos e `strings -a` para examinar o arquivo inteiro em busca de sequências imprimíveis.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Quando a montagem for permitida, use uma montagem loop com `ro` para que a imagem seja anexada somente para leitura; o comando `find` abaixo limita a profundidade da inspeção e o tipo de arquivo.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Se a montagem não estiver disponível e a imagem for ext2/ext3/ext4, inspecione seus metadados diretamente com `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
A técnica é útil porque transforma um arquivo de aparência normal em uma segunda árvore de filesystem.<sup>[[1]](#references)</sup> Trate-a como uma forma de recuperar dados ocultos, não como uma escalada de privilégios por si só.

## Abuso de Montagens Graváveis

Uma montagem gravável torna-se perigosa quando um contexto com mais privilégios posteriormente confia em algo dentro dela. A questão importante não é apenas "posso escrever aqui?", mas "quem posteriormente lê, executa, importa ou carrega algo daqui?".

Use `findmnt` para inspecionar os filesystems montados e suas opções.<sup>[[9]](#references)</sup>

Encontre montagens graváveis e consumidores suspeitos com os predicados documentados de permissão, tipo e limite de filesystem do `find` e, em seguida, use `grep` recursivo para procurar configurações de possíveis consumidores.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Padrões comuns de abuso:

- Um cron job ou serviço systemd executa um script gravável a partir do mount.<sup>[[13]](#references)[[14]](#references)</sup>
- Um serviço privilegiado carrega plugins, configurações, templates ou binários auxiliares a partir do mount.
- Um mount contém arquivos SUID e permite modificação, substituição ou manipulação de paths.
- Um container ou chroot expõe um path respaldado pelo host que pode ser gravado a partir do ambiente restrito. Os mount namespaces fornecem hierarquias de mount distintas, enquanto `chroot()` apenas altera a resolução de nomes de path e não é um sandbox completo.<sup>[[15]](#references)[[16]](#references)</sup>

Padrão genérico de validação usando os mesmos predicados do `find`.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Ao comprovar o impacto em um laboratório autorizado, mantenha o payload observável e mínimo, por exemplo, gravando a saída de `id` em um arquivo temporário.<sup>[[23]](#references)</sup> A técnica principal é a execução atrasada por meio de um local gravável confiável.

## Inodes e Confusão de Caminhos

Um inode é o objeto do filesystem; um caminho é apenas um nome que aponta para ele. Os metadados do dispositivo e do inode permitem distinguir objetos entre filesystems, enquanto as contagens de links revelam múltiplos hard links.<sup>[[3]](#references)</sup> Um caminho excluído nem sempre significa que os dados desapareceram enquanto um processo ainda mantém o arquivo aberto.<sup>[[5]](#references)</sup>

Os predicados de `find` abaixo comparam a identidade do inode, as contagens de links, os limites entre dispositivos e os timestamps.<sup>[[4]](#references)</sup>

Compare arquivos por inode e dispositivo usando `ls -i` e os formatos de metadados de `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Encontre todos os caminhos visíveis para o mesmo inode com `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Pesquise diretamente pelo número do inode com `find -inum` quando você tiver apenas metadados.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Esta técnica é útil quando um arquivo aparece com um nome inesperado, quando um aplicativo valida um caminho, mas usa outro, ou quando um wrapper privilegiado interage com um inode que também pode ser acessado em outro local.

## Hardlink Abuse

Hardlinks criam vários nomes para o mesmo inode. Eles não apontam para um caminho de destino como os symlinks; são nomes equivalentes para o mesmo objeto de arquivo.<sup>[[3]](#references)</sup>

Encontre arquivos SUID com múltiplos hardlinks usando os predicados de permissão e contagem de links do `find`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspecione um arquivo suspeito com `stat` e `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Por que isso importa:

- Um arquivo sensível pode ser acessível por um caminho menos óbvio.
- Um wrapper SUID pode estar oculto por trás de um nome que não pareça privilegiado.
- Uma limpeza que remove um pathname pode deixar outro hardlink ativo.

O sysctl `fs.protected_hardlinks` do Linux pode restringir a criação de hardlinks entre limites de privilégio.<sup>[[7]](#references)</sup> Os hardlinks existentes ainda merecem ser revisados.

## Recuperação de Arquivos Excluídos por meio de FDs Abertos

Quando um processo mantém um arquivo aberto, remover seu último pathname mantém o arquivo ativo até que o último descritor seja fechado; o Linux expõe esses descritores em `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Encontre arquivos abertos excluídos listando os descritores em `/proc` e filtrando a saída de arquivos abertos.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
A recuperação por meio desses links depende de permissões, pois a desreferenciação de `/proc/<pid>/fd` está sujeita às verificações de acesso do ptrace e às permissões do arquivo.<sup>[[6]](#references)</sup>

Quando permitido, `readlink` exibe o destino do descritor e `cp` copia seu conteúdo.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Esta é uma técnica prática para recuperar logs excluídos, secrets temporários, binários descartados, arquivos rotacionados ou scripts removidos após a execução.

## Recuperação de ext com debugfs

Em sistemas de arquivos ext2/ext3/ext4, `debugfs` pode inspecionar metadados de inode e despejar o conteúdo de inodes a partir de um dispositivo de bloco ou imagem; sem `-w`, ele abre o sistema de arquivos em modo somente leitura.<sup>[[2]](#references)</sup> Trabalhe com uma cópia ou uma imagem somente leitura sempre que possível.

Liste entradas e inspecione inodes com solicitações do `debugfs` para listagens de diretórios, status de inode e verificações de inode para caminho.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Extraia um inode conhecido com o comando `debugfs dump` e, em seguida, classifique a saída recuperada com `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Esta recuperação não é garantida. Ela depende do estado do filesystem, de os blocks terem sido reutilizados e de os metadados ainda existirem. Para ext3/ext4, o manual do `debugfs` observa que a recuperação de inodes excluídos pode falhar porque os data blocks dos inodes liberados já não estão disponíveis.<sup>[[2]](#references)</sup> A técnica ainda é valiosa porque permite inspecionar o estado no nível dos inodes sem depender da travessia normal de paths.

## Esgotamento e Ordenação de Inodes

O esgotamento de inodes ocorre quando um filesystem fica sem nós de arquivos, mesmo que ainda haja espaço livre em disco.<sup>[[8]](#references)[[17]](#references)</sup> Isso geralmente causa falhas de confiabilidade, mas também pode explicar comportamentos estranhos durante a resposta a incidentes ou a triagem em laboratório.

Use `df -i` para informar dados sobre inodes em vez do uso de blocks.<sup>[[8]](#references)</sup>

Verifique a pressão sobre os inodes com `df` e uma contagem de diretórios pai usando `find`.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Os números de inode e os timestamps também podem ajudar a reconstruir atividades em ambientes de laboratório simples.

As diretivas de formato do `find` abaixo expõem esses campos.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Trate a ordem como uma pista, não como uma prova. Operações de cópia, extração de arquivos, tipo de filesystem, restaurações e gravações concorrentes podem alterar os padrões de alocação.

## Notas defensivas

- Monte imagens desconhecidas como somente leitura durante a análise.<sup>[[1]](#references)</sup>
- Mantenha scripts privilegiados, unidades de serviço, plugins e caminhos de auxiliares fora de mounts graváveis pelo usuário.
- Use `nosuid`, `nodev` e `noexec` quando for operacionalmente apropriado; essas opções desabilitam a execução de set-ID/capability, a interpretação de dispositivos ou a execução direta de binários no mount.<sup>[[1]](#references)</sup> Não as trate como uma boundary completa.
- Restrinja o acesso a `/proc/<pid>/fd`; o desreferenciamento desses links é controlado pelas verificações de acesso do ptrace e pelas permissões de arquivo.<sup>[[6]](#references)</sup> Restrinja metadados de processos mais amplos e a inspeção entre usuários sempre que possível.
- Monitore mount points graváveis, hardlinks inesperados para arquivos privilegiados e arquivos sensíveis excluídos, mas ainda abertos.

## References

- [1] [mount(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — página de manual do Linux](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — página de manual do Linux](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — página de manual do Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Documentação de /proc/sys/fs/ — documentação do Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — página de manual do Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — página de manual do Linux](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — página de manual do Linux](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — página de manual do Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
