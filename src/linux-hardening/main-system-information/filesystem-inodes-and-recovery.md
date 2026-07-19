# Sistema de arquivos, Inodes e recuperação

{{#include ../../banners/hacktricks-training.md}}

O abuso do sistema de arquivos geralmente consiste em confundir a relação entre um caminho visível e o objeto por trás dele. Imagens de disco podem ocultar outro sistema de arquivos, mounts com permissão de escrita podem ser consumidos por jobs privilegiados, hardlinks podem expor o mesmo inode por meio de um nome diferente, e arquivos excluídos ainda podem ser lidos por meio de um file descriptor aberto.

Esta página se concentra na técnica, não em um lab ou target específico.

## Imagens de disco e Loop Mounts

Um arquivo comum pode conter um sistema de arquivos completo. Portanto, imagens de backup, dispositivos de bloco copiados, artefatos de VM ou blobs renomeados podem conter credenciais, scripts, chaves SSH, arquivos de configuração ou flags, mesmo quando não parecem úteis externamente.

Identifique imagens prováveis:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Se a montagem for permitida, monte primeiro as imagens desconhecidas somente para leitura:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Se a montagem não estiver disponível, inspecione os metadados do sistema de arquivos diretamente:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
A técnica é útil porque transforma um arquivo de aparência normal em uma segunda árvore do sistema de arquivos. Considere-a uma forma de recuperar dados ocultos, não uma privilege escalation por si só.

## Writable Mount Abuse

Um mount com permissão de escrita torna-se perigoso quando um contexto mais privilegiado posteriormente confia em algo dentro dele. A questão importante não é apenas "posso escrever aqui?", mas "quem posteriormente lê, executa, importa ou carrega algo daqui?".

Encontre mounts com permissão de escrita e consumidores suspeitos:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Padrões comuns de abuso:

- Um cron privilegiado ou uma unit do systemd executa um script gravável a partir do mount.
- Um serviço privilegiado carrega plugins, configurações, templates ou binários auxiliares a partir do mount.
- Um mount contém arquivos SUID e permite modificação, substituição ou manipulação de caminhos.
- Um container ou chroot expõe um caminho respaldado pelo host que pode ser gravado a partir do ambiente restrito.

Padrão genérico de validação:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Ao comprovar o impacto em um lab autorizado, mantenha o payload observável e mínimo, por exemplo, gravando a saída de `id` em um arquivo temporário. A técnica central é a execução atrasada por meio de um local gravável confiável.

## Inodes e Confusão de Caminhos

Um inode é o objeto do sistema de arquivos; um caminho é apenas um nome que aponta para ele. Isso é importante porque dois caminhos diferentes podem apontar para o mesmo inode, e a exclusão de um nome de caminho nem sempre significa que os dados foram removidos.

Compare os arquivos pelo inode e pelo dispositivo:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Encontre todos os caminhos visíveis para o mesmo inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Pesquise diretamente pelo número do inode quando você só tiver metadados:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Essa técnica é útil quando um arquivo aparece com um nome inesperado, quando um aplicativo valida um path, mas usa outro, ou quando um wrapper privilegiado interage com um inode que também pode ser acessado em outro local.

## Hardlink Abuse

Hardlinks criam vários nomes para o mesmo inode. Eles não apontam para um path de destino como os symlinks; são nomes equivalentes para o mesmo objeto de arquivo.

Encontre arquivos SUID com vários hardlinks:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspecione um arquivo suspeito:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Por que isso importa:

- Um arquivo sensível pode ser acessível por um caminho menos óbvio.
- Um wrapper SUID pode estar oculto atrás de um nome que não pareça privilegiado.
- Uma limpeza que remove um pathname pode deixar outro hardlink ativo.

Kernels modernos e opções de montagem podem restringir a criação de hardlinks para reduzir esse tipo de abuso, mas os hardlinks existentes ainda merecem ser revisados.

## Recuperação de Arquivos Excluídos por Meio de FDs Abertos

Quando um processo mantém um arquivo aberto, os dados do arquivo podem continuar disponíveis mesmo depois que o pathname é excluído. O Linux expõe esses descritores abertos em `/proc/<pid>/fd/`.

Encontrar arquivos abertos excluídos:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Recupere os dados quando as permissões permitirem:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Esta é uma técnica prática para recuperar logs excluídos, secrets temporários, binaries descartados, arquivos rotacionados ou scripts removidos após a execução.

## Recuperação em ext com debugfs

Em filesystems ext, `debugfs` pode inspecionar metadados de inodes e, às vezes, despejar o conteúdo de arquivos a partir de uma imagem do filesystem. Trabalhe em uma cópia ou em uma imagem somente leitura sempre que possível.

Liste as entradas e inspecione os inodes:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Despejar um inode conhecido:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Isso não garante a recuperação. Isso depende do estado do sistema de arquivos, de os blocos terem sido reutilizados e de os metadados ainda existirem. A técnica continua sendo valiosa porque permite inspecionar o estado no nível dos inodes sem depender da travessia normal de caminhos.

## Esgotamento e ordenação de inodes

O esgotamento de inodes ocorre quando um sistema de arquivos fica sem objetos de arquivo, mesmo que ainda haja espaço livre em disco. Isso geralmente causa falhas de confiabilidade, mas também pode explicar comportamentos estranhos durante a resposta a incidentes ou a triagem em laboratório.

Verifique a pressão de inodes:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Números de inode e timestamps também podem ajudar a reconstruir atividades em ambientes de laboratório simples:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Trate a ordenação como uma pista, não como prova. Operações de cópia, extração de arquivos, tipo de filesystem, restaurações e gravações concorrentes podem alterar os padrões de alocação.

## Notas defensivas

- Monte imagens desconhecidas como somente leitura durante a análise.
- Mantenha scripts privilegiados, unidades de serviço, plugins e caminhos de auxiliares fora de mounts graváveis pelo usuário.
- Use `nosuid`, `nodev` e `noexec` quando for operacionalmente apropriado, mas não os considere um limite completo.
- Restrinja, quando possível, o acesso a `/proc/<pid>/fd`, metadados de processos e inspeção de processos de outros usuários.
- Monitore pontos de montagem graváveis, hardlinks inesperados para arquivos privilegiados e arquivos sensíveis excluídos, mas ainda abertos.
{{#include ../../banners/hacktricks-training.md}}
