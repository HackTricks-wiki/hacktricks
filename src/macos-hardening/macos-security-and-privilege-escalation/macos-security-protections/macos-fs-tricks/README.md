# Truques de FS do macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Combinações de permissões POSIX

Para um **diretório**, os três bits de permissão têm um significado diferente do que têm em um arquivo comum. `chmod(1)` chama o bit de execução de "**search**" quando ele é aplicado a um diretório:<sup>[[2]](#references)</sup>

> `0100` Para arquivos, permite a execução pelo proprietário. Para diretórios, permite que o proprietário faça **search** no diretório.

- **read** - você pode **enumerar** as entradas do diretório (listar os nomes).
- **write** - você pode **criar, renomear e excluir entradas** no diretório. Observe que isso é uma propriedade do diretório *que contém* o arquivo, não do próprio arquivo: você pode excluir um arquivo que não consegue ler nem gravar, desde que possa gravar no diretório pai dele.
  - Para excluir um **subdiretório**, ele precisa estar vazio, o que, por sua vez, exige direitos suficientes para remover tudo que há dentro dele.
  - Se o diretório tiver o **sticky bit** (`S_ISVTX`, como em `/tmp`), isso é restrito — o POSIX estabelece que um processo só pode remover ou renomear arquivos nele se for proprietário do arquivo, proprietário do diretório ou tiver os privilégios adequados.<sup>[[1]](#references)</sup>
- **execute / search** - você tem permissão para **percorrer** o diretório. A resolução de nomes de caminho localiza cada componente "no diretório especificado pelo componente anterior", então **perder o direito de search em qualquer componente do prefixo do caminho torna tudo abaixo dele inacessível pelo caminho**, mesmo que o arquivo final seja legível por todos.<sup>[[1]](#references)</sup>

### Combinações perigosas

**Como sobrescrever um arquivo/pasta pertencente a root**, quando:

- O **proprietário** de um diretório pai no caminho é o usuário
- O **proprietário** de um diretório pai no caminho é um **grupo de usuários** com **acesso de gravação**
- Um **grupo** de usuários tem acesso de **gravação** ao **arquivo**

Com qualquer uma das combinações anteriores, um atacante poderia **injetar** um **link simbólico/absoluto** no caminho esperado para obter uma escrita arbitrária privilegiada.

### Caso especial de pasta root com R+X

Isso decorre diretamente da regra de resolução de nomes de caminho acima. Se um **diretório concede apenas R+X a root**, os arquivos dentro dele ficam inacessíveis *pelo caminho* para todos os demais — mas os **bits de permissão dos próprios arquivos ainda podem ser permissivos**. O diretório é o único obstáculo.

Assim, qualquer primitiva que permita tirar o arquivo **desse diretório** — um processo privilegiado que **move/renomeia/copia** um caminho escolhido pelo atacante para um local que você *pode* percorrer — transforma isso em uma leitura arbitrária, sem jamais precisar contornar as permissões do próprio arquivo:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Procure programas privilegiados que movem arquivos (instaladores, rotacionadores de logs, coletores de falhas/diagnósticos, recursos de backup e “exportação”) e aceitam um caminho de origem fornecido por um usuário com menos privilégios.

## Link simbólico / hard link

### Arquivo/pasta permissivo

Se um processo privilegiado estiver gravando dados em um **arquivo** que possa ser **controlado** por um **usuário com menos privilégios**, ou que possa ter sido **criado anteriormente** por esse usuário, ele poderá simplesmente **apontá-lo para outro arquivo** por meio de um link simbólico ou hard link, e o processo privilegiado gravará nesse arquivo.

Confira as outras seções para ver onde um invasor pode **abusar de uma gravação arbitrária para escalar privilégios**.

### Abrir com `O_NOFOLLOW`

Segundo [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *“Se `O_NOFOLLOW` for usado na máscara e o arquivo de destino passado para `open()` for um link simbólico, a chamada a `open()` falhará.”* Apenas o **componente final** é verificado — todos os **componentes intermediários** ainda são resolvidos e seguidos. Portanto, um desenvolvedor que “protegeu” uma gravação com `O_NOFOLLOW` ainda pode ser atacado por meio de um link simbólico plantado em qualquer **diretório pai** do caminho de destino.<sup>[[3]](#references)</sup>

A mesma página de manual documenta as flags que realmente fecham essa brecha:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *“se ... qualquer componente do caminho passado para `open()` for um link simbólico, a chamada a `open()` falhará.”*
- **`O_RESOLVE_BENEATH`** — *“se ... a resolução do caminho especificado escapar do diretório associado ao fd, a chamada a `openat()` falhará.”*

Caso contrário, usar `openat()` relativo a um FD de diretório que você já validou, ou `realpath()` seguido de nova validação, são as opções restantes para impedir trocas de links simbólicos no meio do caminho.

## .fileloc

Arquivos com a extensão **`.fileloc`** podem apontar para outros aplicativos ou binários; assim, quando são abertos, o aplicativo/binário apontado é executado.\
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

## File Descriptors

### Leak FD (no `O_CLOEXEC`)

Se uma chamada a `open` não tiver a flag `O_CLOEXEC`, o descritor de arquivo será herdado pelo processo filho. Portanto, se um processo privilegiado abrir um arquivo privilegiado e executar um processo controlado pelo atacante, o atacante **herdará o FD do arquivo privilegiado**.

O exemplo canônico é o **LPE de `DYLD_PRINT_TO_FILE` no OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` respeitava `DYLD_PRINT_TO_FILE=/path` até mesmo em **binários restritos (suid root)**, porque essa variável específica era analisada fora de `processDyldEnvironmentVariable()`.
- Ele executava `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, portanto **criava um arquivo pertencente ao root em um caminho arbitrário**.
- O FD **nunca era fechado e não tinha a flag close-on-exec**, então todos os processos filhos do binário suid herdavam um **FD gravável para um arquivo pertencente ao root**.
- Executar, por exemplo, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` e depois ler o número do FD herdado no processo filho permitia gravações arbitrárias em arquivos pertencentes ao root; `fcntl(fd, F_SETFL, 0)` até limpava `O_APPEND`, permitindo sobrescrever em vez de apenas acrescentar.

O mesmo padrão aparece sempre que um processo privilegiado abre um arquivo **antes de executar (`exec`) algo que você controla** (ferramentas auxiliares, editores no estilo `crontab` invocados por meio de `$EDITOR`, arquivos de log/depuração abertos a partir de um caminho definido por variável de ambiente...). Enumere os FDs herdados com:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Qualquer coisa acima de `2` que aponte para um arquivo que você não consegue abrir por conta própria é uma primitiva de escrita arbitrária (ou leitura arbitrária).

## Evite truques com xattrs de quarantine

### Remova-o

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable flag

Se um arquivo/pasta tiver esse atributo imutável, não será possível definir um xattr nele.

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Sistemas de arquivos sem suporte a xattr

Nem todo sistema de arquivos que o macOS pode montar armazena **atributos estendidos** nativamente. HFS+ e APFS armazenam; **FAT32, exFAT e (a maioria dos) mounts NFS não** — o macOS os emula gravando um arquivo auxiliar **AppleDouble** chamado `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Isso importa para a quarentena, porque o xattr só persiste se puder ser **gravado e lido de volta** no mesmo volume:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Se o volume for lido posteriormente por um caminho que ignora o arquivo companion `._` (ou se esse arquivo for removido/excluído), o arquivo chega **sem uma quarantine flag** — e um `.app` sem quarantine já é suficiente para escapar do App Sandbox, conforme abordado em [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### Comportamento de writeextattr ACL e quarantine do AppleDouble

Para ver o exemplo de ACL `writeextattr`, o mecanismo AppleDouble `com.apple.acl.text` e as etapas de construção e validação do sidecar, consulte [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md).

## Bypass de verificações de assinatura

### Bypass de verificações de platform binaries

Algumas verificações de segurança verificam se o binário é um **platform binary**, por exemplo, para permitir a conexão a um serviço XPC. No entanto, como demonstrado em um bypass em https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, é possível contornar essa verificação obtendo um platform binary (como /bin/ls) e injetando o exploit via dyld usando uma variável de ambiente `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass das flags `CS_REQUIRE_LV` e `CS_FORCED_LV`

É possível que um binário em execução modifique suas próprias flags para contornar as verificações com um código como:<sup>[[7]](#references)</sup>

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



## Contornar assinaturas de código

Os bundles contêm o arquivo **`_CodeSignature/CodeResources`**, que contém o **hash** de cada **arquivo** do **bundle**. Observe que o hash de CodeResources também está **incorporado no executável**, então também não podemos alterá-lo.

No entanto, há alguns arquivos cuja assinatura não será verificada. Eles têm a chave omit no plist, como:

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

## Montar DMGs

Um usuário pode montar um DMG personalizado até mesmo sobre algumas pastas existentes. Veja como criar um pacote DMG personalizado com conteúdo personalizado:

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
No entanto, é possível usar ferramentas como `hdik` e `hdiutil` para se comunicar diretamente com a kext `com.apple.driver.DiskImages`.

## Gravações arbitrárias

### Scripts sh periódicos

Se o seu script puder ser interpretado como um **shell script**, você poderá sobrescrever o **`/etc/periodic/daily/999.local`**, um shell script que será executado todos os dias.

Você pode **simular** a execução desse script com: **`sudo periodic daily`**

### Daemons

Grave um **LaunchDaemon** arbitrário, como **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, com um plist que execute um script arbitrário, como:

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

Basta gerar o script `/Applications/Scripts/privesc.sh` com os **comandos** que você gostaria de executar como root.

### Arquivo Sudoers

Se você tiver **arbitrary write**, poderá criar um arquivo dentro da pasta **`/etc/sudoers.d/`** concedendo privilégios de **sudo** a si mesmo.

### Arquivos PATH

O arquivo **`/etc/paths`** é um dos principais locais que preenchem a variável de ambiente PATH. Você precisa ser root para sobrescrevê-lo, mas, se um script de um **processo privilegiado** executar algum **comando sem o caminho completo**, talvez você consiga **hijack**-lo modificando esse arquivo.

Você também pode gravar arquivos em **`/etc/paths.d`** para adicionar novas pastas à variável de ambiente `PATH`.

### cups-files.conf

Essa técnica foi usada [neste writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Crie o arquivo `/etc/cups/cups-files.conf` com o seguinte conteúdo:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

Isso criará o arquivo `/etc/sudoers.d/lpe` com permissões 777. O conteúdo extra no final serve para acionar a criação do log de erros.

Em seguida, escreva em `/etc/sudoers.d/lpe` a configuração necessária para escalar privilégios, como `%staff ALL=(ALL) NOPASSWD:ALL`.

Depois, modifique novamente o arquivo `/etc/cups/cups-files.conf`, indicando `LogFilePerm 700`, para que o novo arquivo sudoers se torne válido ao invocar `cupsctl`.

### Escape do Sandbox

É possível escapar do sandbox do macOS com uma escrita arbitrária no FS. Para ver alguns exemplos, confira a página [macOS Auto Start](../../../../macos-auto-start-locations.md), mas uma opção comum é gravar um arquivo de preferências do Terminal em `~/Library/Preferences/com.apple.Terminal.plist` que execute um comando na inicialização e chamá-lo usando `open`.

## Gerar arquivos graváveis como outros usuários

Um primitivo muito comum de privesc é fazer um **processo privilegiado criar um arquivo para você** em um diretório que você controla e, depois, manter **acesso de escrita** a esse arquivo. São necessários dois ingredientes:

1. Um diretório que você possui (ou no qual pode definir uma **ACL herdável**), para que qualquer item criado nele herde suas permissões.
2. Um processo privilegiado/`suid` que possa ser instruído sobre **onde** criar um arquivo — normalmente por meio de uma variável de ambiente de depuração/log, um arquivo de configuração ou a API XPC de um helper.

A parte da **ACL herdável** é o que permite que você grave no arquivo criado, mesmo que ele pertença a outro usuário. As flags de herança `file_inherit` / `directory_inherit` estão documentadas em [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Agora, qualquer arquivo que um processo privilegiado criar dentro de `$DIRNAME` será **gravável por você**. Se esse diretório também for um local que depois é **executado como root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, um diretório de LaunchDaemon...), isso é uma escalada direta para root. Consulte as seções [Sudoers File](#sudoers-file) e [cups-files.conf](#cups-filesconf) acima para saber o que gravar no arquivo depois de obtê-lo.

Para ver um exemplo completo da cadeia “uma variável de ambiente faz um processo root criar um arquivo, e o FD vaza para você”, consulte [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) acima.

## Memória compartilhada POSIX

A **memória compartilhada POSIX** permite que processos em sistemas operacionais compatíveis com POSIX acessem uma área de memória comum, facilitando uma comunicação mais rápida em comparação com outros métodos de comunicação entre processos. Isso envolve criar ou abrir um objeto de memória compartilhada com `shm_open()`, definir seu tamanho com `ftruncate()` e mapeá-lo no espaço de endereçamento do processo usando `mmap()`. Assim, os processos podem ler e gravar diretamente nessa área de memória. Para gerenciar o acesso concorrente e evitar a corrupção de dados, costumam ser usados mecanismos de sincronização, como mutexes ou semáforos. Por fim, os processos desmapeiam e fecham a memória com `munmap()` e `close()` e, opcionalmente, removem o objeto de memória com `shm_unlink()`. Esse sistema é especialmente eficaz para IPC rápido e eficiente em ambientes nos quais vários processos precisam acessar dados compartilhados rapidamente.

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

<summary>Exemplo de código consumidor</summary>

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

**Descritores guardados do macOS** são um recurso de segurança introduzido no macOS para aumentar a segurança e a confiabilidade das **operações com descritores de arquivos** em aplicativos de usuário. Esses descritores guardados permitem associar restrições específicas, ou “guards”, aos descritores de arquivos, que são aplicadas pelo kernel.

Esse recurso é particularmente útil para prevenir certas classes de vulnerabilidades de segurança, como **acesso não autorizado a arquivos** ou **condições de corrida**. Essas vulnerabilidades ocorrem, por exemplo, quando uma thread acessa uma descrição de arquivo, dando **a outra thread vulnerável acesso a ela**, ou quando um descritor de arquivo é **herdado** por um processo filho vulnerável. Algumas funções relacionadas a essa funcionalidade são:

- `guarded_open_np`: Abre um descritor de arquivo com um guard
- `guarded_close_np`: Fecha-o
- `change_fdguard_np`: Altera as flags de guard em um descritor (inclusive removendo a proteção do guard)

## References

- [1] [POSIX.1-2024 — Definições básicas, cap. 4 (Permissões de acesso a arquivos, proteção de diretórios, resolução de nomes de caminho)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - Escalonamento local de privilégios por meio de DYLD_PRINT_TO_FILE no OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Quais sistemas de arquivos e serviços de nuvem preservam atributos estendidos?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - Uma nova era de escapes do sandbox do macOS](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Revelando vulnerabilidades da Apple: a história da auditoria do diskarbitrationd e do storagekitd, parte 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
