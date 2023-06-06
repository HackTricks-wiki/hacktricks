# Locais Sensíveis do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Senhas

### Senhas Shadow

A senha shadow é armazenada com a configuração do usuário em plists localizados em **`/var/db/dslocal/nodes/Default/users/`**.\
O seguinte comando pode ser usado para extrair **todas as informações sobre os usuários** (incluindo informações de hash):
```
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts como este**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ou [**este**](https://github.com/octomagon/davegrohl.git) podem ser usados para transformar o hash para o formato **hashcat**.

Uma alternativa em uma linha de comando que irá despejar credenciais de todas as contas não de serviço no formato hashcat `-m 7100` (macOS PBKDF2-SHA512):
```
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
### Despejo de Chaveiro

Observe que ao usar o binário de segurança para **despejar as senhas descriptografadas**, várias solicitações pedirão ao usuário para permitir essa operação.
```
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

O atacante ainda precisa obter acesso ao sistema e, em seguida, escalar os privilégios para **root** para executar o **keychaindump**. Essa abordagem vem com suas próprias condições. Como mencionado anteriormente, **após o login, o seu chaveiro é desbloqueado por padrão** e permanece desbloqueado enquanto você usa o sistema. Isso é para conveniência, para que o usuário não precise inserir sua senha toda vez que um aplicativo desejar acessar o chaveiro. Se o usuário alterou essa configuração e escolheu bloquear o chaveiro após cada uso, o keychaindump não funcionará mais; ele depende de um chaveiro desbloqueado para funcionar.

É importante entender como o Keychaindump extrai senhas da memória. O processo mais importante nessa transação é o "processo **securityd**". A Apple se refere a esse processo como um **daemon de contexto de segurança para operações de autorização e criptografia**. As bibliotecas de desenvolvedores da Apple não dizem muito sobre isso; no entanto, elas nos dizem que o securityd lida com o acesso ao chaveiro. Em sua pesquisa, Juuso se refere à **chave necessária para descriptografar o chaveiro como "A Chave Mestra"**. Várias etapas precisam ser realizadas para adquirir essa chave, pois ela é derivada da senha de login do OS X do usuário. Se você quiser ler o arquivo do chaveiro, deverá ter essa chave mestra. As seguintes etapas podem ser realizadas para adquiri-la. **Realize uma varredura do heap do securityd (o keychaindump faz isso com o comando vmmap)**. Possíveis chaves mestras são armazenadas em uma área marcada como MALLOC\_TINY. Você pode ver as localizações desses heaps com o seguinte comando:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
O **Keychaindump** então procurará nas pilhas retornadas por ocorrências de 0x0000000000000018. Se o valor de 8 bytes seguinte apontar para a pilha atual, encontramos uma possível chave mestra. A partir daqui, ainda é necessário um pouco de desobfuscação, que pode ser vista no código-fonte, mas como analista, a parte mais importante a ser observada é que os dados necessários para descriptografar essas informações são armazenados na memória do processo securityd. Aqui está um exemplo de saída do keychain dump.
```bash
sudo ./keychaindump
```
{% hint style="danger" %}
Com base neste comentário [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), parece que essas ferramentas não estão mais funcionando no Big Sur.
{% endhint %}

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode ser usado para extrair os seguintes tipos de informações de um keychain OSX de maneira forense:

* Senha de keychain com hash, adequada para quebrar com [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
* Senhas de internet
* Senhas genéricas
* Chaves privadas
* Chaves públicas
* Certificados X509
* Notas seguras
* Senhas de compartilhamento de rede da Apple

Dado a senha de desbloqueio do keychain, uma chave mestra obtida usando [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou um arquivo de desbloqueio como SystemKey, o Chainbreaker também fornecerá senhas em texto simples.

Sem um desses métodos de desbloqueio do Keychain, o Chainbreaker exibirá todas as outras informações disponíveis.

### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
### **Despejar chaves do keychain (com senhas) com SystemKey**

O SystemKey é uma ferramenta que permite despejar chaves do keychain, incluindo senhas, sem a necessidade de autenticação do usuário. Para usar o SystemKey, é necessário ter privilégios de root.

Para despejar as chaves do keychain, execute o seguinte comando:

```
sudo systemkeychain -dump
```

Isso irá despejar todas as chaves do keychain, incluindo senhas, em formato de texto simples. É importante lembrar que essas senhas podem ser usadas para acessar informações sensíveis, portanto, é importante manter esses arquivos seguros e protegidos contra vazamentos.
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Extrair chaves do keychain (com senhas) quebrando o hash**

Para extrair chaves do keychain do macOS, é necessário primeiro obter acesso root ou acesso físico ao dispositivo. Em seguida, é possível usar a ferramenta `security` para exportar as chaves do keychain em um arquivo `.keychain` criptografado. 

No entanto, se a senha do keychain for desconhecida, é possível quebrar o hash da senha usando ferramentas como `John the Ripper` ou `hashcat`. Essas ferramentas podem ser usadas para gerar uma lista de senhas possíveis com base em um dicionário ou em regras personalizadas e, em seguida, tentar quebrar o hash da senha do keychain com essas senhas. 

Uma vez que a senha do keychain é conhecida, é possível usar a ferramenta `security` novamente para exportar as chaves do keychain em um arquivo `.keychain` descriptografado e, em seguida, extrair as senhas armazenadas nas chaves usando ferramentas como `keychaindump.py`. 

É importante lembrar que a extração de senhas do keychain sem autorização explícita é ilegal e pode resultar em consequências legais graves.
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Despejar chaves do keychain (com senhas) com dump de memória**

[Siga estes passos](..#dumping-memory-with-osxpmem) para realizar um **dump de memória**.
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Despejar chaves do keychain (com senhas) usando a senha do usuário**

Se você conhece a senha do usuário, pode usá-la para **despejar e descriptografar keychains que pertencem ao usuário**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

O arquivo **kcpassword** é um arquivo que contém a **senha de login do usuário**, mas somente se o proprietário do sistema tiver **habilitado o login automático**. Portanto, o usuário será automaticamente conectado sem ser solicitada uma senha (o que não é muito seguro).

A senha é armazenada no arquivo **`/etc/kcpassword`** xored com a chave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se a senha do usuário for mais longa do que a chave, a chave será reutilizada.\
Isso torna a senha bastante fácil de recuperar, por exemplo, usando scripts como [**este**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Você pode encontrar os dados de Notificações em `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

A maioria das informações interessantes estará no **blob**. Portanto, você precisará **extrair** esse conteúdo e **transformá-lo** em algo **legível** para humanos ou usar **`strings`**. Para acessá-lo, você pode fazer:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notas

As notas do usuário podem ser encontradas em `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
