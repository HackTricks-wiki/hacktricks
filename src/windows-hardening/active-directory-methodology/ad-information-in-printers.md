# Informações em Impressoras

{{#include ../../banners/hacktricks-training.md}}

Há vários blogs na Internet que **destacam os perigos de deixar impressoras configuradas com LDAP usando credenciais de login padrão/fracas**.  \
Isso ocorre porque um atacante poderia **enganar a impressora para que ela se autentique em um servidor LDAP malicioso** (normalmente, um `nc -vv -l -p 389` ou `slapd -d 2` é suficiente) e capturar as **credenciais da impressora em texto simples**.

Além disso, várias impressoras conterão **logs com nomes de usuário** ou poderão até mesmo ser capazes de **baixar todos os nomes de usuário** do Controlador de Domínio.

Todas essas **informações sensíveis** e a comum **falta de segurança** tornam as impressoras muito interessantes para os atacantes.

Alguns blogs introdutórios sobre o tema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuração da Impressora

- **Localização**: A lista de servidores LDAP geralmente é encontrada na interface web (por exemplo, *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportamento**: Muitos servidores web integrados permitem modificações no servidor LDAP **sem a necessidade de inserir novamente as credenciais** (recurso de usabilidade → risco de segurança).
- **Exploração**: Redirecione o endereço do servidor LDAP para um host controlado pelo atacante e use o botão *Test Connection* / *Address Book Sync* para forçar a impressora a fazer bind com você.

---

## Captura de Credenciais

### Método 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
MFPs pequenas/antigas podem enviar um *simple-bind* simples cujo bind DN e senha ficam visíveis no fluxo BER bruto. Dispositivos modernos geralmente realizam primeiro uma consulta anônima e depois tentam o bind, portanto os resultados variam.<sup>[[1]](#references)</sup>

Um listener `nc` simples nas portas 636/3269 recebe apenas ciphertext TLS; testar LDAPS requer um endpoint LDAP compatível com TLS, e o redirecionamento deve falhar quando o dispositivo valida corretamente o certificado do servidor.

### Method 2 – Full Rogue LDAP server (recommended)

Como muitos dispositivos realizam uma busca anônima *antes* da autenticação, configurar um daemon LDAP real produz resultados muito mais confiáveis:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Quando a impressora realizar a consulta, você verá as credenciais em texto claro na saída de debug.

> 💡  Responder inclui serviços de autenticação LDAP e SMB rogue. Um bind LDAP simples pode expor a senha configurada, enquanto a autenticação NTLM produz material de challenge-response; não descreva ambos os resultados como uma senha em texto claro.

---

## Vulnerabilidades recentes de Pass-Back (2024-2025)

Pass-back *não* é um problema teórico – os vendors continuam publicando avisos em 2024/2025 que descrevem exatamente essa classe de ataque.

### Xerox VersaLink – CVE-2024-12510 e CVE-2024-12511

O firmware ≤ 57.69.91 das MFPs Xerox VersaLink C70xx permitia que um administrador autenticado (ou qualquer pessoa quando as credenciais padrão permaneciam) pudesse:

* **CVE-2024-12510 – LDAP pass-back**: alterar o endereço do servidor LDAP e acionar uma consulta, fazendo com que o dispositivo desse leak das credenciais Windows configuradas para o host controlado pelo atacante.
* **CVE-2024-12511 – SMB/FTP pass-back**: problema idêntico por meio de destinos *scan-to-folder*, dando leak das credenciais NetNTLMv2 ou FTP em texto claro.<sup>[[2]](#references)</sup>

Um listener simples, como:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
ou um servidor SMB rogue (`impacket-smbserver`) é suficiente para coletar as credenciais.

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

A Canon confirmou uma falha de **SMTP/LDAP pass-back** em dezenas de linhas de produtos Laser e MFP. Um atacante com acesso administrativo pode modificar a configuração do servidor e recuperar as credenciais armazenadas de LDAP **ou** SMTP (muitas organizações usam uma conta privilegiada para permitir a digitalização para e-mail).<sup>[[3]](#references)</sup>

As orientações do fornecedor recomendam explicitamente:

1. Atualizar para o firmware corrigido assim que estiver disponível.
2. Usar senhas administrativas fortes e exclusivas.
3. Evitar contas privilegiadas do AD na integração da impressora.

---

### Dispositivos Brother e variantes OEM – acesso administrativo derivado do serial às credenciais de serviço

Uma divulgação coordenada em 2025 demonstrou uma cadeia especialmente útil em dispositivos Brother afetados; partes do conjunto de vulnerabilidades também afetam modelos OEM, portanto verifique o modelo exato no advisory do fornecedor. Um atacante não autenticado pode obter o serial do dispositivo por HTTP/HTTPS/IPP em firmwares vulneráveis, enquanto os seriais também podem estar disponíveis por meio de protocolos de gerenciamento, como SNMP ou PJL. Se a senha de fábrica nunca tiver sido alterada, o serial determina de forma determinística a senha do administrador. Após a autenticação, a falha separada de pass-back CVE-2024-51984 expõe em texto simples as senhas configuradas de serviços externos, como LDAP ou FTP, transformando o acesso ao gerenciamento da impressora em credenciais de rede reutilizáveis. O firmware corrige a divulgação da senha de serviço, mas os dispositivos fabricados anteriormente ainda exigem que o operador substitua a senha inicial do administrador derivada do serial.<sup>[[6]](#references)</sup>

O Metasploit atual inclui um módulo auxiliar que descobre o serial por HTTP, SNMP ou PJL, gera a senha inicial candidata e, opcionalmente, a verifica no console web. `DiscoverSerialVia=AUTO` tenta os caminhos de descoberta compatíveis; forneça `TargetSerial` quando o inventário de ativos já contiver o serial.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
Use o resultado apenas para validar ativos autorizados. O funcionamento da senha depende do modelo exato e, principalmente, de a senha de administrador de fábrica já ter sido alterada ou não.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Ferramentas automatizadas de Enumeração / Exploitation

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso de PostScript/PJL/PCL, acesso ao sistema de arquivos, verificação de credenciais padrão, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Coleta de configurações (incluindo catálogos de endereços e credenciais LDAP) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Executa serviços de autenticação fraudulentos e captura/encaminha NetNTLM a partir de callbacks SMB | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Descobre um número de série, deriva a senha de administrador de fábrica candidata e verifica o acesso ao console web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening e Detecção

1. **Aplicar patches / atualizar o firmware** das MFPs prontamente (consulte os boletins PSIRT do fornecedor).
2. **Substituir as senhas de administrador de fábrica** – o firmware, por si só, não remove as senhas iniciais derivadas do número de série de dispositivos Brother/OEM afetados fabricados anteriormente.<sup>[[6]](#references)</sup>
3. **Contas de serviço com menor privilégio** – nunca use Domain Admin para LDAP/SMB/SMTP; restrinja-as a escopos de OU *somente leitura*.
4. **Restringir o acesso de gerenciamento** – coloque as interfaces web/IPP/SNMP da impressora em uma VLAN de gerenciamento ou atrás de uma ACL/VPN.
5. **Restringir o tráfego de saída da impressora** – permita que cada dispositivo se comunique apenas com os destinos esperados de DC/LDAP, e-mail, DNS/NTP, impressão e arquivos de scan. O pass-back exige um callback para um endpoint escolhido pelo atacante.
6. **Desabilitar protocolos não utilizados** – FTP, Telnet, raw-9100 e cifras SSL antigas.
7. **Habilitar o registro de auditoria** – alguns dispositivos podem enviar falhas de LDAP/SMTP para o syslog; correlacione binds inesperados.
8. **Monitorar os destinos de autenticação** – alerte quando uma impressora iniciar conexões LDAP, SMB, SMTP ou FTP para um host fora da lista de permissões, especialmente imediatamente após um login de gerenciamento ou uma alteração de configuração.
9. **SNMPv3 ou desabilitar o SNMP** – a comunidade `public` frequentemente vaza informações sobre o dispositivo e o número de série.

---



---

## References

- [1] [É apenas uma impressora... O que poderia dar errado?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Impressora multifuncional Xerox Versalink C7025: vulnerabilidades de ataque pass-back (corrigidas)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [Mitigação/Remediação da vulnerabilidade CP2025-004 para impressoras de produção, impressoras multifuncionais de escritório/pequenos escritórios e impressoras a laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtendo credenciais de domínio por meio de uma impressora com Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Explorando impressoras multifuncionais durante um trabalho de Penetration Test](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Vários dispositivos Brother: várias vulnerabilidades (CORRIGIDAS)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: módulo de bypass de autenticação do administrador padrão da Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
