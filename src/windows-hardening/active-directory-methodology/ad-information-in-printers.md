# Informações em Impressoras

{{#include ../../banners/hacktricks-training.md}}

Existem vários blogs na Internet que **destacam os perigos de deixar impressoras configuradas com LDAP com credenciais de logon padrão/fracas**.  \
Isso ocorre porque um atacante poderia **enganar a impressora para autenticar contra um servidor LDAP malicioso** (tipicamente um `nc -vv -l -p 389` ou `slapd -d 2` é suficiente) e capturar as **credenciais da impressora em texto claro**.

Além disso, várias impressoras conterão **logs com nomes de usuários** ou poderão até mesmo **baixar todos os nomes de usuários** do Controlador de Domínio.

Todas essas **informações sensíveis** e a comum **falta de segurança** tornam as impressoras muito interessantes para os atacantes.

Alguns blogs introdutórios sobre o tema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## Configuração da Impressora

- **Localização**: A lista de servidores LDAP geralmente é encontrada na interface web (por exemplo, *Rede ➜ Configuração LDAP ➜ Configurando LDAP*).
- **Comportamento**: Muitos servidores web embutidos permitem modificações no servidor LDAP **sem reintroduzir credenciais** (recurso de usabilidade → risco de segurança).
- **Exploit**: Redirecione o endereço do servidor LDAP para um host controlado pelo atacante e use o botão *Testar Conexão* / *Sincronização da Lista de Contatos* para forçar a impressora a se conectar a você.

---
## Capturando Credenciais

### Método 1 – Listener Netcat
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Small/old MFPs podem enviar um simples *simple-bind* em texto claro que o netcat pode capturar. Dispositivos modernos geralmente realizam uma consulta anônima primeiro e depois tentam o bind, então os resultados variam.

### Método 2 – Servidor LDAP Rogue Completo (recomendado)

Porque muitos dispositivos farão uma busca anônima *antes* de autenticar, configurar um verdadeiro daemon LDAP gera resultados muito mais confiáveis:
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Quando a impressora realiza sua busca, você verá as credenciais em texto claro na saída de depuração.

> 💡 Você também pode usar `impacket/examples/ldapd.py` (Python rogue LDAP) ou `Responder -w -r -f` para coletar hashes NTLMv2 via LDAP/SMB.

---
## Vulnerabilidades Recentes de Pass-Back (2024-2025)

Pass-back *não* é um problema teórico – os fornecedores continuam publicando avisos em 2024/2025 que descrevem exatamente essa classe de ataque.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 das MFPs Xerox VersaLink C70xx permitiu que um administrador autenticado (ou qualquer um quando as credenciais padrão permanecem) pudesse:

* **CVE-2024-12510 – LDAP pass-back**: alterar o endereço do servidor LDAP e acionar uma busca, fazendo com que o dispositivo vazasse as credenciais do Windows configuradas para o host controlado pelo atacante.
* **CVE-2024-12511 – SMB/FTP pass-back**: problema idêntico via destinos de *scan-to-folder*, vazando credenciais em texto claro do NetNTLMv2 ou FTP.

Um simples listener como:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
ou um servidor SMB malicioso (`impacket-smbserver`) é suficiente para coletar as credenciais.

### Canon imageRUNNER / imageCLASS – Aviso 20 de Maio de 2025

A Canon confirmou uma vulnerabilidade de **pass-back SMTP/LDAP** em dezenas de linhas de produtos Laser e MFP. Um atacante com acesso de administrador pode modificar a configuração do servidor e recuperar as credenciais armazenadas para LDAP **ou** SMTP (muitas organizações usam uma conta privilegiada para permitir o envio de escaneamentos por e-mail).

A orientação do fornecedor recomenda explicitamente:

1. Atualizar para o firmware corrigido assim que disponível.
2. Usar senhas de administrador fortes e únicas.
3. Evitar contas AD privilegiadas para integração de impressoras.

---
## Ferramentas de Enumeração / Exploração Automatizadas

| Ferramenta | Propósito | Exemplo |
|-------------|-----------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso de PostScript/PJL/PCL, acesso ao sistema de arquivos, verificação de credenciais padrão, *descoberta SNMP* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Coletar configuração (incluindo catálogos de endereços e credenciais LDAP) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Capturar e retransmitir hashes NetNTLM de pass-back SMB/FTP | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Serviço LDAP leve e malicioso para receber ligações em texto claro | `python ldapd.py -debug` |

---
## Dureza e Detecção

1. **Patch / atualização de firmware** MFPs prontamente (verifique os boletins PSIRT do fornecedor).
2. **Contas de Serviço de Menor Privilégio** – nunca use Domain Admin para LDAP/SMB/SMTP; restrinja a escopos *somente leitura* de OU.
3. **Restringir Acesso de Gerenciamento** – coloque interfaces web/IPP/SNMP da impressora em uma VLAN de gerenciamento ou atrás de um ACL/VPN.
4. **Desativar Protocolos Não Utilizados** – FTP, Telnet, raw-9100, cifras SSL mais antigas.
5. **Ativar Registro de Auditoria** – alguns dispositivos podem registrar falhas LDAP/SMTP no syslog; correlacione ligações inesperadas.
6. **Monitorar por ligações LDAP em texto claro** de fontes incomuns (impressoras normalmente devem se comunicar apenas com DCs).
7. **SNMPv3 ou desativar SNMP** – a comunidade `public` frequentemente vaza configuração de dispositivo e LDAP.

---
## Referências

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Vulnerabilidades de Ataque Pass-Back do Xerox VersaLink C7025 MFP.” Fevereiro de 2025.
- Canon PSIRT. “Mitigação de Vulnerabilidades Contra Passback SMTP/LDAP para Impressoras a Laser e Multifuncionais de Pequenos Escritórios.” Maio de 2025.

{{#include ../../banners/hacktricks-training.md}}
