# Limites de confiança do auto-update do Electron

{{#include ../../banners/hacktricks-training.md}}

## Superfície de ataque do auto-update do Electron

Trate um atualizador como um limite de execução remota de código: ele busca conteúdo executável, decide se esse conteúdo é mais recente e confiável, prepara-o localmente e o entrega a um instalador. Revise todo o grafo de confiança — índice de releases, metadados por versão, artefato, assinaturas destacadas, chave de verificação incorporada, cache, caminho temporário e instalador — e não apenas se o `.app` final está assinado.<sup>[[1]](#references)[[2]](#references)</sup>

### Testes de alto valor

- **Rollback/replay:** reproduza um manifesto anteriormente válido e seu artefato ainda assinado. Uma assinatura autentica sua entrada, mas não garante atualidade; o cliente deve rejeitar versões abaixo de um limite monotônico persistente, a menos que uma política de recuperação autenticada autorize explicitamente o rollback.<sup>[[2]](#references)</sup>
- **Substituição de metadados/artefato:** altere separadamente a versão, a URL, o hash esperado, o artefato e a assinatura destacada. Tente também combinar um par válido de artefato/assinatura de uma release com metadados de outra. Se os metadados da release não estiverem assinados, TLS ou um executável final assinado não impedem que uma origem/CDN comprometida altere a lógica de seleção.<sup>[[1]](#references)[[2]](#references)</sup>
- **Confusão de canal com assinatura válida:** distribua pelo feed de produção uma build alpha, beta, de desenvolvimento ou debug legitimamente assinada. Reutilizar a mesma chave e política em diferentes ambientes permite que o artefato passe por uma verificação que confere apenas o signatário; a identidade/canal de produção deve fazer parte da política autenticada, ou deve ser usada uma raiz de confiança separada.<sup>[[2]](#references)</sup>
- **TOCTOU de arquivo temporário:** determine se a verificação abre um caminho e a instalação reabre esse mesmo caminho mais tarde. Se um atacante local puder renomear, substituir ou redirecionar o objeto preparado entre essas operações, o instalador poderá consumir bytes que nunca foram verificados. Um diretório de preparação com permissões `0700` restringe o acesso, mas não torna as duas operações atômicas.<sup>[[2]](#references)</sup>

A triagem estática e em tempo de execução pode localizar rapidamente esses limites.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

Durante um teste autorizado, intercepte a verificação de atualização, arquive todas as respostas e altere um campo por vez. Em seguida, inspecione a propriedade e as permissões do diretório de staging e rastreie as aberturas de arquivos desde o download até a instalação. No macOS, prossiga com os [testes de limite de confiança do instalador](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) se o fluxo chegar a um helper privilegiado e revise as [fragilidades de code signing](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md), em vez de tratar “assinado” como uma verificação completa de identidade.<sup>[[2]](#references)</sup>

### Vinculação e política esperadas

Um design defensável autentica tanto os metadados de seleção quanto os bytes do artefato. O design de referência do SafeUpdater demonstra uma chave pública Ed25519 incorporada, manifestos e artefatos assinados, uma mensagem assinada derivada de `SHA-256(file)` mais a versão, e um digest SHA-512 do artefato armazenado em metadados assinados; ele é explicitamente uma referência de pesquisa, não um pacote pronto para produção.<sup>[[1]](#references)[[2]](#references)</sup>

Verifique se o alvo também oferece estas propriedades.<sup>[[1]](#references)[[2]](#references)</sup>

- usa uma representação assinada inequívoca que vincula o digest do artefato à sua versão canônica e ao ambiente de release;
- desativa o downgrade por padrão e impõe uma versão mínima aceita para rollback autorizado;
- separa produção de ambientes não produtivos por meio de chaves/canais distintos ou dados autenticados de política de release; e
- instala o arquivo aberto já verificado (ou um identificador/objeto imutável equivalente), em vez de resolver o mesmo caminho novamente.

## References

- [1] [Implementação de referência Doyensec ElectronSafeUpdater](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: projetando um mecanismo seguro de atualização automática para Electron](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
