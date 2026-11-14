# Confini di fiducia dell’auto-update di Electron

{{#include ../../banners/hacktricks-training.md}}

## Superficie di attacco dell’auto-update di Electron

Considera un updater come un confine di remote-code-execution: recupera contenuti eseguibili, determina se sono più recenti e attendibili, li prepara localmente e li passa a un installer. Esamina l’intero grafo di fiducia—indice delle release, metadati per versione, artifact, firme detached, chiave di verifica incorporata, cache, percorso temporaneo e installer—non solo se il `.app` finale è firmato.<sup>[[1]](#references)[[2]](#references)</sup>

### Test di alto valore

- **Rollback/replay:** riproduci un manifest precedentemente valido e il relativo artifact ancora firmato. Una firma autentica il contenuto che protegge, ma non ne garantisce l’attualità; il client deve rifiutare versioni inferiori a una soglia monotona persistente, a meno che una policy di recovery autenticata non autorizzi esplicitamente il rollback.<sup>[[2]](#references)</sup>
- **Sostituzione di metadati/artifact:** modifica separatamente la versione, l’URL, l’hash atteso, l’artifact e la firma detached. Prova anche a combinare una coppia artifact/firma valida di una release con i metadati di un’altra. Se i metadati della release non sono firmati, TLS o un eseguibile finale firmato non impediscono a un origin/CDN compromesso di modificare la logica di selezione.<sup>[[1]](#references)[[2]](#references)</sup>
- **Confusione tra canali firmati:** distribuisci tramite il feed di produzione una build alpha, beta, development o debug firmata legittimamente. Riutilizzare la stessa chiave e la stessa policy tra ambienti permette all’artifact di superare un controllo basato solo sul signer; l’identità/canale di produzione deve far parte della policy autenticata oppure va usata una trust root separata.<sup>[[2]](#references)</sup>
- **TOCTOU dei file temporanei:** verifica se la verifica apre un pathname e l’installazione lo riapre in seguito. Se un attaccante locale può rinominare, sostituire o reindirizzare l’oggetto preparato tra queste operazioni, l’installer potrebbe usare byte mai verificati. Una directory di staging con permessi `0700` limita l’accesso, ma non rende atomiche le due operazioni.<sup>[[2]](#references)</sup>

Il triage statico e runtime può individuare rapidamente questi confini.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

Durante un test autorizzato, intercetta il controllo degli aggiornamenti, archivia ogni risposta e modifica un campo alla volta. Poi esamina proprietario e permessi della directory di staging e traccia le aperture dei file dal download all'installazione. Su macOS, se il flusso raggiunge un helper privilegiato, prosegui con i [test dei confini di fiducia dell'installer](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) e consulta le [debolezze della code-signing](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md), invece di considerare “firmato” una verifica completa dell'identità.<sup>[[2]](#references)</sup>

### Binding e policy attesi

Un design difendibile autentica sia i metadati di selezione sia i byte dell'artefatto. Il design di riferimento SafeUpdater illustra una chiave pubblica Ed25519 incorporata, manifest e artefatti firmati, un messaggio firmato derivato da `SHA-256(file)` più la versione e un digest dell'artefatto SHA-512 memorizzato nei metadati firmati; è esplicitamente un riferimento di ricerca, non un pacchetto pronto per la produzione.<sup>[[1]](#references)[[2]](#references)</sup>

Verifica che il target fornisca anche queste proprietà.<sup>[[1]](#references)[[2]](#references)</sup>

- usa una rappresentazione firmata non ambigua che associa il digest dell'artefatto alla sua versione canonica e all'ambiente di release;
- disabilita il downgrade per impostazione predefinita e impone una versione minima accettata per i rollback autorizzati;
- separa produzione e ambienti non di produzione mediante chiavi/canali distinti o dati autenticati relativi alla policy di release; e
- installa il file già verificato e aperto (o un handle/oggetto immutabile equivalente), invece di risolvere di nuovo lo stesso percorso.

## References

- [1] [Implementazione di riferimento Doyensec ElectronSafeUpdater](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: progettare un meccanismo sicuro di aggiornamento automatico per Electron](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
