{{#include ../../banners/hacktricks-training.md}}

# Controlla le possibili azioni all'interno dell'applicazione GUI

**Dialoghi comuni** sono quelle opzioni di **salvataggio di un file**, **apertura di un file**, selezione di un font, un colore... La maggior parte di essi **offrirà una funzionalità completa di Explorer**. Questo significa che sarai in grado di accedere alle funzionalità di Explorer se puoi accedere a queste opzioni:

- Chiudi/Chiudi come
- Apri/Apri con
- Stampa
- Esporta/Importa
- Cerca
- Scansiona

Dovresti controllare se puoi:

- Modificare o creare nuovi file
- Creare collegamenti simbolici
- Accedere ad aree riservate
- Eseguire altre app

## Esecuzione di comandi

Forse **utilizzando un'opzione `Apri con`** puoi aprire/eseguire qualche tipo di shell.

### Windows

Ad esempio _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trova più binari che possono essere utilizzati per eseguire comandi (e compiere azioni inaspettate) qui: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX \_\_

_bash, sh, zsh..._ Maggiori informazioni qui: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Bypassare le restrizioni del percorso

- **Variabili di ambiente**: Ci sono molte variabili di ambiente che puntano a qualche percorso
- **Altri protocolli**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Collegamenti simbolici**
- **Scorciatoie**: CTRL+N (apri nuova sessione), CTRL+R (Esegui comandi), CTRL+SHIFT+ESC (Gestione attività), Windows+E (apri explorer), CTRL-B, CTRL-I (Preferiti), CTRL-H (Cronologia), CTRL-L, CTRL-O (File/Dialogo di apertura), CTRL-P (Dialogo di stampa), CTRL-S (Salva con nome)
- Menu amministrativo nascosto: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Strumenti amministrativi, shell:Libreria documenti, shell:Librerie, shell:Profili utente, shell:Personale, shell:Cerca nella cartella home, shell:Posti di rete, shell:Invia a, shell:Profili utenti, shell:Strumenti amministrativi comuni, shell:Cartella computer, shell:Cartella Internet_
- **Percorsi UNC**: Percorsi per connettersi a cartelle condivise. Dovresti provare a connetterti al C$ della macchina locale ("\\\127.0.0.1\c$\Windows\System32")
- **Altri percorsi UNC:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUT
