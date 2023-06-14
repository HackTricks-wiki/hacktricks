# Writable Sys Path +Dll Hijacking Privesc

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introdução

Se você descobriu que pode **escrever em uma pasta do caminho do sistema** (observe que isso não funcionará se você puder escrever em uma pasta do caminho do usuário), é possível que você possa **elevar privilégios** no sistema.

Para fazer isso, você pode abusar de um **Dll Hijacking** em que você vai **sequestrar uma biblioteca sendo carregada** por um serviço ou processo com **mais privilégios** do que os seus, e porque esse serviço está carregando uma Dll que provavelmente nem existe em todo o sistema, ele vai tentar carregá-la do Caminho do Sistema onde você pode escrever.

Para mais informações sobre **o que é Dll Hijacking** confira:

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Privesc com Dll Hijacking

### Encontrando uma Dll ausente

A primeira coisa que você precisa é **identificar um processo** em execução com **mais privilégios** do que você que está tentando **carregar uma Dll do Caminho do Sistema** em que você pode escrever.

O problema nesses casos é que provavelmente esses processos já estão em execução. Para encontrar quais Dlls estão faltando nos serviços que você precisa lançar o procmon o mais rápido possível (antes que os processos sejam carregados). Então, para encontrar as .dlls ausentes faça:

* **Crie** a pasta `C:\privesc_hijacking` e adicione o caminho `C:\privesc_hijacking` à **variável de ambiente do Caminho do Sistema**. Você pode fazer isso **manualmente** ou com **PS**:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
    New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
    $newPath = "$envPath;$folderPath"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* Inicie o **`procmon`** e vá em **`Opções`** --> **`Habilitar log de inicialização`** e pressione **`OK`** na janela de confirmação.
* Em seguida, **reinicie** o computador. Quando o Windows for reiniciado, o **`procmon`** começará a **gravar** eventos imediatamente.
* Assim que o Windows for iniciado, execute o **`procmon`** novamente. Ele informará que está em execução e perguntará se você deseja armazenar os eventos em um arquivo. Responda **sim** e **armazene os eventos em um arquivo**.
* **Depois** que o **arquivo** for **gerado**, **feche** a janela do **`procmon`** aberta e **abra o arquivo de eventos**.
* Adicione esses **filtros** e você encontrará todas as DLLs que algum **processo tentou carregar** da pasta do caminho do sistema gravável:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### DLLs perdidas

Executando isso em uma máquina virtual gratuita do **Windows 11 (vmware)**, obtive estes resultados:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

Neste caso, os arquivos .exe são inúteis, então ignore-os. As DLLs perdidas eram de:

| Serviço                         | Dll                | Linha de comando                                                     |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Agendador de Tarefas (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Serviço de Política de Diagnóstico (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Depois de encontrar isso, encontrei este interessante post de blog que também explica como [**abusar do WptsExtensions.dll para escalonamento de privilégios**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Que é o que vamos fazer agora.

### Exploração

Então, para **escalar privilégios**, vamos sequestrar a biblioteca **WptsExtensions.dll**. Tendo o **caminho** e o **nome**, só precisamos **gerar a DLL maliciosa**.

Você pode [**tentar usar qualquer um desses exemplos**](../dll-hijacking.md#creating-and-compiling-dlls). Você pode executar payloads como: obter um shell reverso, adicionar um usuário, executar um beacon...

{% hint style="warning" %}
Observe que **nem todos os serviços são executados** com **`NT AUTHORITY\SYSTEM`**, alguns também são executados com **`NT AUTHORITY\LOCAL SERVICE`**, que tem **menos privilégios** e você **não poderá criar um novo usuário** abusando de suas permissões.\
No entanto, esse usuário tem o privilégio **`seImpersonate`**, então você pode usar o [**conjunto de ferramentas potato para escalar privilégios**](../roguepotato-and-printspoofer.md). Portanto, neste caso, um shell reverso é uma opção melhor do que tentar criar um usuário.
{% endhint %}

No momento da escrita deste artigo, o serviço **Agendador de Tarefas** é executado com **Nt AUTHORITY\SYSTEM**.

Tendo **gerado a DLL maliciosa** (_no meu caso, usei um shell reverso x64 e consegui um shell de volta, mas o defender o matou porque era do msfvenom_), salve-a no caminho do sistema gravável com o nome **WptsExtensions.dll** e **reinicie** o computador (ou reinicie o serviço ou faça o que for necessário para executar novamente o serviço/programa afetado).

Quando o serviço for reiniciado, a **DLL deve ser carregada e executada** (você pode **reutilizar** o **truque do procmon** para verificar se a **biblioteca foi carregada conforme o esperado**).

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
