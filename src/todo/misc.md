{{#include ../banners/hacktricks-training.md}}

핑 응답 TTL:\
127 = Windows\
254 = Cisco\
나머지, 어떤 리눅스

$1$- md5\
$2$ 또는 $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

서비스 뒤에 무엇이 있는지 모른다면, HTTP GET 요청을 시도해 보세요.

**UDP 스캔**\
nc -nv -u -z -w 1 \<IP> 160-16

특정 포트로 빈 UDP 패킷이 전송됩니다. UDP 포트가 열려 있으면, 대상 머신에서 응답이 전송되지 않습니다. UDP 포트가 닫혀 있으면, 대상 머신에서 ICMP 포트 도달 불가 패킷이 전송되어야 합니다.\
UDP 포트 스캔은 종종 신뢰할 수 없으며, 방화벽과 라우터가 ICMP 패킷을 차단할 수 있습니다. 이는 스캔에서 잘못된 긍정 결과를 초래할 수 있으며, 스캔된 머신에서 모든 UDP 포트가 열려 있는 것으로 표시되는 경우가 자주 있습니다.\
대부분의 포트 스캐너는 사용 가능한 모든 포트를 스캔하지 않으며, 일반적으로 스캔할 "흥미로운 포트"의 미리 설정된 목록을 가지고 있습니다.

# CTF - 트릭

**Windows**에서 **Winzip**을 사용하여 파일을 검색하세요.\
**대체 데이터 스트림**: _dir /r | find ":$DATA"_
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Start with "_begin \<mode> \<filename>_" and weird chars\
**Xxencoding** --> Start with "_begin \<mode> \<filename>_" and B64\
\
**Vigenere** (frequency analysis) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (offset of characters) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> 메시지를 공백과 탭을 사용하여 숨기기

# Characters

%E2%80%AE => RTL Character (writes payloads backwards)

{{#include ../banners/hacktricks-training.md}}
