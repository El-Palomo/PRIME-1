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


## 4. Explotando la Vulnerabilidad






















