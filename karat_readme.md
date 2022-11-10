[//]: # "Upravováno a prohlíženo s VS extension: [Markdown Editor v2]!"
# WebDav server

Server umožòující zobrazení obsahu webového úložištì, vèetnì otevøení a následné\
modifikace souborù a složek, bez nutnosti ukládání souborù na disk klienta.


---
## Spuštìní
1. Nastavit v souboru ~\KaratWebDavServer\Demo.cs v Main()\
   požadované parametry serveru: serverUrl, serverStorageDir, logFileName.
2. Zapnout server.
3. Namapovat webového úložištì (volitelné, \
   pokud se požaduje pouze otevírání dokumentù, ne složek).
4. Použít vybraný zpùsob otevøení souborù.

---
### Postup mapování úložištì
1) Z prùzkumníku souborù -

        1. krok: V prùzkumíku souborù pravým kliknout na 'Tento Poèítaè'.

        2. krok: Kliknout na 'Pøidat síové úložistì'.

        3. krok: Zadat serverUrl.

2) Z cmd pøíkazem - \
    Mount    - `net use x: http://localhost:4848/`\
    *Unmount - `net use x: /d`

---
### Zpùsoby otevøení souborù:
1. Spuštìní celé složky v prùzkumníku souborù (file explorer)\
   1) Pøes prùzkumníka souborù v 'Tento poèítaè'

   2) Z cmd pøíkazem: \
       `Explorer.exe \\\\localhost@4848\\DavWWWRoot\\`\
       `Explorer.exe X:\\` - varianta s net use

2. Spuštìní samostatného souboru:
    1) Z cmd pøíkazem:\
        `Explorer.exe \\\\localhost@4848\\DavWWWRoot\\pokus.docx`\
        `Explorer.exe X:\\pokus.docx` - varianta s net use

    2) Z webového prohlížeèe zadáním do vyhledávaèe:\
        `ms-word:ofe|u|http://localhost:4848/pokus.docx`\
        `ms-excel:ofe|u|http://localhost:4848/pokus.xlsx`\
        `ms-powerpoint:ofe|u|http://localhost:4848/pokus.pptx`


---
## Dùležité poznámky:
1) Soubory jsou vždy zamykány pro zápis (exkluzivním zámkem), pro zabránìní konfiktu se zámky.

    Døíve se otevíraly office dokumenty pro ètení a vyskakovala nabídka, zda chceme dokument editovat.

    Proto pro otevøení office dokumentù pøímo v režimu pro zápis jsem povolil ve všech office aplikacích:\
    ['Chránìný pøístup' -> povolit 'Soubory z internetu'].

    Jiná možné zpùsoby øešení:
    1. øešení - Vytváøet dokumenty jako 'Dùvìryhodný vydavatel' ('Trusted Publisher') - KARAT Software a.s.
    2. øešení - Nastavení v office aplikacích ['Chránìný pøístup' ->\
                -> 'Dùvìryhodné umístìní' -> pøidat cestu napø.: "http://localhost:4848/"]

2) U otevírání souborù webového prohlížeèe lze navíc nastavit HKEY_LOCAL_MACHINE registry, aby byl
   nabízen checkbox (nabídka): \
   "Always allow to open file of this type in the associated app" (Ano / ne).


---
### Debuging
Používal jsem aplikaci Wireshark s urèitými filtry pro odhalení chyby:

Použité filtry:

`tcp.port == 4848 && http`

`tcp.port == 4848 && http && (http.request.method == "PROPPATCH" || http.response)`

`tcp.port == 4848 && http && (http.response.code != 401 || (http.request && ntlmssp && !ntlmssp.negotiate.callingworkstation))`


---
### Zdroje - RFC

http://webdav.org/specs/rfc2518.html

http://www.webdav.org/specs/rfc3648.html

http://www.webdav.org/specs/rfc4918.html


---
### Inspirace pro budoucí návrh webu

Layout:\
https://webdavserver.net/Userdead041

Debuging (jedná se o podobný projekt):\
https://github.com/rezabazargan/xDav


---
### Autor
David Drtil - <<David.Drtil@karatsoftware.cz>>
