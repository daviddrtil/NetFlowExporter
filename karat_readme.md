[//]: # "Upravov�no a prohl�eno s VS extension: [Markdown Editor v2]!"
# WebDav server

Server umo��uj�c� zobrazen� obsahu webov�ho �lo�i�t�, v�etn� otev�en� a n�sledn�\
modifikace soubor� a slo�ek, bez nutnosti ukl�d�n� soubor� na disk klienta.


---
## Spu�t�n�
1. Nastavit v souboru ~\KaratWebDavServer\Demo.cs v Main()\
   po�adovan� parametry serveru: serverUrl, serverStorageDir, logFileName.
2. Zapnout server.
3. Namapovat webov�ho �lo�i�t� (voliteln�, \
   pokud se po�aduje pouze otev�r�n� dokument�, ne slo�ek).
4. Pou��t vybran� zp�sob otev�en� soubor�.

---
### Postup mapov�n� �lo�i�t�
1) Z pr�zkumn�ku soubor� -

        1. krok: V pr�zkum�ku soubor� prav�m kliknout na 'Tento Po��ta�'.

        2. krok: Kliknout na 'P�idat s�ov� �lo�ist�'.

        3. krok: Zadat serverUrl.

2) Z cmd p��kazem - \
    Mount    - `net use x: http://localhost:4848/`\
    *Unmount - `net use x: /d`

---
### Zp�soby otev�en� soubor�:
1. Spu�t�n� cel� slo�ky v pr�zkumn�ku soubor� (file explorer)\
   1) P�es pr�zkumn�ka soubor� v 'Tento po��ta�'

   2) Z cmd p��kazem: \
       `Explorer.exe \\\\localhost@4848\\DavWWWRoot\\`\
       `Explorer.exe X:\\` - varianta s net use

2. Spu�t�n� samostatn�ho souboru:
    1) Z cmd p��kazem:\
        `Explorer.exe \\\\localhost@4848\\DavWWWRoot\\pokus.docx`\
        `Explorer.exe X:\\pokus.docx` - varianta s net use

    2) Z webov�ho prohl�e�e zad�n�m do vyhled�va�e:\
        `ms-word:ofe|u|http://localhost:4848/pokus.docx`\
        `ms-excel:ofe|u|http://localhost:4848/pokus.xlsx`\
        `ms-powerpoint:ofe|u|http://localhost:4848/pokus.pptx`


---
## D�le�it� pozn�mky:
1) Soubory jsou v�dy zamyk�ny pro z�pis (exkluzivn�m z�mkem), pro zabr�n�n� konfiktu se z�mky.

    D��ve se otev�raly office dokumenty pro �ten� a vyskakovala nab�dka, zda chceme dokument editovat.

    Proto pro otev�en� office dokument� p��mo v re�imu pro z�pis jsem povolil ve v�ech office aplikac�ch:\
    ['Chr�n�n� p��stup' -> povolit 'Soubory z internetu'].

    Jin� mo�n� zp�soby �e�en�:
    1. �e�en� - Vytv��et dokumenty jako 'D�v�ryhodn� vydavatel' ('Trusted Publisher') - KARAT Software a.s.
    2. �e�en� - Nastaven� v office aplikac�ch ['Chr�n�n� p��stup' ->\
                -> 'D�v�ryhodn� um�st�n�' -> p�idat cestu nap�.: "http://localhost:4848/"]

2) U otev�r�n� soubor� webov�ho prohl�e�e lze nav�c nastavit HKEY_LOCAL_MACHINE registry, aby byl
   nab�zen checkbox (nab�dka): \
   "Always allow to open file of this type in the associated app" (Ano / ne).


---
### Debuging
Pou��val jsem aplikaci Wireshark s ur�it�mi filtry pro odhalen� chyby:

Pou�it� filtry:

`tcp.port == 4848 && http`

`tcp.port == 4848 && http && (http.request.method == "PROPPATCH" || http.response)`

`tcp.port == 4848 && http && (http.response.code != 401 || (http.request && ntlmssp && !ntlmssp.negotiate.callingworkstation))`


---
### Zdroje - RFC

http://webdav.org/specs/rfc2518.html

http://www.webdav.org/specs/rfc3648.html

http://www.webdav.org/specs/rfc4918.html


---
### Inspirace pro budouc� n�vrh webu

Layout:\
https://webdavserver.net/Userdead041

Debuging (jedn� se o podobn� projekt):\
https://github.com/rezabazargan/xDav


---
### Autor
David Drtil - <<David.Drtil@karatsoftware.cz>>
