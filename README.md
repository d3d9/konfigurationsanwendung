Konfigurationsanwendung
===

Erstellt im Rahmen vom Modul IT-Sicherheit an der FH SWF im Sommersemester 2019.
Kann beispielsweise (mitgeliefert) verwendet werden für einfache Eingabe/Speicherung von Werbetexten, Farbe, Helligkeit für ein Fahrgastinformationssystem (siehe <https://d3d9.xyz/dfi/>).

Ausführung beispielsweise (vorher pipenv sync und ggf. auch pipenv install gunicorn notwendig):
```
ExecStart=/bin/sh -c 'pipenv run gunicorn --preload -w4 --access-logfile - --certfile fullchain.pem --keyfile=privkey.pem --bind 0.0.0.0:8000 main:app'
```
