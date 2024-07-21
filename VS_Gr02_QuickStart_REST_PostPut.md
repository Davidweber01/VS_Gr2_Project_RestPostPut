# REST API POST/PUT



## Inhaltsverzeichnis

- [Klonen](#Klonen)
- [Import](#Import)
- [Debug und Start](#Debug-und-Start)
- [Postman](#Postman)

## Klonen

Um das Projekt lokal auf deinem Rechner einzurichten, folge bitte diesen Schritten:

1. **Repository klonen**
    ```bash
   cd CCS_Workspace
    ```
   
   ```bash
   git clone https://github.com/Davidweber01/VS_Gr2_Project_RestPostPut.git
   ```

## Import
Projekt -> CCS Projekt Importieren -> Select Archive Directory -> VS_Gr2_Project_RestPostPut -> Finish

## Debug und Start
Das Projekt kann ohne Veränderungen direkt gedebugt und gestartet werden. 
Nach dem Debug-Prozess sollte noch ein Serielles Terminal für die UART Kommunikation geöffnet werden.
![](qg2.png)

## Postman

Postman Herunterladen:

https://www.postman.com/downloads/

Installations Guide Folgen und Starten

![](qg1.png)

Auf "Continue with lightweight API client" klicken oder Account erstellen, ist aber nicht notwendig.


### GET-Anfrage

Für eine GET-Anfrage die IP-Adresse des Webservers aus dem Terminal kopieren und die URI der gewünschten Ressource anhängen

![](qg3.png)


Als Anfrage "GET" Auswählen und abschicken.

Als Antwort erhält man eine Liste aller User.



