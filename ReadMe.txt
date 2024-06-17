Build/Path variables
********************
The following Buld/Path Variables must be defined at workspace level:
SW_ROOT	Directory C:\Tools\TexasInstruments\TivaWare_C_Series-2.2.0.295
SW_FREERTOS	Directory C:\Tools\ThirdParty\FreeRTOSv10.2.1


Required ThirdParty software
****************************
FreeRTOS




Filesystem
***********
Create the file system using the command
"makefsfile -i fs -o myfsdata.h -h"  (or "makefsfile -i fs -o myfsdata.h -r -h -q")
in the project folder (as the makefsfile.exe file is present in the project folder! (copied from "C:\Tools\TexasInstruments\TivaWare_C_Series-2.1.4.178\tools\bin"))

Anleitung in C:\Tools\TexasInstruments\TivaWare_C_Series-2.1.4.178\docs, File: SW-TM4C-TOOLS-UG-2.1.4.178.pdf, Abschnitt 16 (web Filesystem Generator)
  -i: input folder
  -o: output file name
  -h: excludes HTTP headers from files.


cd C:\Data\Workspaces\workspace_ccs_v9_ss20_VS\webserver_1




Required include paths
***********************
Add include path (Properties>Build>Include Path): 
- "${SW_ROOT}\third_party"
- "${SW_ROOT}\third_party\lwip-1.4.1\apps"
- "${SW_ROOT}\third_party\lwip-1.4.1\ports\tiva-tm4c129\include"
- "${SW_ROOT}\third_party\lwip-1.4.1\src\include"
- "${SW_ROOT}\third_party\lwip-1.4.1\src\include\ipv4"



Favicon
*******
z.B. 32x32 pixel
Created with PHOTO-PAINT, 32x32 pixel, character size: 18 (for VS)  and 8 (for HTWG)
Exported as -ico



SSI:
****
ServerSideInclude
Dient zum Austausch von Daten vom Webserver zum Browser
Ein SSIhandler ersetzt die Tags (z.B. "ledR" gegeben als <!--#ledR-->) im html-File vor dem Versenden an den Browser durch die entsprechenden Werte

Die Tags sind im File "ssiHandler.c" in der Struktur "g_pcConfigSSITags" eingetragen. 
Die Bearbeitung erfolgt durch die Funktion "int32_t ssiHandler(int32_t iIndex, char *pcInsert, int32_t iInsertLen)" anhand des jedem Eintrag zugewiesenen Index.

Der SSI-Handler (ssiHandler(int32_t iIndex, char *pcInsert, int32_t iInsertLen)) und die Liste der Tags wird dem HTTPD server bei der Initialisierung über den Befehl 
"http_set_ssi_handler((tSSIHandler)ssiHandler, g_pcConfigSSITags, NUM_CONFIG_SSI_TAGS);" mitgeteilt.

ACHTUNG: In der aktuellen Implementierung darf ein Tag-Name maximal 8 Zeichen lang sein

The server will call SSIHandler to request a replacement string whenever the pattern <!--#tagname--> is found in ".ssi", ".shtml" or ".shtm" files that it serves.




CGI
***
CommonGatewayInterface
Austausch von Daten vom Browser zum Webserver
Im html-Dokument werden die Daten innerhalb eines "forms" eingetragen.
Dem form ist eine URL zugeordnet (im feld "action") an die das form beim submit eine Anfrage (meist: method="GET") schickt.
Die im form vorhandenen "input"-Werte werden als Name-Wert-Paare der GET-Anfrage mitgegeben (sieht man auch in der Adressleiste des Browsers)

  z.B.:
     <form method="get" action="numberform.cgi" name="numberform" id="rgbFormID">
       ...
       <input type="range" min="0" max="255" step="1" value="0" name="rgbledr">
       ...
       <input type="range" min="0" max="255" step="1" value="0" name="rgbledg">
       ...
       <input type="number" min="0" max="255" step="1" value="0" name="rgbledb">
       ...
       <input name="rgb" value="submit" type="submit">
       <button form="rgbFormID" type="reset">reset</button>
     </form>
     
  Wenn der Reset-butten gedrückt wird, wird das form mit der gegebeben ID ("rgbFormID") zurückgesetzt (auf Startwerte, gegeben in "value = ")
  Wenn der Submit-button gedrückt wird, wird eine GET-Anfrage mit allen Parameter-Wert-Paaren an die URI "numberform.cgi" gesendet, z.B. 
        "http://141.37.159.202/numberform.cgi?rgbledr=108&rgbledg=167&rgbledb=15&rgb=submit"
        
Die vom CGI-Handler abzufangenen URIs sind im File "cgiHandler.c" im Feld "g_psConfigCGIURIs" eingetragen.
In diesem Feld ist jeder URI ein entsprechender Handler als Callback-Funktion zugeordnet.

Bei der Initialisierung muss dieses Feld dem HTTPD-Server mitgeteilt werden:
"http_set_cgi_handlers(g_psConfigCGIURIs, NUM_CONFIG_CGI_URIS);"


JavaScript
**********
This script replaces the content of div "content" with the new input fields !

