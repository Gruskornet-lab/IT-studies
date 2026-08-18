# TryHackMe — REvil Corp

| | |
|---|---|
| **URL** | https://tryhackme.com/room/revilcorp |
| **Kategori** | DFIR / Minnesforensik / Ransomware-analys |
| **Svårighetsgrad** | Medium |
| **Uppskattad tid** | 45 minuter |
| **Antal genomförda** | 6 869 |
| **Datum genomfört** | ÅÅÅÅ-MM-DD |

## Översikt
En anställd på Lockman Group rapporterade att alla filer på arbetsstationen bytt namn till en okänd filändelse. IT-avdelningen eskalerade till Incident Response-teamet.
Din uppgift är att analysera den komprometterade endpointen med Redline (Mandiant Analysis-filen finns redan förberedd på skrivbordet)
och kartlägga hela infektionskedjan — från nedladdning till ransomware-notan.

---

## Uppgift 1 — Undersöka den komprometterade endpointen

---

**F1: Vad är den drabbade medarbetarens fullständiga namn?**

**Tillvägagångssätt:**
När vi öppnar Redline verktyget så kan vi gå i på system information där vi kommer hitta mycket information av den påverkade dator.
Under user information så hittar vi användarens namn
**Svar:**
John Coleman
---

**F2: Vilket operativsystem kör den komprometterade värden?**

**Tillvägagångssätt:**
Svaret hittas under "Operating System Information"

**Svar:**
Windows 7 Home Premium 7601 Service Pack 1
---

**F3: Vad heter den skadliga körbara filen som användaren öppnade?**

**Tillvägagångssätt:**
Malware typen låter som i förklaringen som ett klassikst ransomware som krypterar filer direkt när det körs.
Alltså kan man tänka sig att den misstänkta filen som kördes nydligen laddats ner. 
På redline tool kan vi hitta en flik som vissar ner laddade filers historia och där kan vi hitta en fil som nydligen blivit nerladdad. 

**Svar:**
WinRAR2021.exe
---

**F4: Vad är den fullständiga URL:en som användaren besökte för att ladda ner den skadliga binären?**

**Tillvägagångssätt:**

**Svar:**
http://192[.]168[.]75[.]129:4748/Documents/WinRAR2021[.]exe
---

**F5: Vad är binärens MD5-hash?**

**Tillvägagångssätt:**

**Svar:**
890a58f200dfff23165df9e1b088e58[f]
---

**F6: Vad är binärens storlek i kilobyte?**

**Tillvägagångssätt:**

**Svar:**
164
---

**F7: Vilken filändelse fick användarens filer bytt till?**

**Tillvägagångssätt:**

**Svar:**
.t48s39la
---

**F8: Hur många filer fick namnet och ändelsen ändrad?**

**Tillvägagångssätt:**

**Svar:**
48
---

**F9: Vad är den fullständiga sökvägen till bakgrundsbilden som angriparen ändrade, inklusive bildens namn?**

**Tillvägagångssätt:**

**Svar:**
C:\Users\John Coleman\AppData\Local\Temp\hk8.bmp
---

**F10: Angriparen lämnade ett meddelande till användaren på skrivbordet — ange notens namn med filändelse.**

**Tillvägagångssätt:**

**Svar:**
t48s39la-readme.txt
---

**F11: Angriparen skapade en mapp "Links for United States" under C:\Users\John Coleman\Favorites\ och lämnade en fil där. Ange filens namn.**

**Tillvägagångssätt:**

**Svar:**
GobiernoUSA.gov.url.t48s39la
---

**F12: Det finns en dold fil som skapades på användarens skrivbord med 0 byte. Ange den dolda filens namn.**

**Tillvägagångssätt:**

**Svar:**
d60dff40.lock
---

**F13: Användaren laddade ner en dekrypterare i hopp om att låsa upp filerna, men misslyckades. Ange dekrypterarfilens MD5-hash.**

**Tillvägagångssätt:**

**Svar:**
f617af8c0d276682fdf528bb3e72560[b]
---

**F14: I ransomware-notan angav angriparen en URL som är åtkomlig via en vanlig webbläsare för att dekryptera en fil gratis. Ange den fullständiga URL:en.**

**Tillvägagångssätt:**

**Svar:**
http://decryptor[.]top/644E7C8EFA02FBB7
---

**F15: Vilka är tre namn associerade med skadeprogrammet som infekterade den här värden? (i bokstavsordning)**

**Tillvägagångssätt:**

**Svar:**
REvil,Sodin,Sodinokibi
---

## Indicators of Compromise (IOC:er)

| Typ | Värde | Beskrivning |
|-----|-------|-------------|
| Hash (binär) | 890a58f200dfff23165df9e1b088e58[f] |  |
| Hash (dekrypterare) | f617af8c0d276682fdf528bb3e72560[b] |  |
| URL (nedladdning) | http://192[.]168[.]75[.]129:4748/Documents/WinRAR2021[.]exe |  |
| URL (dekrypteringssida) | http://decryptor[.]top/644E7C8EFA02FBB7 |  |
| Filnamn | WinRAR2021.exe |  |
| Filändelse |  |  |

## Viktigaste lärdomar
- Korrekta filter
- Användning av hash att lägga in i hemsidor som virustotal
