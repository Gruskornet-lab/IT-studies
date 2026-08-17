# TryHackMe — Shadow Trace

| | |
|---|---|
| **Rum** | Shadow Trace |
| **Kategori** | Malware-analys / SOC |
| **Verktyg använda** | PEStudio, CyberChef |
| **Datum genomfört** | 2026-08-17 |

## Scenario

> Analysera en misstänkt fil, hitta dolda ledtrådar och spåra infektionens ursprung.
>
> Det är mitt i nattskiftet. Du är ensam analytiker i SOC:en när en chef ringer akut: en misstänkt fil har hittats på en användares maskin och behöver omedelbar granskning. Du öppnar filen och börjar gräva. Något känns inte normalt för en företagsuppdaterare, och samtidigt slår EDR:en larm om ett par varningar.
>
> **Uppgift:** analysera filen, samla in det som kan identifiera den, hitta potentiella IOC:er, och korrelera/analysera larmen för potentiellt skadligt beteende.

---

## Analys

### 1. Vilken arkitektur har binärfilen `windows-update.exe`?

**Tillvägagångssätt:** Laddade in filen i PEStudio och kollade header-informationen längst ner i gränssnittet.

**Fynd:** Fältet `cpu` under filegenskaperna visar målarkitekturen direkt.

**Svar:** `64-bit`

---

### 2. Vad är hashen (SHA-256) för filen `windows-update.exe`?

**Tillvägagångssätt:** PEStudio räknar automatiskt ut vanliga hashar. SHA-256-värdet finns i panelen längst ner till vänster, och kan också hittas under sektionen "footprints".

**Svar:**
```
B2A88DE3E3BCFAE4A4B38FA36E884C586B5CB2C2C283E71FBA59EFDB9EA64BF
```

---

### 3. Identifiera URL:en i filen för att använda den som en IOC

**Tillvägagångssätt:** Använde **strings**-vyn i PEStudio för att lista inbäddad text i binären, och skrollade sedan igenom resultatet för att hitta nätverksrelaterade indikatorer.

**Svar (defangat):**
```
http://tryhatme[.]com/update/security-update[.]exe
```

---

### 4. Utifrån URL:en, kan du hitta en domän som kan användas som en IOC?

**Tillvägagångssätt:** Samma strings-resultat som ovan — en andra, relaterad domän för callback/svarstrafik syntes intill den första URL:en.

**Svar (defangat):**
```
responses[.]tryhatme[.]com
```

---

### 5. Ange den avkodade flaggan från den misstänkta domänen

**Tillvägagångssätt:** Baserat på erfarenhet av TryHackMe-rum brukar flaggor gömmas som Base64-kodade strängar bifogade till en URL. Vid vidare skrollning i strings-resultatet syntes en misstänkt länk:

```
tryhatme[.]com/VEhNe3lvdV9nMHRfc29tZV9JT0NzX2ZyaWVuZH0=
```

Den avslutande strängen var Base64-kodad. Avkodning via CyberChefs recept `From Base64` gav flaggan.

**Svar:** `THM{REDACTED}`

---

### 6. Vilket bibliotek relaterat till socket-kommunikation laddas av binären?

**Tillvägagångssätt:** Eftersom filen är en Windows PE-binär (`.exe`) hanteras socket-kommunikation via Windows Sockets API snarare än en Linux libc-motsvarighet. Bekräftat genom att kolla imports/strings efter relevant DLL.

**Svar:** `WS2_32.dll`

---

## Indicators of Compromise (IOCs)

| Typ | Värde (defangat) |
|------|-------------------|
| SHA-256 | `B2A88DE3E3BCFAE4A4B38FA36E884C586B5CB2C2C283E71FBA59EFDB9EA64BF` |
| URL | `http://tryhatme[.]com/update/security-update[.]exe` |
| Domän | `responses[.]tryhatme[.]com` |
| Laddat bibliotek | `WS2_32.dll` (Windows Sockets API) |

---

## Viktiga lärdomar

- En fil som utger sig för att vara en legitim "företagsuppdaterare" är ett vanligt social engineering-/persistens-trick — verifiera alltid signatur, hash och beteende snarare än att lita på filnamnet.
- `WS2_32.dll` i importtabellen för en Windows PE-binär är en stark tidig signal på att filen har nätverksfunktionalitet, värt att flagga redan innan dynamisk analys görs.
- Base64-kodade strängar bifogade till URL:er är ett återkommande mönster för dolda payloads/flaggor — värt att leta efter vid statisk strängsanalys.


# TryHackMe — Shadow Trace

| | |
|---|---|
| **Room** | Shadow Trace |
| **Category** | Malware Analysis / SOC |
| **Tools used** | PEStudio, CyberChef |
| **Date completed** | 2026-08-17 |

## Scenario

> Analyse a suspicious file, uncover hidden clues, and trace the source of the infection.
>
> It's the middle of the night shift. You're the only analyst in the SOC when a manager calls in urgently: a suspicious file was found on a user's machine and needs immediate review. You open the file and start digging. Something doesn't look normal for a company updater, and at the same time, the EDR throws a couple of alerts.
>
> **Task:** analyse the file, collect anything to identify it, gather any potential IOCs, correlate and analyse the alerts for potential malicious behaviour.

---

## Analysis

### 1. What is the architecture of the binary file `windows-update.exe`?

**Approach:** Loaded the binary into PEStudio and checked the header information panel at the bottom of the interface.

**Finding:** The `cpu` field under the file properties shows the target architecture directly.

**Answer:** `64-bit`

---

### 2. What is the hash (SHA-256) of the file `windows-update.exe`?

**Approach:** PEStudio calculates common hashes automatically. The SHA-256 value is available in the bottom-left panel, and can also be cross-referenced under the "footprints" section.

**Answer:**
```
B2A88DE3E3BCFAE4A4B38FA36E884C586B5CB2C2C283E71FBA59EFDB9EA64BF
```

---

### 3. Identify the URL within the file to use it as an IOC

**Approach:** Used the **strings** view in PEStudio to list embedded text within the binary, then scrolled through the extracted strings to identify network-related indicators.

**Answer (defanged):**
```
http://tryhatme[.]com/update/security-update[.]exe
```

---

### 4. With the URL identified, can you spot a domain that can be used as an IOC?

**Approach:** Same strings output as above — a second, related domain used for callback/response traffic was visible alongside the initial URL.

**Answer (defanged):**
```
responses[.]tryhatme[.]com
```

---

### 5. Input the decoded flag from the suspicious domain

**Approach:** Based on experience with TryHackMe rooms, flags are often hidden as Base64-encoded strings appended to a URL. Scanning the strings output further revealed a suspicious link:

```
tryhatme[.]com/VEhNe3lvdV9nMHRfc29tZV9JT0NzX2ZyaWVuZH0=
```

The trailing string was Base64-encoded. Decoding it via CyberChef's `From Base64` recipe revealed the flag.

**Answer:** `THM{REDACTED}`

---

### 6. What library related to socket communication is loaded by the binary?

**Approach:** Since the file is a Windows PE binary (`.exe`), socket communication is handled through the Windows Sockets API rather than a Linux libc equivalent. Confirmed by checking the imports/strings for the relevant DLL.

**Answer:** `WS2_32.dll`

---

## Indicators of Compromise (IOCs)

| Type | Value (defanged) |
|------|-------------------|
| SHA-256 | `B2A88DE3E3BCFAE4A4B38FA36E884C586B5CB2C2C283E71FBA59EFDB9EA64BF` |
| URL | `http://tryhatme[.]com/update/security-update[.]exe` |
| Domain | `responses[.]tryhatme[.]com` |
| Loaded library | `WS2_32.dll` (Windows Sockets API) |

---

## Key Takeaways

- A file impersonating a legitimate "company updater" is a common social engineering / persistence trick — always verify signer, hash, and behavior rather than trusting the filename.
- `WS2_32.dll` in the import table of a Windows PE binary is a strong early signal that the file has network capability, worth flagging even before dynamic analysis.
- Base64-encoded strings appended to URLs are a recurring pattern for hidden payloads/flags — worth scanning for during static string analysis.
