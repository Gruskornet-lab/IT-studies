# Hitta avvikelser i AD-loggar: baseline och stack counting

Källa: TryHackMe: LÄGG TILL RUMSNAMN OCH LÄNK

Grundprincip: man måste veta hur normalt ser ut för att kunna upptäcka det onormala. Målet är inte att granska varje event, utan att hitta avvikelserna bland bruset.

## Baseline (vad som är normalt)

### Normal volym

Stora eventmängder är normalt. En enda användare som når en filresurs genererar flera events, och med hundratals användare blir det snabbt tusentals.

Ungefärliga siffror för en miljö med 500 användare:

| Event | Typisk daglig volym |
|---|---|
| 4769 (TGS-förfrågningar) | 50 000 till 100 000+ |
| 4768 (TGT-förfrågningar) | 5 000 till 10 000+ |
| 4624 (inloggningar) | Varierar kraftigt beroende på serverroll |

### Datorkonton (`$`)

Datorkonton i AD slutar på `$` (till exempel `THM-DC$`, `THM-IT-DESK$`). De autentiserar hela tiden för maskin-till-maskin-kommunikation, uppdateringar och automatiska processer, och kan stå för 70-80 % av all Kerberos-trafik i en upptagen miljö. Filtrera bort dem när du undersöker mänsklig aktivitet.

### Jämför datorkonton mot användarkonton

Räknar autentiseringsevents per kontotyp och EventCode. I rummets exempel hade datorkonton 1500+ lyckade inloggningar mot 350+ för användarkonton, så filtreringen gör stor skillnad.

```splunk
index=* EventCode IN (4624, 4768, 4769)
| eval AccountType=if(like(Account_Name, "%$%"), "Computer Account", "User Account")
| stats count by AccountType, EventCode
| sort AccountType, -count
```

### Vanliga Service_Name-mönster (Event 4769)

`Service_Name` visar vilken resurs som nåddes. Ett servicenamn som inte passar mönstren nedan är värt att undersöka.

| Service_Name | Vad det representerar |
|---|---|
| `krbtgt` | Förnyelse av TGT |
| `cifs/THM-SHR-SRV` | Åtkomst till filresurs |
| `ldap/THM-DC` | Katalogfrågor |
| `http/THM-WEB-SRV` | Åtkomst till webbapplikation |
| `MSSQLSvc/THM-SQL-SRV` | Åtkomst till SQL Server |
| `HOST/THM-IT-DESK` | Allmänna värdtjänster |

### Mönster för servicekonton

Servicekonton är förutsägbara: samma källor, samma mål, samma tider.

| Kontotyp | Förväntat mönster |
|---|---|
| SQL-servicekonton | Når databasservrar från applikationsservrar |
| Backup-servicekonton | Når filresurser från backupservrar, oftast nattetid |
| Övervakningskonton | Frågar flera system med jämna intervall |
| Admin-konton | Når system från utsedda admin-arbetsstationer under kontorstid |

### Tidsbaserade mönster

Fråga alltid om tidpunkten är rimlig för kontot och dess syfte.

| Aktivitet | Förväntad tid |
|---|---|
| Användarinloggningar | Kontorstid (08-18) |
| Backupkonton | Natt (00-04) |
| Batchjobbskonton | Schemalagda fönster |
| Admin-användning | Underhållsfönster |

## Stack counting (long-tail analysis)

Räkna hur många gånger varje värde förekommer, sortera efter frekvens och fokusera på de sällsynta värdena längst ner i listan. Toppen visar baseline, botten visar var avvikelser brukar gömma sig.

### Stack counting på Account_Name

Filtrerar bort datorkonton och räknar 4769-events per användarkonto. Ett konto som bara begärt en eller två servicebiljetter sticker ut just för att det är sällsynt.

```splunk
index=* EventCode=4769 NOT Account_Name="*$*"
| stats count by Account_Name
| sort -count
```

För att se de sällsynta värdena först, sortera stigande:

```splunk
index=* EventCode=4769 NOT Account_Name="*$*"
| stats count by Account_Name
| sort count
```

### Samma teknik på andra fält

Tekniken fungerar på vilket fält som helst i vilken eventtyp som helst:

| Räkna per | Hittar |
|---|---|
| `Account_Name` | Ovanliga användarkonton |
| `Client_Address` | Ovanliga käll-IP:n |
| `Service_Name` | Ovanliga tjänster som nås |
| `Ticket_Encryption_Type` | Ovanliga krypteringsmetoder |

## Viktiga lärdomar

- Hög volym är normalt, anomalier hittar man genom att jämföra mot en baseline.
- Filtrera bort datorkonton (`$`) för att fokusera på mänskligt beteende.
- Stack counting: sortera efter frekvens och granska botten av listan.
- Kontrollera alltid tidpunkt och kontotyp mot förväntat mönster.
