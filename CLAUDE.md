# CLAUDE.md – Instruktioner för Claude Code i detta repo

## Om projektet
Detta är ett **publikt** repo med mina anteckningar från egenstudier inom cybersäkerhet
(bug bounty / offensivt och blue team / SOC / defensivt). Huvudfilen är en levande
referensbank: `cybersakerhet-referens.md`.

## Språk
Skriv allt innehåll och alla förklaringar på **svenska**.

## ELIF-konventionen
När jag avslutar en fråga med **"ELIF"**, strukturera svaret så här:
1. **ELI5** – förklara som för ett barn, med en enkel analogi.
2. **Teknisk fördjupning** – hur det faktiskt fungerar i grunden.
3. **Verkliga exempel** – kopplat till sådant jag känner igen (webb, verktyg, protokoll).

## Var innehåll ska läggas i `cybersakerhet-referens.md`
- **Ett nytt begrepp/koncept** → lägg i avsnittet **"Begreppsordlista (ELIF)"**.
- **Ett kommando eller verktyg** → rätt underrubrik i **"Rekognosering"** eller **"Verktyg"**,
  med formatet: Vad / När / kodblock / förklarade flaggor / Källa.
- **En sårbarhetstyp** → avsnittet **"Webbsårbarheter"**.
- **Blue team / SOC** eller **nätverk/protokoll** → respektive avsnitt.
- Om inget avsnitt passar: skapa ett nytt under rätt huvudrubrik och lägg till det i
  innehållsförteckningen.
- Uppdatera **"Senast uppdaterad"** och lägg en rad i **"Ändringslogg"** vid varje ändring.

## Källor
Inkludera alltid en **källa med länk** när informationen bygger på något specifikt
(officiell dokumentation, OWASP, PortSwigger, etc.).

## Säkerhet / integritet (VIKTIGT)
Detta repo är publikt. Lägg **aldrig** in:
- Mitt Intigriti-användarnamn, e-postalias eller andra personliga identifierare
- Program-specifik scope, custom headers eller credentials
- Riktiga PoC:er mot namngivna mål

Håll allt innehåll **generellt** – kommandon, koncept och metodik som vem som helst kan lära av.

## Arbetsflöde (git)
Efter att du lagt till eller uppdaterat innehåll:
1. `git add` de ändrade filerna.
2. `git commit` med ett beskrivande meddelande på svenska
   (t.ex. `Lägg till förklaring av TLS-handskakning i ordlistan`).
3. `git push`.

Committa gärna varje avslutat tillägg för sig, så ändringsloggen blir tydlig.
