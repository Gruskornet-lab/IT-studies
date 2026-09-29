# Securing the AI Supply Chain

Källa: [TryHackMe: Securing the AI Supply Chain](https://tryhackme.com/room/securing-the-ai-supplychain)

## Verifiering

### SHA-256-checksum

Beräknar filens hash så att den kan jämföras med författarens publicerade värde. Ändras en enda byte blir hashen helt annorlunda, så det avslöjar manipulerade modeller.

```bash
sha256sum model.pkl model.safetensors
```

## Säker inläsning

### PyTorch: läs in modell säkert

Begränsar pickle så att bara tensorer kan återskapas och kodexekvering blockeras. Standard från PyTorch 2.6, äldre versioner måste ange det explicit.

```python
torch.load("model.pt", weights_only=True)
```

### Konvertera pickle till SafeTensors

SafeTensors kan inte innehålla körbar kod. Konverteringen läser in pickle-filen, så använd `weights_only=True` även här.

```python
from safetensors.torch import save_file, load_file

weights = torch.load("model.pkl", weights_only=True)
save_file(weights, "model.safetensors")
safe = load_file("model.safetensors")
```

## Skanning av modeller

### Fickling

Dekompilerar pickle-bytecode till läsbar Python utan att köra filen, så man ser exakt vad en skadlig modell gör.

```bash
fickling model.pkl                      # visa dekompilerad kod
fickling --check-safety -p model.pkl    # säkerhetsbedömning i terminalen (utan -p sparas den i safety_results.json)
```

### ModelScan

Skannar pickle, PyTorch, TensorFlow och Keras och ger allvarlighetsgrad (LOW till CRITICAL). CRITICAL betyder karantän, MEDIUM betyder granska manuellt.

```bash
modelscan -p model.pkl
```

### Inspektera Keras-modell (Lambda-lager)

Listar lagren i en `.h5`-modell utan att ladda den. Lager markerade `[WARNING]` (till exempel Lambda) bör undersökas.

```bash
python3 /opt/supply-chain/tools/inspect_h5_model.py model.h5
```

## Beroenden och SBOM

### pip-audit

Kontrollerar beroenden mot kända sårbarheter och visar fixad version för varje.

```bash
pip-audit -r requirements.txt
```

### Lockfile med hashar

Låser exakt version och hash för varje paket, så utbytta paket blockeras vid installation.

```bash
pip-compile --generate-hashes    # pip-tools
poetry lock                      # Poetry
```

### Privat paketindex

Löser interna paketnamn mot privat index först och skyddar mot dependency confusion. `extra-index-url` används bara som fallback.

```ini
# ~/.pip/pip.conf
[global]
index-url = https://your-private-pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/
```

### Syft: generera SBOM

Skapar en materiallista över alla paket i ett projekt, användbar för att snabbt se om man påverkas av en ny sårbarhet.

```bash
syft <mapp> --exclude './venv/**' -o cyclonedx-json > sbom.json   # CycloneDX JSON till fil
syft <mapp> --exclude './venv/**' -o table                        # läsbar tabell
cat sbom.json | python3 -m json.tool | less                       # bläddra i JSON
```
