# Sensitive Information Disclosure

Källa: [TryHackMe: Sensitive Information Disclosure](https://tryhackme.com/room/sensitiveinformationdisclosure)

## Vektorsökning och RAG

### Cosine similarity

Mäter hur nära två vektorer ligger varandra, vilket är det RAG-system rankar dokument efter. Högst poäng hämtas, oavsett om dokumentet är behörigt eller inte.

```python
import numpy as np   # numpy används för vektorberäkningar

# Funktion som räknar ut likheten mellan två vektorer (1.0 = identiska riktningar)
def cosine(a, b):
    # np.dot(a, b): skalärprodukten, hur mycket vektorerna pekar åt samma håll
    # np.linalg.norm(...): vektorns längd, används för att normalisera poängen
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))

# Användarens fråga omvandlad till en embedding (en vektor)
query = np.array([0.8, 0.1])

# Två dokument som embeddings, där det andra är konfidentiellt
doc_safe = np.array([0.7, 0.2])
doc_confidential = np.array([0.79, 0.11])

# Jämför frågan mot varje dokument, högre poäng = högre rankning
cosine(query, doc_safe)            # 0.98
cosine(query, doc_confidential)    # 0.999, konfidentiella dokumentet rankas högst
```

### Retrieval med metadatafilter

Filtrerar bort obehöriga och raderade dokument innan likhetssökningen. Utan filter hamnar konfidentiella och inaktuella dokument i top-k, och högre `top_k` ökar exponeringen.

```python
# Hämtar de top_k mest lika dokumenten. apply_filter styr om behörighet kontrolleras
# (documents och query_embedding är definierade tidigare i rummet)
def retrieve(top_k=2, apply_filter=False):
    scored = []                                   # lista för (poäng, dokument)
    for doc in documents:                         # går igenom alla lagrade dokument
        if apply_filter:
            # Hoppa över dokument som inte är publika (behörighetskontroll)
            if doc["metadata"].get("access") != "public":
                continue
            # Hoppa över dokument som är raderade i källsystemet (stale embeddings)
            if doc["metadata"].get("deleted"):
                continue
        # Räknar likheten mellan frågan och dokumentets embedding
        score = cosine(query_embedding, doc["embedding"])
        scored.append((score, doc))
    # Sorterar med högst poäng först
    scored.sort(reverse=True, key=lambda x: x[0])
    # Returnerar bara de top_k bästa, det är dessa som hamnar i modellens prompt
    return scored[:top_k]

# apply_filter=False, top_k=2: public_policy + confidential_payroll
# apply_filter=False, top_k=3: dessutom deleted_old_policy
# apply_filter=True:           bara public_policy
```
