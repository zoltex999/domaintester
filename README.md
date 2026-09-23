![Banner](banner.gi)
# Domain Tester
### Vérifier la disponibilité des domaines de premier niveau

## Fonctionnement

4 vérifications
1. Résolution DNS + connectivité
2. RDAP officiel
3. WHOIS
4. RDAP fallback

## Fonctionnalités
- Vérification en masse sur 582 TLD disponibles
- Multi-thread
- Sauvegarde des résultats en `.txt`
- Compatible Windows 

## Installation

```bash
git clone https://github.com/zoltex999/domaintester
cd domain-tester
python main.py
```

## Utilisation

```
1. Global TLD check   → teste un SLD sur tous les TLDs de la liste
2. Single domain check → teste un domaine complet
3. Exit
```

