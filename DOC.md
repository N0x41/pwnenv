---
## `DOC.md`

---
## 5. Notes sur les tests (réalité contrôlée)

Ces tests complètent la couverture de `pwnapi.py` en exécutant des chemins proches de la réalité, mais de manière sûre et hermétique.

- Binaire factice local ("dummy")
  - Certains tests compilent au vol un petit programme C minimal avec `gcc` dans un dossier temporaire (`tmp_path`).
  - Ce binaire est utilisé pour valider les modes `LOCAL` (via `process(...)`) et `DEBUG` (via `gdb.debug(...)` stubé) sans dépendances externes.
  - Si `gcc` n'est pas disponible dans l'environnement CI/local, les tests concernés sont marqués `skip` automatiquement.

- GDB/Pwndbg par défaut
  - En mode `DEBUG` sans `gdbscript` fourni, `pwnapi` insère par défaut `source /usr/share/pwndbg/gdbinit.py` suivi d'un `continue`.
  - Lorsqu'un `breakpoint` est passé à `connect(...)`, il est converti en `break *0x...` pour un entier, ou `break <symbole>` pour une chaîne, puis ajouté au script.

- SSH localhost (optionnel)
  - Un test tente d'exécuter le binaire via SSH sur `localhost` pour couvrir le chemin `REMOTE` réel.
  - Ce test est conditionné par une connexion SSH sans mot de passe (BatchMode) disponible ; sinon, il est marqué `skip`.
  - Aucun état persistant n'est modifié et les sessions sont fermées proprement en `finally`.

Ce fichier contient la documentation technique qui détaille le fonctionnement interne de l'outil.

# Documentation Technique de PwnEnv

Ce document détaille l'architecture et le fonctionnement interne de l'outil `pwnenv`.

## 1. Architecture Générale

PwnEnv repose désormais sur un unique script Python qui orchestre l'ensemble de la chaîne :

* **`pwnenv` (Python)** gère la configuration de l'environnement utilisateur (création/activation du `venv`, changement de répertoire), l'analyse des arguments en ligne de commande et la génération des projets. C'est le point d'entrée unique et la face visible de l'outil.

* **Les ressources partagées (dossier `tools/`)** regroupent `pwnapi.py`, le template `pwnenv.mako`, la configuration tmux et les scripts auxiliaires. Elles sont copiées par `pwnenv` dans `~/challenges/.pwnenv/tools` lors de la première exécution afin d'être accessibles aux exploits.

Le flux d'exécution typique est le suivant :
`Utilisateur -> pwnenv (Python) -> Fichiers du Projet (.json, exploit.py)`

---
## 2. Le Script `pwnenv` (Python)

### Auto-Installation (`self_setup`)
À sa toute première exécution, le script détecte l'absence de l'environnement global (`~/challenges/.pwnenv`). Il exécute alors une routine d'auto-configuration unique :
1.  Il crée la structure de dossiers `~/challenges/.pwnenv/tools`.
2.  Il copie les ressources partagées (`pwnapi.py`, `pwnenv.mako`, `tmux.config`, scripts `tmux-sidebar/`) depuis le dossier `tools/` du dépôt (ou `PWNENV_TOOLS_PATH` si défini) vers `~/challenges/.pwnenv/tools`.
3.  Il crée l'environnement virtuel (`venv`) et y installe `pwntools`.
4.  L'environnement d'exécution présuppose la présence de `tmux` : `pwnenv` configure un layout par défaut et prépare l'ouverture d'une session dédiée pour chaque projet.
L'outil est donc entièrement autonome après sa création initiale.

### Commande `init`
C'est la commande la plus complète. Sa logique est la suivante :
1.  **Analyse des Arguments (argparse)** : `pwnenv` collecte les sources (`--local`, `--ssh`, `--source-path`), les options de connexion (`--ssh-*`) et la libc (`--libc`).
2.  **Préparation et validations** : les chemins fournis sont résolus (`expanduser`), la présence des fichiers nécessaires est vérifiée avant toute création, et un mot de passe SSH est demandé si besoin.
3.  **Création du projet** : `pwnenv` crée directement la structure (`src/`, `bin/`, `lib/`), copie le binaire local si fourni, et enregistre la configuration SSH/libc dans `pwnenv.conf.json`.
4.  **Gestion des sources** : un dossier ou fichier fourni via `--source-path`/argument positionnel est recopié dans `src/`.
5.  **Génération d'exploit** : le script exécute `pwn template` avec le template `pwnenv.mako` (copié dans l'environnement global) et produit `exploit.py`. En cas d'échec, un fallback minimal est écrit.
6.  **Gestion de l'Environnement** : après la création, `pwnenv` bascule dans le nouveau dossier et lance une session `tmux` dédiée avec le `venv` actif et `PYTHONPATH` configuré.

### Commande `go`
Une commande simple qui se déplace dans un dossier de projet existant et exécute la même logique d'activation d'environnement que `init`.

---
## 3. Les Scripts Python Déployés

### `pwnapi.py`
C'est la librairie partagée par tous les projets. Elle est importée dynamiquement grâce au `PYTHONPATH` modifié par `pwnenv`.
* **Classe `Pipeline`** : Le cœur de la librairie.
* **`__init__`** : À l'initialisation, la classe cherche et charge le fichier `pwnenv.conf.json` du projet courant. Elle configure le contexte `pwntools` et définit le chemin du binaire local à partir de la configuration.
  * `context.terminal = ['tmux', 'splitw', '-v']` est défini afin d'ouvrir automatiquement un split vertical dans `tmux` pour GDB/Pwndbg. Cela fonctionne également si votre émulateur (ex: Terminator) est utilisé, tant que `tmux` est installé et accessible depuis le PATH.
* **`connect`** : Cette méthode utilise la configuration chargée pour se connecter. Si `mode='REMOTE'`, elle consomme l'objet `ssh` de `pwnenv.conf.json` pour établir une connexion `pwnlib.ssh` et lancer le processus distant. Les modes `DEBUG`/`GDB` sont supportés en local et via SSH avec un `gdbscript` optionnel.
* **`print_summary`** : Fournit un aperçu rapide des chemins locaux/distant, du port et de la libc détectée.
* **`@step` et `run`** : Implémentent un système de pipeline simple et déclaratif pour structurer le code de l'exploit. `run()` accepte `mode`, `breakpoint` et `gdbscript` pour piloter l'exécution.

---
## 4. Le Flux de Données (`pwnenv.conf.json`)

Ce fichier JSON est la "colle" qui lie la configuration du projet à l'exécution de l'exploit.

* **Création** : Il est généré directement par `pwnenv init` lors de l'initialisation avec les informations fournies.
* **Lecture** : Il est lu par `pwnapi.py` chaque fois qu'un script d'exploit est lancé.

Cela permet de dissocier la configuration (qui ne se fait qu'une fois) de l'exécution (qui peut être répétée en mode `LOCAL`, `DEBUG`, ou `REMOTE` sans changer les arguments).

**Exemple de structure :**
```json
{
    "binary_path_local": "./bin/my_binary",
    "ssh": {
    "host": "pwn.challenge.com",
    "user": "user",
    "pass": "password123",
    "port": 2222,
    "bin": "/path/on/server/my_binary"
  }
}