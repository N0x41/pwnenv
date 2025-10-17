---
## `DOC.md`

Ce fichier contient la documentation technique qui détaille le fonctionnement interne de l'outil.

```markdown
# Documentation Technique de PwnEnv

Ce document détaille l'architecture et le fonctionnement interne de l'outil `pwnenv`.

## 1. Architecture Générale

PwnEnv repose sur un modèle hybride qui sépare la gestion de l'environnement de la génération des fichiers :

* **Un script Bash (`pwnenv`)** agit comme un "chef d'orchestre". Il gère l'environnement du terminal de l'utilisateur (activation du `venv`, changement de répertoire), l'analyse des arguments en ligne de commande, et la collecte des informations de déploiement. C'est le point d'entrée unique et la face visible de l'outil.

* **Des scripts Python (dans le dossier `tools/`)** agissent comme des "artisans" : `init_challenge.py` et `pwnlib_api.py`. Ils sont copiés par `pwnenv` dans `~/challenges/.pwnenv/tools` lors de la première exécution. Si le dossier `tools/` est indisponible, `pwnenv` dispose d'un fallback via heredocs pour les générer.

Le flux d'exécution typique est le suivant :
`Utilisateur -> pwnenv (Bash) -> init_challenge.py (Python) -> Fichiers du Projet (.json, exploit.py)`

---
## 2. Le Script `pwnenv` (Bash)

### Auto-Installation (`self_setup`)
À sa toute première exécution, le script détecte l'absence de l'environnement global (`~/challenges/.pwnvenv`). Il exécute alors une routine d'auto-configuration unique :
1.  Il crée la structure de dossiers `~/challenges/.pwnvenv/tools`.
2.  Il copie les scripts Python (`pwnlib_api.py`, `init_challenge.py`) depuis le dossier `tools/` du dépôt (ou `PWNENV_TOOLS_PATH` si défini) vers `~/challenges/.pwnenv/tools`. Si indisponibles, il les génère via des heredocs embarqués.
3.  Il crée l'environnement virtuel (`venv`) et y installe `pwntools`.
4.  L'environnement d'exécution des exploits présuppose la présence de `tmux` pour permettre le split automatique du terminal lors de l'utilisation de GDB/Pwndbg.
L'outil est donc entièrement autonome après sa création initiale.

### Commande `init`
C'est la commande la plus complexe. Sa logique est la suivante :
1.  **Analyse des Arguments** : Une boucle `while` analyse les arguments pour identifier la source du binaire (`--local`, `--ssh`), les options de connexion (`--ssh-*`) et la libc à utiliser (`--libc`).
2.  **Collecte SSH** : Lorsqu'une cible distante est fournie, le script déduit l'utilisateur, l'hôte et le chemin du binaire, puis demande un mot de passe interactif si nécessaire (lecture silencieuse via `read -s`). Aucun transfert de fichier n'est effectué à cette étape.
3.  **Définition de la libc** : Si `--libc` pointe vers un fichier local, le chemin est mémorisé pour copie ultérieure. Sinon la valeur est prise telle quelle (version glibc, URL, etc.) et transmise au script Python.
4.  **Appel du Script Python** : Il exécute `init_challenge.py`, en lui passant le chemin du projet et les options collectées. Les arguments `--ssh-*` sont sérialisés dans un objet `ssh` unique transmis à Python, et `--libc` est envoyé tel quel.
5.  **Gestion de l'Environnement** : Après une création de projet réussie, il se déplace dans le nouveau dossier et exécute `exec "$SHELL"`. Cette commande remplace le processus shell actuel par un nouveau, ce qui permet à l'utilisateur de rester dans le nouveau répertoire avec l'environnement virtuel activé.

### Commande `go`
Une commande simple qui se déplace dans un dossier de projet existant et exécute la même logique d'activation d'environnement que `init`.

---
## 3. Les Scripts Python Déployés

### `init_challenge.py`
Ce script est le générateur de projet.
1.  Il reçoit les informations de `pwnenv` via `argparse`.
2.  Il crée la structure de dossiers `bin`/`src` et prépare `lib/` si une libc locale est fournie.
3.  Il copie le binaire depuis son emplacement d'origine vers le dossier `bin` final.
4.  Il gère l'option `--libc` : copie le fichier dans `lib/` ou enregistre la version demandée.
5.  Il génère le fichier de configuration `pwnenv.conf.json`.
6.  Il génère le script `exploit.py` à partir d'un template interne, en y injectant les informations pertinentes.

### `pwnlib_api.py`
C'est la librairie partagée par tous les projets. Elle est importée dynamiquement grâce au `PYTHONPATH` modifié par `pwnenv`.
* **Classe `Pipeline`** : Le cœur de la librairie.
* **`__init__`** : À l'initialisation, la classe cherche et charge le fichier `pwnenv.conf.json` du projet courant. Elle configure le contexte `pwntools` et définit le chemin du binaire local à partir de la configuration.
  * `context.terminal = ['tmux', 'splitw', '-v']` est défini afin d'ouvrir automatiquement un split vertical dans `tmux` pour GDB/Pwndbg. Cela fonctionne également si votre émulateur (ex: Terminator) est utilisé, tant que `tmux` est installé et accessible depuis le PATH.
* **`connect`** : Cette méthode utilise la configuration chargée pour se connecter. Si `mode='REMOTE'`, elle consomme l'objet `ssh` de `pwnenv.conf.json` pour établir une connexion `pwnlib.ssh` et lancer le processus distant.
* **`@step` et `run`** : Implémentent un système de pipeline simple et déclaratif pour structurer le code de l'exploit.

---
## 4. Le Flux de Données (`pwnenv.conf.json`)

Ce fichier JSON est la "colle" qui lie la configuration du projet à l'exécution de l'exploit.

* **Création** : Il est généré par `init_challenge.py` lors de l'initialisation avec les informations fournies à `pwnenv`.
* **Lecture** : Il est lu par `pwnlib_api.py` chaque fois qu'un script d'exploit est lancé.

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