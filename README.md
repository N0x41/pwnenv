# PwnEnv - Gestionnaire d'Environnement de Pwn

[![Version](https://img.shields.io/badge/version-3.2.1-blue.svg)](https://github.com/N0x41/pwnenv)
[![Python](https://img.shields.io/badge/python-3.9+-green.svg)](https://python.org)
[![codecov](https://codecov.io/gh/N0x41/pwnenv/branch/main/graph/badge.svg?token=OKZ0154KE0)](https://codecov.io/gh/N0x41/pwnenv)

[Installation](https://www.google.com/search?q=%23installation) • [Utilisation](https://www.google.com/search?q=%23utilisation) • [**Documentation Technique**](/DOC.md)

PwnEnv est un outil en ligne de commande pour initialiser et gérer rapidement des environnements de travail pour des challenges d'exploitation binaire (pwn). Il automatise la création des dossiers, la configuration d'un environnement Python global avec `pwntools`, et la génération de scripts d'exploitation templates.


-----

## Dépendances

Assurez-vous que les outils suivants sont installés sur votre système :
  * **git** (utilisé par `pwntools` pour l'installation)
  * **pwndbg** (recommandé, pour le débogage. Le chemin est configuré par défaut sur `/usr/share/pwndbg/gdbinit.py`)
  * **tmux** (utilisé pour les splits automatiques lors du DEBUG)
  * **vim** (éditeur présent par défaut dans l'environnement généré)
  * **Python 3.9+** avec le module `venv`

-----

## Installation

L'installation se fait en une seule étape.

1.  **Téléchargez et installez le script `pwnenv` :**

    ```bash
    # Copiez le contenu du script pwnenv fourni précédemment dans le fichier ci-dessous
    # (ou téléchargez-le si un lien est disponible)
    touch ~/.local/bin/pwnenv
    chmod +x ~/.local/bin/pwnenv
    # nano ~/.local/bin/pwnenv # Collez le code ici
    ```

2.  **Assurez-vous que `~/.local/bin` est dans votre PATH.**
    Si ce n'est pas le cas, ajoutez la ligne suivante à votre `~/.bashrc` ou `~/.zshrc` et rechargez votre shell :

    ```bash
    export PATH="$HOME/.local/bin:$PATH"
    ```

La première fois que vous utiliserez la commande `pwnenv init`, il configurera automatiquement un environnement Python global dans `~/challenges/.pwnvenv` et y installera `pwntools`.

### Structure des sources

```
./
├─ pwnenv                # Script CLI principal
├─ tools/
│  ├─ pwnenv.mako       # Template pwntools pour le squelette exploit.py
│  ├─ pwnapi.py         # API partagée pour les exploits et le pipeline
│  └─ tmux.config       # Layout tmux par défaut
├─ README.md
└─ DOC.md
```

Au premier lancement, `pwnenv` copie les ressources partagées (`pwnapi.py`, `pwnenv.mako`, configuration tmux, scripts auxiliaires) depuis `tools/` vers `~/challenges/.pwnenv/tools`.

-----

## Utilisation

### Initialiser un nouveau challenge (`init`)

La commande `init` crée un nouveau dossier de projet dans `~/challenges` et vous place dedans avec l'environnement activé.

**1. Avec un binaire local :**

```bash
pwnenv init MyLocalChallenge --local ~/Downloads/binary
```

**2. Avec un binaire distant (via SSH) :**

```bash
pwnenv init OverTheWire_Bandit0 --ssh bandit0@bandit.labs.overthewire.org:/bandit/bandit0
```

**3. Avec options SSH (port et mot de passe) :**

```bash
pwnenv init MyRemoteChallenge \
  --ssh user@host:/path/to/binary \
  --ssh-port 2222 \
  --ssh-pass "password123"
```

  * `--ssh` enregistre le chemin distant du binaire (aucun téléchargement n'est effectué).
  * Les autres options `--ssh-*` sont regroupées dans l'objet `ssh` du fichier `pwnenv.conf.json` et servent à l'exploit (`REMOTE`).
  * Si aucun mot de passe n'est fourni, un prompt sécurisé est affiché pendant l'initialisation.

**4. Spécifier une libc :**

```bash
pwnenv init MyLibcChallenge --local ./bin/challenge --libc ~/libs/libc-2.35.so
```

  * `--libc` accepte un chemin local (copié dans `./lib/`) ou une version glibc à télécharger.

**5. Projet vide (sans binaire) :**

```bash
pwnenv init MyEmptyProject
```

### Naviguer vers un projet (`go`)

Pour retourner rapidement dans un projet existant et activer l'environnement virtuel global :

```bash
pwnenv go MyLocalChallenge
```

-----

## Utiliser le script d'exploitation

Une fois dans un projet, le script `exploit.py` peut être lancé de trois manières différentes.

  * **Localement (sans débogueur) :**

    ```bash
    ./exploit.py LOCAL
    ```

  * **Avec GDB et Pwndbg :**

    ```bash
    # Lance GDB et s'arrête sur la fonction 'main'
    ./exploit.py DEBUG -b main
    ```

  * **À distance (si le projet a été configuré avec des informations SSH) :**

    ```bash
    ./exploit.py REMOTE
    ```