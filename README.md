# PwnEnv - Gestionnaire d'Environnement de Pwn

[![Version](https://img.shields.io/badge/version-3.1.1-blue.svg)](https://github.com/N0x41/pwnenv)
[![Python](https://img.shields.io/badge/python-3.9+-green.svg)](https://python.org)
[Installation](https://www.google.com/search?q=%23installation) • [Utilisation](https://www.google.com/search?q=%23utilisation) • [**Documentation Technique (DOC.md)**](https://www.google.com/search?q=DOC.md)

PwnEnv est un outil en ligne de commande pour initialiser et gérer rapidement des environnements de travail pour des challenges d'exploitation binaire (pwn). Il automatise la création des dossiers, la configuration d'un environnement Python global avec `pwntools`, et la génération de scripts d'exploitation templates.

-----

## Dépendances

Assurez-vous que les outils suivants sont installés sur votre système :

  * **Python 3.9+** et le module `venv`
  * **git** (utilisé par `pwntools` pour l'installation)
  * **sshpass** (optionnel, pour utiliser l'option `--password` avec SSH)
  * **pwndbg** (recommandé, pour le débogage. Le chemin est configuré par défaut sur `/usr/share/pwndbg/gdbinit.py`)

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
  --ssh-host user@host \
  --ssh-user user \
  --ssh-port 2222 \
  --ssh-password "password123"
```

  * `--ssh` sert à télécharger le binaire pour l'analyse locale.
  * Les autres options `--ssh-*` sont sauvegardées dans `pwnenv.conf.json` pour permettre à votre script d'exploit de se connecter au serveur distant.

**4. Projet vide (sans binaire) :**

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