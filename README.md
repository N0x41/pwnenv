# PwnEnv - Gestionnaire d'Environnement de Pwn

![Language](https://img.shields.io/badge/language-Bash%20%26%20Python-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

[Installation](#installation) • [Utilisation](#utilisation) • [**Documentation Technique (DOC.md)**](DOC.md)

PwnEnv est un outil en ligne de commande pour initialiser et gérer rapidement des environnements de travail pour des challenges d'exploitation binaire (pwn). Il automatise la création des dossiers, la configuration d'un environnement Python global avec `pwntools`, et la génération de scripts d'exploitation templates.

---
## Dépendances

Assurez-vous que les outils suivants sont installés sur votre système :
* **Python 3.x** et le module `venv`
* **git** (utilisé par `pwntools` pour l'installation)
* **sshpass** (optionnel, pour utiliser l'option `--password` avec SSH)
* **pwndbg** (recommandé, pour le débogage. Le chemin est configuré par défaut sur `/usr/share/pwndbg/gdbinit.py`)

---
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

---
## Utilisation

### Initialiser un nouveau challenge (`init`)

La commande `init` crée un nouveau dossier de projet dans `~/challenges` et vous place dedans avec l'environnement activé.

**1. Avec un binaire local :**
```bash
pwnenv init MyLocalChallenge --local ~/Downloads/binary