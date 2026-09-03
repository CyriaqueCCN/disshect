#!/bin/bash
# Les gardes propres a ce depot, appelees par le job `cco custom
# controls` de la chaine `garde`.
#
# POURQUOI CE FICHIER EXISTE PLUTOT QU'UN NOM EN DUR DANS LE WORKFLOW.
#
# `garde.yml` est identique a l'OCTET dans tous les depots. Il ne peut
# donc pas connaitre le nom du harnais de celui-ci. Il cherche un chemin
# FIXE - ce fichier - et le depot y appelle ce qu'il veut. La convention
# est calculee, il n'y a aucune valeur a tenir a jour ailleurs.
set -euo pipefail

echo "disshect : harnais de parsing, 25 controles"
python3 checks/verifie.py
