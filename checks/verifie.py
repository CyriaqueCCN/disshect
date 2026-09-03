#!/usr/bin/env python3
"""Run disshect against generated log samples and check what it prints.

WHY THIS FILE EXISTS.

Every case below is a defect that was measured on 2026-09-03, on this
repository, at the commit before the fix. None of them was reported by
ruff or bandit: four were crashes, and the worst one printed a WRONG IP
address without any error at all. Static analysis was green throughout.

Run it from the repository root:

    python3 checks/verifie.py

It writes its samples under a temporary directory and removes them.
"""
import os
import shutil
import subprocess
import sys
import tempfile

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DISSHECT = os.path.join(RACINE, "disshect.py")

TRADITIONNEL = [
    ("Jul 01 00:00:00 srv sshd[111]: Failed password for root from "
     "12.34.56.78 port 4242 ssh2"),
    ("Jul 01 00:00:01 srv sshd[112]: Failed password for invalid user "
     "admin from 12.34.56.78 port 4243 ssh2"),
    ("Jul 01 00:00:02 srv sshd[113]: Unable to negotiate with 98.76.54.32 "
     "port 5555: no matching key exchange method found. Their offer: "
     "diffie-hellman-group1-sha1 [preauth]"),
    ("Jul 01 00:00:03 srv sshd[114]: Disconnecting authenticating user "
     "root 11.22.33.44 port 6666: Change of username or service not "
     "allowed: (root,ssh-connection) -> (Mroot,ssh-connection) [preauth]"),
]

# Same four lines, timestamp as a single ISO 8601 token. This is what
# Debian 12, journald and RFC5424 write, and it shifted every absolute
# index by two.
ISO = [
    ligne.replace("Jul 01 00:00:0", "2026-09-03T00:00:0", 1)
         .replace("T00:00:0" + str(n) + " ",
                  "T00:00:0" + str(n) + ".123456+02:00 ", 1)
    for n, ligne in enumerate(TRADITIONNEL)
]

# One IPv6 client. sshd logs them, and the previous IP check knew only v4.
IPV6 = [("Jul 01 00:00:04 srv sshd[115]: Failed password for root from "
         "2001:db8::dead:beef port 4444 ssh2")]


def ecrire(dossier, nom, lignes, mode="w"):
    chemin = os.path.join(dossier, nom)
    with open(chemin, mode, encoding="utf-8") as f:
        f.writelines(ligne + "\n" for ligne in lignes)
    return chemin


def lancer(dossier, fichier, *extra):
    """Runs disshect and returns (return code, stdout+stderr)."""
    cmd = [sys.executable, DISSHECT, "-l", dossier, "-f", fichier, "--all",
           *extra]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=RACINE,
                       check=False)
    return r.returncode, r.stdout + r.stderr


class Bilan:
    def __init__(self):
        self.faits = 0
        self.echecs = []

    def verifie(self, nom, condition, detail=""):
        self.faits += 1
        if condition:
            print(f"  OK      {nom}")
        else:
            print(f"  ECHEC   {nom}  {detail}")
            self.echecs.append(nom)


def main():
    d = tempfile.mkdtemp(prefix="disshect-verifie-")
    b = Bilan()
    try:
        print("1. traditional syslog timestamp (the README format)")
        ecrire(d, "trad.log", TRADITIONNEL)
        rc, out = lancer(d, "trad.log")
        b.verifie("returns 0", rc == 0, f"rc={rc}")
        for ip in ("12.34.56.78", "98.76.54.32", "11.22.33.44"):
            b.verifie(f"lists {ip}", ip in out)
        b.verifie("counts the two password failures together",
                  "12.34.56.78 : 2 errors" in out)

        print("2. ISO 8601 timestamp - one token instead of three")
        ecrire(d, "iso.log", ISO)
        rc, out = lancer(d, "iso.log")
        b.verifie("returns 0", rc == 0, f"rc={rc}")
        b.verifie("reads the cipher address", "98.76.54.32" in out)
        # THE REGRESSION WITNESS. Before the fix this printed the PORT,
        # colon included, as an offending address.
        b.verifie("never prints a port as an address", "5555:" not in out,
                  out)

        print("3. IPv6 client")
        ecrire(d, "v6.log", IPV6)
        rc, out = lancer(d, "v6.log")
        b.verifie("lists the v6 address", "2001:db8::dead:beef" in out, out)
        rc, out = lancer(d, "v6.log", "-i", "2001:db8::dead:beef")
        b.verifie("-i accepts a v6 address", rc == 0, out)

        print("4. truncated line - the anchors cannot be found")
        tronquee = "Jul 01 00:00:05 srv sshd[116]: Unable to negotiate with"
        ecrire(d, "court.log", [*TRADITIONNEL, tronquee])
        rc, out = lancer(d, "court.log")
        b.verifie("does not crash", rc == 0, out)
        b.verifie("says how many lines it could not read",
                  "1 matching lines could not be read" in out, out)
        b.verifie("still counts the four sound lines", "4 errors" in out, out)

        print("5. byte that is not valid UTF-8")
        chemin = os.path.join(d, "binaire.log")
        mauvaise = (b"Jul 01 00:00:00 srv sshd[111]: Failed password for "
                    b"\xff\xfe from 12.34.56.78 port 42 ssh2\n")
        with open(chemin, "wb") as f:
            f.write(mauvaise)
            f.write((TRADITIONNEL[0] + "\n").encode())
        rc, out = lancer(d, "binaire.log")
        b.verifie("does not crash", rc == 0, out)
        b.verifie("keeps counting after the bad byte",
                  "12.34.56.78 : 2 errors" in out, out)

        print("6. blank lines")
        ecrire(d, "vide.log", ["", "   ", *TRADITIONNEL, ""])
        rc, out = lancer(d, "vide.log")
        b.verifie("does not crash", rc == 0, out)
        b.verifie("counts nothing extra", "4 errors" in out, out)

        print("7. the glob matches gzipped files only")
        gz = os.path.join(d, "gz")
        os.makedirs(gz, exist_ok=True)
        with open(os.path.join(gz, "auth.log.1.gz"), "wb") as f:
            f.write(b"\x1f\x8b\x08\x00\x00\x00\x00\x00")
        rc, out = lancer(gz, "auth.log*")
        b.verifie("refuses with a message rather than a traceback",
                  rc != 0 and "Traceback" not in out, out)
        b.verifie("names the reason", "gzipped" in out, out)

        print("8. -t with a name that does not exist")
        rc, out = lancer(d, "trad.log", "-t", "ciphers")
        b.verifie("refuses an unknown type", rc != 0, out)
        b.verifie("names it", "ciphers" in out, out)
        rc, out = lancer(d, "trad.log", "-t", "cipher")
        b.verifie("still accepts an exact name", rc == 0, out)
        b.verifie("and only that type", "12.34.56.78" not in out, out)

        print("9. active control - the harness can fail")
        # Without this, a checker whose `lancer` silently returned an
        # empty string would report nine green sections.
        rc, out = lancer(d, "trad.log")
        temoin = "CETTE-CHAINE-NE-DOIT-PAS-APPARAITRE" in out
        b.verifie("a false expectation IS reported as false",
                  temoin is False)
        b.verifie("the output is not empty", len(out) > 100, repr(out[:80]))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    print()
    ATTENDU = 25
    if b.faits != ATTENDU:
        print(f"ARRET : {b.faits} checks ran, {ATTENDU} expected. A silent "
              "section is a failure, not a success.")
        return 2
    if b.echecs:
        print(f"ARRET : {len(b.echecs)} failure(s) : {', '.join(b.echecs)}")
        return 1
    print(f"{b.faits} checks, all green.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
