"""A fake `bw` for the tests: the vault is a JSON file, <BITWARDENCLI_APPDATA_DIR>/db.json; no real vault is ever touched.
Master password "testmaster" → session "testsession". A file <dir>/fail makes create and edit fail (a vault that refuses).
"""
import base64
import json
import os
import sys
import uuid

d = os.environ["BITWARDENCLI_APPDATA_DIR"]
db = json.load(open(os.path.join(d, "db.json")))
a = [x for x in sys.argv[1:] if x != "--nointeraction"]
inp = lambda: json.loads(base64.b64decode(sys.stdin.read()))
out = ""
if a[:2] == ["unlock", "--raw"]:
    pw = open(a[a.index("--passwordfile") + 1]).read()
    if pw != "testmaster":
        sys.exit("Invalid master password.")
    print("testsession")
    sys.exit(0)
if os.environ.get("BW_SESSION") != "testsession":
    sys.exit("You are not logged in or the vault is locked.")
if os.path.exists(os.path.join(d, "fail")) and a[0] in ("create", "edit"):
    sys.exit("Server error")
if a[0] == "lock":
    out = "Your vault is locked."
elif a[0] == "sync":
    out = "Syncing complete."
elif a[:2] == ["list", "folders"]:
    out = json.dumps([f for f in db["folders"] if len(a) < 4 or a[3] in f["name"]])
elif a[:2] == ["list", "items"]:
    out = json.dumps([i for i in db["items"] if (len(a) < 4 or i.get("folderId") == a[3]) and not i.get("deleted")])
elif a[:2] == ["get", "item"]:
    out = json.dumps(next(i for i in db["items"] if i["id"] == a[2]))
elif a[:2] == ["create", "item"]:
    i = {**inp(), "id": str(uuid.uuid4()), "revisionDate": "2026-11-21"}
    db["items"].append(i)
    out = json.dumps(i)
elif a[:2] == ["edit", "item"]:  # like Bitwarden: a changed password goes to the item's history
    i, old = inp(), next(x for x in db["items"] if x["id"] == a[2])
    if (old.get("login") or {}).get("password") != (i.get("login") or {}).get("password"):
        i["passwordHistory"] = [{"password": old["login"]["password"], "lastUsedDate": "2026-11-21T08:00:00Z"}] + (old.get("passwordHistory") or [])
        i["login"]["passwordRevisionDate"] = "2026-11-21T08:00:00Z"
    db["items"] = [i if x["id"] == a[2] else x for x in db["items"]]
    out = json.dumps(i)
elif a[:2] == ["delete", "item"]:
    for x in db["items"]:
        if x["id"] == a[2]:
            x["deleted"] = True
else:
    sys.exit("stub: unknown " + " ".join(a))
json.dump(db, open(os.path.join(d, "db.json"), "w"))
print(out)
