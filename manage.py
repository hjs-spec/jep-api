"""Offline state migration and key provisioning. Never prints secret material."""
import argparse, json, os, sqlite3
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from keys import public, b64
from state import PostgresState

def write_private(path, value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w") as f:
        json.dump(value,f);f.flush();os.fsync(f.fileno())

def export_key(directory,output,kid):
    # Opening a missing state must never manufacture a replacement historical key.
    path=Path(directory)/"state.sqlite3"
    with sqlite3.connect(f"file:{path.resolve()}?mode=ro",uri=True) as db:
        row=db.execute("SELECT seed FROM signing_keys WHERE id='default'").fetchone()
    if row is None:raise ValueError("Historical signing key unavailable")
    key=Ed25519PrivateKey.from_private_bytes(row[0]);jwk=public(kid,key.public_key().public_bytes_raw());jwk["d"]=b64(row[0])
    write_private(output,{"active_kid":kid,"keys":[jwk]})

def migrate(directory,dsn):
    source=Path(directory)/"state.sqlite3"
    dest=PostgresState(dsn)
    with sqlite3.connect(f"file:{source.resolve()}?mode=ro",uri=True) as old, dest.connect() as db:
        old.execute("BEGIN")
        # Requires writers to be stopped; copy a consistent snapshot, merge replay expiries conservatively.
        tables={r[0] for r in old.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for actor,audience,nonce,expires in old.execute("SELECT actor,audience,nonce,expires FROM nonces"):
            db.execute("INSERT INTO jep_nonces VALUES (%s,%s,%s,%s) ON CONFLICT(actor,audience,nonce) DO UPDATE SET expires=GREATEST(jep_nonces.expires,EXCLUDED.expires)",(actor,audience,nonce,expires))
        for h,payload in old.execute("SELECT hash,payload FROM events"):
            db.execute("INSERT INTO jep_events VALUES (%s,%s::jsonb) ON CONFLICT DO NOTHING",(h,payload))
        if "created_requests" in tables:
            for key,digest,response in old.execute("SELECT request_key,request_digest,response FROM created_requests"):
                db.execute(
                    "INSERT INTO jep_created_requests VALUES (%s,%s,%s::jsonb) ON CONFLICT(request_key) DO NOTHING",
                    (key,digest,response),
                )
                existing=db.execute(
                    "SELECT request_digest,response FROM jep_created_requests WHERE request_key=%s",(key,)
                ).fetchone()
                if existing is None or existing[0]!=digest or existing[1]!=json.loads(response):
                    raise ValueError("Creation response conflict; migration rolled back")
        if "accepted_events" in tables:
            for actor,event_id,digest,event_hash,accepted_at in old.execute(
                "SELECT actor,event_id,payload_digest,event_hash,accepted_at FROM accepted_events"
            ):
                db.execute(
                    """INSERT INTO jep_accepted_events
                       (actor,event_id,payload_digest,event_hash,accepted_at)
                       VALUES (%s,%s,%s,%s,%s)
                       ON CONFLICT(actor,event_id) DO NOTHING""",
                    (actor,event_id,digest,event_hash,accepted_at),
                )
                existing=db.execute(
                    "SELECT payload_digest FROM jep_accepted_events WHERE actor=%s AND event_id=%s",
                    (actor,event_id),
                ).fetchone()
                # An identity already accepted with different content cannot be
                # reconciled by choosing a database. Roll back the whole import.
                if existing is None or existing[0]!=digest:
                    raise ValueError("Accepted Event Identity conflict; migration rolled back")
        records=dict(old.execute("SELECT kid,payload FROM public_keys")) if "public_keys" in tables else {}
        row=old.execute("SELECT seed FROM signing_keys WHERE id='default'").fetchone()
        if row:
            key=Ed25519PrivateKey.from_private_bytes(row[0]);records.setdefault("did:example:jep-api#key-1",json.dumps(public("did:example:jep-api#key-1",key.public_key().public_bytes_raw())))
        for kid,payload in records.items():
            db.execute("INSERT INTO jep_public_keys VALUES (%s,%s::jsonb) ON CONFLICT DO NOTHING",(kid,payload))
            if db.execute("SELECT payload FROM jep_public_keys WHERE kid=%s",(kid,)).fetchone()[0]!=json.loads(payload):raise ValueError("Historical key ID conflict")
    return "Migration complete; private keys were not copied into PostgreSQL"

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest="command",required=True)
    e=sub.add_parser("export-key");e.add_argument("state_dir");e.add_argument("output");e.add_argument("--kid",default="did:example:jep-api#key-1")
    g=sub.add_parser("generate-key");g.add_argument("output");g.add_argument("--kid",required=True)
    m=sub.add_parser("migrate-postgres");m.add_argument("state_dir");m.add_argument("--database-url-file",required=True)
    args=p.parse_args()
    if args.command=="export-key":export_key(args.state_dir,args.output,args.kid);print("Key exported to private file")
    elif args.command=="generate-key":
        key=Ed25519PrivateKey.generate();jwk=public(args.kid,key.public_key().public_bytes_raw());jwk["d"]=b64(key.private_bytes_raw());write_private(args.output,{"active_kid":args.kid,"keys":[jwk]});print("Key created in private file")
    else:print(migrate(args.state_dir,Path(args.database_url_file).read_text().strip()))
if __name__=="__main__":main()
