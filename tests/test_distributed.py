import json, os, subprocess, sys, time, socket
from concurrent.futures import ThreadPoolExecutor
import pytest, httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from keys import KeyManager, KeyUnavailable, b64, public
from state import LocalState, PostgresState
from compatibility import verify_legacy_event

def keyring(path,kid="key-1"):
    key=Ed25519PrivateKey.generate();jwk=public(kid,key.public_key().public_bytes_raw());jwk["d"]=b64(key.private_bytes_raw())
    path.write_text(json.dumps({"active_kid":kid,"keys":[jwk]}));path.chmod(0o600)
    return key,jwk

def test_rotation_keeps_history_and_rejects_reused_kid(tmp_path,monkeypatch):
    path=tmp_path/"keys.json";keyring(path);monkeypatch.setenv("JEP_KEYRING_FILE",str(path));state=LocalState(tmp_path/"state");manager=KeyManager(state)
    assert manager.snapshot()[0]=="key-1"
    keyring(path,"key-2");assert manager.snapshot()[0]=="key-2"
    assert set(state.public_keys())=={"key-1","key-2"}
    keyring(path,"key-1")
    with pytest.raises(KeyUnavailable):manager.snapshot()

def test_missing_provider_never_falls_back(tmp_path,monkeypatch):
    path=tmp_path/"keys.json";keyring(path);monkeypatch.setenv("JEP_KEYRING_FILE",str(path));manager=KeyManager(LocalState(tmp_path/"state"));path.unlink()
    with pytest.raises(KeyUnavailable):manager.snapshot()

def test_explicit_legacy_integrity(tmp_path):
    key,k=keyring(tmp_path/"keys.json")
    event={"jep":"1","verb":"J","who":"a","when":1,"what":{"number":1e-7},"nonce":"4d0e9f80-3333-4abc-9def-123456789abc"}
    canon=lambda value:json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    header=b64(canon({"alg":"Ed25519","kid":"key-1"}));event["sig"]=header+".."+b64(key.sign((header+"."+b64(canon(event))).encode()))
    keys={"key-1":public("key-1",key.public_key().public_bytes_raw())}
    result=verify_legacy_event(event,"hf-space-v06",keys)
    assert result["valid"] and result["level"]==0 and result["profile"]=="legacy-hf-space-v06"
    assert not verify_legacy_event(event,"hf-space-v06",{})["valid"]
    event["ref"]=None;assert not verify_legacy_event(event,"hf-space-v06",keys)["valid"]

def test_vault_pins_version_and_verifies_signature(tmp_path,monkeypatch):
    import keys as module,base64
    key=Ed25519PrivateKey.generate();token=tmp_path/"token";token.write_text("test-token")
    for name,value in {"JEP_VAULT_ADDR":"https://vault.test","JEP_VAULT_TOKEN_FILE":str(token),"JEP_VAULT_KEY":"jep","JEP_VAULT_KID_PREFIX":"jep"}.items():monkeypatch.setenv(name,value)
    calls=[]
    def handle(request):
        if request.method=="GET":return httpx.Response(200,json={"data":{"type":"ed25519","derived":False,"latest_version":2,"keys":{"2":{"public_key":base64.b64encode(key.public_key().public_bytes_raw()).decode()}}}})
        data=json.loads(request.content);calls.append(data)
        return httpx.Response(200,json={"data":{"signature":"vault:v2:"+base64.b64encode(key.sign(base64.b64decode(data["input"]))).decode()}})
    client=httpx.Client;monkeypatch.setattr(module.httpx,"Client",lambda **kw:client(transport=httpx.MockTransport(handle),**kw))
    manager=KeyManager(LocalState(tmp_path/"state"));kid,sign=manager.snapshot();signature=sign(b"payload");key.public_key().verify(signature,b"payload")
    assert kid=="jep:v2" and calls[0]["key_version"]==2 and calls[0]["prehashed"] is False

@pytest.mark.skipif(not os.environ.get("JEP_TEST_DATABASE_URL"),reason="CI supplies real PostgreSQL")
def test_postgres_independent_apis(tmp_path):
    dsn=os.environ["JEP_TEST_DATABASE_URL"];state=PostgresState(dsn)
    with state.connect() as db:db.execute("TRUNCATE jep_nonces,jep_events,jep_public_keys")
    paths=[tmp_path/"one.json",tmp_path/"two.json"];keyring(paths[0]);paths[1].write_text(paths[0].read_text());paths[1].chmod(0o600)
    token=tmp_path/"auth";token.write_text("test-only-bearer");procs=[];urls=[];logs=[]
    try:
        for i,path in enumerate(paths):
            with socket.socket() as sock:sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
            env={**os.environ,"JEP_DATABASE_URL":dsn,"JEP_KEYRING_FILE":str(path),"JEP_DEPLOYMENT_MODE":"production","JEP_SIGNING_TOKEN_FILE":str(token),"JEP_STATE_DIR":str(tmp_path/f"unused-{i}")}
            log=open(tmp_path/f"api-{i}.log","w");logs.append(log)
            p=subprocess.Popen([sys.executable,"-m","uvicorn","main:app","--host","127.0.0.1","--port",str(port)],env=env,stdout=log,stderr=log);procs.append(p);url=f"http://127.0.0.1:{port}";urls.append(url)
            for _ in range(100):
                try:
                    if httpx.get(url+"/health").status_code==200:break
                except httpx.TransportError:pass
                time.sleep(.1)
            else:raise AssertionError((tmp_path/f"api-{i}.log").read_text())
        with httpx.Client(timeout=15) as client:
            request={"verb":"J","who":"a","what":{"claim":"test"},"aud":"test"};headers={"Authorization":"Bearer test-only-bearer"}
            assert client.post(urls[0]+"/events/create",json=request).status_code==401
            created=client.post(urls[0]+"/events/create",json=request,headers=headers);assert created.status_code==200,created.text;event=created.json()["event"]
            def consume(i):return client.post(urls[i%2]+"/events/verify",json={"event":event,"mode":"acceptance","expected_audience":"test"}).json()
            with ThreadPoolExecutor(8) as pool:results=list(pool.map(consume,range(16)))
            assert sum(r["valid"] for r in results)==1,results
            keyring(paths[0],"key-2");paths[1].write_text(paths[0].read_text());paths[1].chmod(0o600)
            new=client.post(urls[0]+"/events/create",json=request,headers=headers);assert new.status_code==200,new.text
            for url in urls:
                assert client.post(url+"/events/verify",json={"event":event}).json()["valid"]
                assert client.post(url+"/events/verify",json={"event":new.json()["event"]}).json()["valid"]
        with state.connect() as db:
            assert db.execute("SELECT count(*) FROM jep_events").fetchone()[0]==2
            assert db.execute("SELECT count(*) FROM jep_public_keys").fetchone()[0]==2
    finally:
        for p in procs:p.terminate()
        for p in procs:p.wait(timeout=10)
        for log in logs:log.close()

def test_metadata_observes_rotation_in_one_request(tmp_path,monkeypatch):
    import main
    path=tmp_path/"keys.json";keyring(path);monkeypatch.setenv("JEP_KEYRING_FILE",str(path))
    state=LocalState(tmp_path/"state");manager=KeyManager(state)
    monkeypatch.setattr(main,"STATE",state);monkeypatch.setattr(main,"KEYS",manager)
    keyring(path,"key-2")
    assert main.root()["public_key"]["kid"]=="key-2"
