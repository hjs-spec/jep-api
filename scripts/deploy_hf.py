"""Deploy the existing Space with an explicit tested revision, then verify readiness."""
import os,shutil,tempfile,time
from pathlib import Path
import httpx
from huggingface_hub import HfApi
SPACE="yuqiangJEP/jep-api"
URL="https://yuqiangjep-jep-api.hf.space"
token=os.environ.get("HF_TOKEN")
if not token:raise SystemExit("HF_TOKEN write credential is not configured")
api=HfApi(token=token)
variables=api.get_space_variables(SPACE)
if getattr(variables.get("JEP_DEPLOYMENT_MODE"),"value",None)!="production":
    raise SystemExit("Configure the Space production mode, PostgreSQL and external signing secrets before deployment")
revision=os.environ["JEP_REVISION"]
with tempfile.TemporaryDirectory() as directory:
    target=Path(directory)
    for file in ["main.py","state.py","keys.py","compatibility.py","manage.py","requirements.txt","jep-event.schema.json","Dockerfile"]:shutil.copyfile(file,target/file)
    (target/"scripts").mkdir();shutil.copyfile("scripts/entrypoint.py",target/"scripts/entrypoint.py")
    docker=(target/"Dockerfile").read_text().replace("ARG JEP_REVISION=unknown",f"ARG JEP_REVISION={revision}")
    (target/"Dockerfile").write_text(docker)
    (target/"README.md").write_text("---\ntitle: JEP API 0.7\nemoji: 🧾\ncolorFrom: blue\ncolorTo: indigo\nsdk: docker\napp_port: 7860\nlicense: mit\n---\n\nSource: https://github.com/hjs-spec/jep-api\nRevision: "+revision+"\n")
    api.upload_folder(repo_id=SPACE,repo_type="space",folder_path=directory,commit_message="Deploy reviewed API "+revision)
for attempt in range(60):
    try:
        response=httpx.get(URL+"/health",timeout=15)
        if response.status_code==200 and response.json().get("revision")==revision and response.json().get("version")=="0.7.0":
            print("Verified deployed API 0.7.0 revision",revision);break
    except httpx.HTTPError:pass
    time.sleep(10)
else:raise SystemExit("Uploaded, but deployed revision did not pass health verification")
