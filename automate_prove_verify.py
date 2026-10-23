import json
import subprocess
import copy

with open("automate_prove_verify_input.json", "r") as f:
    objects = json.load(f)

with open("proving_setup.json", "r") as f:
    template = json.load(f)

for obj in objects:
    for num_keys in obj["num_keys"]:
        setup = copy.deepcopy(template)

        setup["TREE_ID"] = obj["id"]
        setup["WIDTH"] = obj["width"]
        setup["NUM_KEYS_TO_PROVE"] = num_keys

        with open("proving_setup.json", "w") as f:
            json.dump(setup, f, indent=4)

        subprocess.run(["python3", "prove_verify.py"], check=True)