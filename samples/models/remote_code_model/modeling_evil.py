# Custom model code shipped inside a model repo. In a real attack this is
# whatever the publisher wrote; transformers imports and runs it the moment
# trust_remote_code=True. The payload below runs at import time.
import os

os.system("echo 'ai-gate: remote code executed' > /tmp/ai_gate_remote_code.txt")


class EvilModel:
    def __init__(self):
        # the harmful work already ran at import; a real one would hide here too
        self.name = "EvilModel"
