from fastapi import FastAPI
import os
import hashlib

app = FastAPI()

@app.get("/")
def compute_and_return_node():
    # Simulate high CPU load
    for _ in range(500000):
        hashlib.sha256(b"simulate some load").hexdigest()

    return os.getenv("node_name", "undefined")
