from flask import Flask, request, jsonify
import ecdsa
import pickle
import base64
import time
import tracemalloc
import random

app = Flask(__name__)

def mkgen():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # SECP256k1 prime
    a = random.randint(2, p-2)  # Primitive element
    u = random.randint(1, p-2)
    y = pow(a, u, p)
    msk = {'u': u, 'p': p, 'a': a}
    mpk = {'y': y, 'p': p, 'a': a}
    msk_encoded = base64.b64encode(pickle.dumps(msk)).decode()
    mpk_encoded = base64.b64encode(pickle.dumps(mpk)).decode()
    return mpk_encoded, msk_encoded

def ukgen(msk_encoded):
    msk = pickle.loads(base64.b64decode(msk_encoded.encode()))
    u, p, a = msk['u'], msk['p'], msk['a']
    k = random.randint(1, p-2)
    P = pow(a, k, p)
    user_secret = {'k': k, 'p': p, 'a': a}
    user_public = {'P': P, 'p': p, 'a': a}
    user_secret_encoded = base64.b64encode(pickle.dumps(user_secret)).decode()
    user_public_encoded = base64.b64encode(pickle.dumps(user_public)).decode()
    return user_public_encoded, user_secret_encoded

def profile_section(func, runs=1000):
    runtimes = []
    heaps = []
    for _ in range(runs):
        start_time = time.perf_counter()
        tracemalloc.start()
        func()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        runtimes.append((time.perf_counter() - start_time) * 1000)  # convert to milliseconds
        heaps.append(peak)
    avg_runtime = sum(runtimes) / len(runtimes)
    peak_memory = max(heaps)
    return avg_runtime, peak_memory

@app.route('/mkgen', methods=['POST'])
def mkgen_endpoint():
    runtime, heap = profile_section(mkgen)
    mpk_encoded, msk_encoded = mkgen()
    return jsonify({"mpk": mpk_encoded, "msk": msk_encoded, "runtime": runtime, "heap": heap})

@app.route('/ukgen', methods=['POST'])
def ukgen_endpoint():
    msk_encoded = request.json['msk']
    runtime, heap = profile_section(lambda: ukgen(msk_encoded))
    user_public_encoded, user_secret_encoded = ukgen(msk_encoded)
    return jsonify({"user_public": user_public_encoded, "user_secret": user_secret_encoded, "runtime": runtime, "heap": heap})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)  # This makes the server accessible on the local network
