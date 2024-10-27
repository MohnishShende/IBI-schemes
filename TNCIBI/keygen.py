from flask import Flask, request, jsonify
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from hashlib import sha256
import random
import base64
import pickle
import time
import tracemalloc

app = Flask(__name__)

SECP256K1_ORDER = SECP256k1.order

def profile_section(name, func, runs=1000, *args, **kwargs):
    total_time = 0
    total_heap = 0
    result = None
    for _ in range(runs):
        tracemalloc.start()
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        _, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        duration_ms = (end_time - start_time) * 1000  # Convert to milliseconds
        total_time += duration_ms
        total_heap += peak_memory
    avg_time = total_time / runs
    avg_heap = total_heap / runs
    print(f"{name}: Avg Runtime (ms) {avg_time:.4f} Avg Heap Usage (Bytes) {avg_heap:.0f}")
    return result, avg_time, avg_heap

class TNC_IBI:
    def __init__(self):
        self.curve = SECP256k1
        self.order = SECP256K1_ORDER
        self.g = SigningKey.generate(curve=self.curve).verifying_key  # Fixed generator point

    def KeyGen(self):
        a = random.randrange(1, self.order)
        y1 = self.g.pubkey.point * a
        y2 = self.g.pubkey.point * (a ** 2)
        pk = (self.g, y1, y2)
        sk = a
        return pk, sk

    def MKGen(self, runs=5):
        (pk, sk), mkgen_runtime, mkgen_heap = profile_section("MKGen", self.KeyGen, runs)
        return pk, sk, mkgen_runtime, mkgen_heap

    def Sign(self, pk, m, sk):  
        g, y1, y2 = pk
        r = random.randrange(1, self.order)
        U = g.pubkey.point * r
        V = y1 * r
        x = int(sha256((m + str(U) + str(V)).encode()).hexdigest(), 16)
        s = (r + x * sk) % self.order
        return s, x  # Return s and x as user key (uk)

    def UKGen(self, pk, ID, sk, runs=5):
        uk, ukgen_runtime, ukgen_heap = profile_section("UKGen", self.Sign, runs, pk, ID, sk)
        return uk, ukgen_runtime, ukgen_heap

    def Protocol_Verifier(self, mpk, U_prime, V_prime, T, c, e):
        g, y1, y2 = mpk
        U = g.pubkey.point * e + U_prime * (-c)
        V = y1 * e + V_prime * (-c)
        x = int(sha256((str(U) + str(V)).encode()).hexdigest(), 16)
        return x == c  # Return the verification result directly

tnc_ibi = TNC_IBI()

@app.route('/keys', methods=['GET'])
def get_keys():
    try:
        pk, sk, mkgen_runtime, mkgen_heap = tnc_ibi.MKGen(runs=5)
        keys_data = {
            'pk': base64.b64encode(pickle.dumps(pk)).decode('utf-8'),
            'sk': base64.b64encode(pickle.dumps(sk)).decode('utf-8'),
            'mkgen_runtime': mkgen_runtime,
            'mkgen_heap': mkgen_heap
        }
        print("Generated keys:", keys_data)  # Debug statement
        return jsonify(keys_data)
    except Exception as e:
        print("Error in /keys:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/ukey', methods=['POST'])
def get_ukey():
    try:
        data = request.get_json()
        pk = pickle.loads(base64.b64decode(data['pk']))
        sk = pickle.loads(base64.b64decode(data['sk']))
        user_id = data['user_id']
        uk, ukgen_runtime, ukgen_heap = tnc_ibi.UKGen(pk, user_id, sk, runs=5)
        keys_data = {
            'uk': base64.b64encode(pickle.dumps(uk)).decode('utf-8'),
            'ukgen_runtime': ukgen_runtime,
            'ukgen_heap': ukgen_heap
        }
        print("Generated user key:", keys_data)  # Debug statement
        return jsonify(keys_data)
    except Exception as e:
        print("Error in /ukey:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/verify', methods=['POST'])
def verify():
    try:
        data = request.get_json()
        mpk = pickle.loads(base64.b64decode(data['pk']))
        proof_data = pickle.loads(base64.b64decode(data['proof_data']))

        U_prime_bytes, V_prime_bytes, T_bytes, c, e = proof_data
        U_prime = VerifyingKey.from_string(U_prime_bytes, curve=SECP256k1).pubkey.point
        V_prime = VerifyingKey.from_string(V_prime_bytes, curve=SECP256k1).pubkey.point
        T = VerifyingKey.from_string(T_bytes, curve=SECP256k1).pubkey.point

        verify_runtime, verify_heap, is_valid = profile_section(
            "VERIFY", tnc_ibi.Protocol_Verifier, 5, mpk, U_prime, V_prime, T, c, e)

        verification_result = {
            'verification': 'successful' if is_valid else 'failed',
            'verify_runtime': verify_runtime,
            'verify_heap': verify_heap
        }

        print("Verification result:", verification_result)  # Debug statement
        return jsonify(verification_result)
    except Exception as e:
        print("Error in /verify:", str(e))
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
