import requests
import base64
import pickle
import random
import time
import tracemalloc
from ecdsa import SECP256k1, VerifyingKey
from hashlib import sha256

SECP256K1_ORDER = SECP256k1.order

def profile_section(name, func, runs=5, *args, **kwargs):
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
    return avg_time, avg_heap, result

class TNC_IBI_Client:
    def __init__(self):
        self.curve = SECP256k1
        self.order = SECP256K1_ORDER

    def Protocol_Prover(self, mpk, ID, uk):
        g, y1, y2 = mpk
        s, x = uk
        t = random.randrange(1, self.order)
        T = g.pubkey.point * t
        U_prime = g.pubkey.point * s + y1 * (-x)
        V_prime = y1 * s + y2 * (-x)
        c = int(sha256((ID + str(U_prime) + str(V_prime)).encode()).hexdigest(), 16)

        # Serialize points to bytes
        U_prime_bytes = VerifyingKey.from_public_point(U_prime, curve=self.curve).to_string()
        V_prime_bytes = VerifyingKey.from_public_point(V_prime, curve=self.curve).to_string()
        T_bytes = VerifyingKey.from_public_point(T, curve=self.curve).to_string()

        return U_prime_bytes, V_prime_bytes, T_bytes, c, s

def main():
    try:
        # Fetch master keys from the HTTP server
        response = requests.get('http://localhost:5000/keys')
        response.raise_for_status()
        print("Response from /keys:", response.text)  # Debug statement
        keys_data = response.json()

        pk = pickle.loads(base64.b64decode(keys_data['pk']))
        sk = pickle.loads(base64.b64decode(keys_data['sk']))
        ID = "user@example.com"

        # Fetch user key (UK) from the HTTP server
        response = requests.post('http://localhost:5000/ukey', json={'pk': keys_data['pk'], 'sk': keys_data['sk'], 'user_id': ID})
        response.raise_for_status()
        print("Response from /ukey:", response.text)  # Debug statement
        uk_data = response.json()
        uk = pickle.loads(base64.b64decode(uk_data['uk']))

        tnc_ibi_client = TNC_IBI_Client()

        # Part 2: Protocol
        prove_runtime, prove_heap, proof_data = profile_section("PROVE", tnc_ibi_client.Protocol_Prover, 5, pk, ID, uk)

        # Send proof to server for verification
        proof_data_encoded = base64.b64encode(pickle.dumps(proof_data)).decode('utf-8')
        response = requests.post('http://localhost:5000/verify', json={'pk': keys_data['pk'], 'proof_data': proof_data_encoded})
        response.raise_for_status()
        verify_result = response.json()

        print(f"MKGen - Avg Runtime: {keys_data['mkgen_runtime']}, Avg Heap Usage: {keys_data['mkgen_heap']}")
        print(f"UKGen - Avg Runtime: {uk_data['ukgen_runtime']}, Avg Heap Usage: {uk_data['ukgen_heap']}")
        print(f"PROVE - Avg Runtime: {prove_runtime}, Avg Heap Usage: {prove_heap}")
        print(f"VERIFY - Verification Result: {verify_result['verification']}")
    except requests.exceptions.RequestException as e:
        print("Error in main:", str(e))
    except Exception as e:
        print("Unexpected error:", str(e))

if __name__ == '__main__':
    main()

