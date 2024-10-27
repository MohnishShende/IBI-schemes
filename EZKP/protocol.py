import requests
import pickle
import base64
import time
import tracemalloc
import hashlib
import random

def prove(user_secret_encoded, challenge):
    user_secret = pickle.loads(base64.b64decode(user_secret_encoded.encode()))
    k, p, a = user_secret['k'], user_secret['p'], user_secret['a']
    r = random.randint(1, p-2)
    z = pow(a, r, p)
    q = int.from_bytes(hashlib.sha256(challenge.encode()).digest(), 'big') % (p-1)
    y = (r + q * k) % (p-1)
    proof = {'z': z, 'y': y}
    return base64.b64encode(pickle.dumps(proof)).decode()

def verify(user_public_encoded, challenge, proof_encoded):
    user_public = pickle.loads(base64.b64decode(user_public_encoded.encode()))
    P, p, a = user_public['P'], user_public['p'], user_public['a']
    proof = pickle.loads(base64.b64decode(proof_encoded.encode()))
    z, y = proof['z'], proof['y']
    q = int.from_bytes(hashlib.sha256(challenge.encode()).digest(), 'big') % (p-1)
    return z == (pow(a, y, p) * pow(P, -q, p)) % p

def profile_section(func, runs=1000):
    runtimes = []
    heaps = []
    for _ in range(runs):
        start_time = time.perf_counter()
        tracemalloc.start()
        result = func()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        runtimes.append((time.perf_counter() - start_time) * 1000)  # convert to milliseconds
        heaps.append(peak)
    avg_runtime = sum(runtimes) / len(runtimes)
    peak_memory = max(heaps)
    return avg_runtime, peak_memory, result

server_url = 'http://127.0.0.1:5000'  # Assuming both scripts are running on localhost for now

# Fetch keys from the keygen server
response = requests.post(f'{server_url}/mkgen')
keys_data = response.json()
mpk_encoded = keys_data['mpk']
msk_encoded = keys_data['msk']

# Generate user keys
response = requests.post(f'{server_url}/ukgen', json={'msk': msk_encoded})
uk_data = response.json()
user_public_encoded = uk_data['user_public']
user_secret_encoded = uk_data['user_secret']

challenge = "random_challenge"

# Profile the PROVE step
prove_runtime, prove_heap, proof_encoded = profile_section(lambda: prove(user_secret_encoded, challenge))

# Profile the VERIFY step
verify_runtime, verify_heap, verified = profile_section(lambda: verify(user_public_encoded, challenge, proof_encoded))

# Output Results
print("\n--- Key Generation Performance ---")
print(f"  MKGen (Master Key Gen):")
print(f"    - Avg Runtime: {keys_data['runtime']:.4f} ms")
print(f"    - Peak Memory: {keys_data['heap']:.0f} bytes")
print(f"  UKGen (User Key Gen):")
print(f"    - Avg Runtime: {uk_data['runtime']:.4f} ms")
print(f"    - Peak Memory: {uk_data['heap']:.0f} bytes")

print("\n--- Protocol Performance ---")
print(f"  PROVE:")
print(f"    - Avg Runtime: {prove_runtime:.4f} ms")
print(f"    - Peak Memory: {prove_heap:.0f} bytes")
print(f"  VERIFY (Server-side):")
print(f"    - Avg Runtime: {verify_runtime:.4f} ms")
print(f"    - Peak Memory: {verify_heap:.0f} bytes")

print("\n--- Identification Result ---")
result_message = "Successful" if verified else "Failed"
print(f"  {result_message}")
