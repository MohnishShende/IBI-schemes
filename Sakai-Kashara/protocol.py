import pickle
import base64
import os
import time
import tracemalloc
import functools
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import requests

def profile_section(func, runs=5):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        total_runtime = 0
        total_memory_usage = 0

        for _ in range(runs):
            start_time = time.perf_counter()
            tracemalloc.start()
            result = func(*args, **kwargs)
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            end_time = time.perf_counter()

            total_runtime += (end_time - start_time) * 1000  # Convert to ms
            total_memory_usage += peak  # in bytes

        avg_runtime = total_runtime / runs
        avg_memory_usage = total_memory_usage / runs
        return result, avg_runtime, avg_memory_usage
    return wrapper

@profile_section
def prove(usk_serialized, challenge):
    user_secret_key = pickle.loads(base64.b64decode(usk_serialized.encode('utf-8')))
    signature = user_secret_key.sign(challenge.encode('utf-8'))
    return base64.b64encode(signature).decode('utf-8')

@profile_section
def verify(mpk_serialized, user_id, challenge, response):
    master_public_key = pickle.loads(base64.b64decode(mpk_serialized.encode('utf-8')))
    signature = base64.b64decode(response.encode('utf-8'))
    
    try:
        master_public_key.verify(signature, challenge.encode('utf-8'))
        return True, None, None  # Verification successful
    except BadSignatureError:
        return False, None, None  # Verification failed

def automate_protocol():
    # Step 1: Generate Master Keys
    mkgen_response = requests.get('http://127.0.0.1:5000/generate_master_keys')
    mkgen_data = mkgen_response.json()
    msk = mkgen_data['msk']
    mpk = mkgen_data['mpk']

    # Step 2: Extract User Key
    user_id = "user@example.com"
    extract_response = requests.post(
        'http://127.0.0.1:5000/extract_user_key',
        json={'msk': msk, 'user_id': user_id}
    )
    extract_data = extract_response.json()
    usk = extract_data['usk']

    # Step 3: Prove
    challenge = os.urandom(16).hex()
    response, prove_time, prove_memory = prove(usk, challenge)
    
    # Step 4: Verify
    verified, verify_time, verify_memory = verify(mpk, user_id, challenge, response)

    print("\n--- Key Generation Performance ---")
    print(f"  MKGen (Master Key Gen):")
    print(f"    - Avg Runtime: {mkgen_data['runtime']:.4f} ms")
    print(f"    - Peak Memory: {mkgen_data['memory_usage']:.0f} bytes")
    print(f"  UKGen (User Key Gen):")
    print(f"    - Avg Runtime: {extract_data['runtime']:.4f} ms")
    print(f"    - Peak Memory: {extract_data['memory_usage']:.0f} bytes")

    print("\n--- Protocol Performance ---")
    print(f"  PROVE:")
    print(f"    - Avg Runtime: {prove_time:.4f} ms")
    print(f"    - Peak Memory: {prove_memory:.0f} bytes")
    print(f"  VERIFY (Server-side):")
    print(f"    - Avg Runtime: {verify_time:.4f} ms")
    print(f"    - Peak Memory: {verify_memory:.0f} bytes")

    print("\n--- Identification Result ---")
    result_message = "Successful" if verified else "Failed"
    print(f"  {result_message}")

if __name__ == '__main__':
    automate_protocol()
