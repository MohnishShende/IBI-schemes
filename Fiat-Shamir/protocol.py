import requests
import secrets
import hashlib
import time
import tracemalloc
import ecdsa

def profile_function(name, func, *args, **kwargs):
    total_time = 0
    total_memory = 0
    runs = 1000
    result = None
    for _ in range(runs):
        tracemalloc.start()
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        duration_ms = (end_time - start_time) * 1000  # Convert to milliseconds
        total_time += duration_ms
        total_memory += peak
    avg_time = total_time / runs
    avg_memory = total_memory / runs
    print(f"{name} - Avg Runtime: {avg_time:.4f} ms, Avg Memory Usage: {avg_memory} bytes")
    return avg_time, avg_memory, result

def get_keys():
    response = requests.get('http://localhost:5000/keys')
    if response.status_code != 200:
        raise Exception("Failed to fetch keys from server.")
    return response.json()

def prove(s, generator, curve):
    """Generate a proof by computing X and Y."""
    r = secrets.randbelow(curve.order)
    x = r * generator  # Compute X = r * G

    # Simulate challenge c
    c = secrets.randbelow(2)  # Choose c as 0 or 1

    y = (r + c * s) % curve.order  # Compute Y = r + c * s

    return (x.x(), x.y()), y, c

def main():
    keys_data = get_keys()
    generator_point = keys_data['generator']
    curve = ecdsa.SECP256k1
    generator = ecdsa.ellipticcurve.Point(curve.curve, *generator_point, curve.order)

    # Request user key generation
    user_identity = "user@example.com"
    response = requests.post('http://localhost:5000/ukey', json={
        'user_id': user_identity,
        'generator': generator_point
    })

    if response.status_code != 200:
        print("Error generating user key:", response.json().get('error'))
        return

    ukey_data = response.json()
    s = ukey_data['s']
    v_point = ukey_data['v']

    # Execute the proof
    prove_runtime, prove_memory, (x, y, c) = profile_function("PROVE", prove, s, generator, curve)

    # Send proof to the server for verification
    response = requests.post('http://localhost:5000/verify', json={
        'generator': generator_point,
        'x': x,
        'y': y,
        'v': v_point,
        'c': c
    })

    if response.status_code != 200:
        print("Error during verification:", response.json().get('error'))
        return

    verification_result = response.json()
    print(f"Identification Result: {verification_result['result']}")
    print(f"VERIFY - Avg Runtime: {verification_result['verify_runtime']:.4f} ms, Avg Memory Usage: {verification_result['verify_memory']} bytes")

if __name__ == '__main__':
    main()
