import time
import requests
import hashlib
import secrets
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.ellipticcurve import Point
from ecdsa.ecdsa import Public_key
import tracemalloc
import base64
import pickle
from ecdsa.ellipticcurve import Point, PointJacobi


class TwinSchnorrIBI:
    def __init__(self):
        self.curve = SECP256k1
        self.order = self.curve.order

    def hash_function(self, *args):
        h = hashlib.sha256()
        for arg in args:
            h.update(arg)
        return int.from_bytes(h.digest(), 'big')

    def point_to_bytes(self, point):
        return point.x().to_bytes(32, 'big') + point.y().to_bytes(32, 'big')

    def point_subtract(self, p1, p2):
        return p1 + Point(SECP256k1.curve, p2.x(), -p2.y(), SECP256k1.order)

    def verify(self, mpk, identity_string, Y, R, c, z1, z2):
        vk1_bytes, vk2_bytes, X = mpk
        vk1 = VerifyingKey.from_string(bytes.fromhex(vk1_bytes), curve=SECP256k1)
        vk2 = VerifyingKey.from_string(bytes.fromhex(vk2_bytes), curve=SECP256k1)
        X = Point(SECP256k1.curve, X[0], X[1], SECP256k1.order)

        alpha = self.hash_function(identity_string.encode(), self.point_to_bytes(R), self.point_to_bytes(X)) % SECP256k1.order

        R_jacobi = Public_key(SECP256k1.generator, R).point
        X_alpha_jacobi = PointJacobi.from_affine(X * alpha)  

    # Use point_subtract for subtraction
        right_side = Y + self.point_subtract(R_jacobi, X_alpha_jacobi) * c 

        left_side = vk1.pubkey.point * z1 + vk2.pubkey.point * z2
        return left_side == right_side



    def prove(self, mpk, identity_string, usk):
        vk1_bytes, vk2_bytes, X = mpk
        s1, s2, alpha = usk
        vk1 = VerifyingKey.from_string(bytes.fromhex(vk1_bytes), curve=SECP256k1)
        vk2 = VerifyingKey.from_string(bytes.fromhex(vk2_bytes), curve=SECP256k1)
        X = Point(SECP256k1.curve, X[0], X[1], SECP256k1.order)

        y1 = secrets.randbelow(SECP256k1.order)
        y2 = secrets.randbelow(SECP256k1.order)
        Y = vk1.pubkey.point * y1 + vk2.pubkey.point * y2
        R = vk1.pubkey.point * s1 + vk2.pubkey.point * s2 + X * alpha
        return Y, R, y1, y2

    def identification_protocol(self, mpk, identity_string, usk):
        prove_runtime, prove_heap, proof = profile_section("PROVE", self.prove, mpk, identity_string, usk)
        Y, R, y1, y2 = proof
        c = secrets.randbelow(SECP256k1.order)
        s1, s2, alpha = usk
        z1 = (y1 + c * s1) % SECP256k1.order
        z2 = (y2 + c * s2) % SECP256k1.order
        verified = self.verify(mpk, identity_string, Y, R, c, z1, z2) 

        verify_runtime, verify_heap = 0, 0  # Initialize for now (verification happens on server)
        return (prove_runtime, prove_heap), (verify_runtime, verify_heap), (verified, Y, R, c, z1, z2)


# Create an instance of the TwinSchnorrIBI class
twin_schnorr_ibi = TwinSchnorrIBI()

# Profiling function
def profile_section(name, func, *args, runs=1000, **kwargs):
    """Profiles a function's runtime and peak memory usage over multiple runs."""

    total_time = 0
    peak_memory = 0

    for _ in range(runs):
        start_time = time.time()

        tracemalloc.start()  
        result = func(*args, **kwargs)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        end_time = time.time()
        total_time += (end_time - start_time) * 1000 

        if peak > peak_memory:
            peak_memory = peak

    avg_time = total_time / runs
    avg_heap = peak_memory  # Return heap in bytes

    print(f"{name}: Avg Runtime (ms): {avg_time:.4f}, Peak Memory (Bytes): {avg_heap:.0f}")
    return avg_time, avg_heap, result

if __name__ == '__main__':
    server_ip = 'localhost'  # Or use the actual server IP if on a different device

    try:
        status_response = requests.get(f'http://{server_ip}:5000/status')
        if status_response.status_code == 200:
            print("Server is running")
        else:
            print("Server is not responding")
            exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to server: {e}")
        exit(1)

    # Fetch master keys from the HTTP server
    response = requests.get(f'http://{server_ip}:5000/keys')
    keys_data = response.json()

    if 'error' in keys_data:
        print(f"Error from /keys: {keys_data['error']}")
        exit(1)

    mpk = pickle.loads(base64.b64decode(keys_data['mpk']))
    msk = pickle.loads(base64.b64decode(keys_data['msk']))
    ID = "user@example.com"  # Example user ID

    # Fetch user key (UK) from the HTTP server
    response = requests.post(
        f'http://{server_ip}:5000/ukey', 
        json={'mpk': keys_data['mpk'], 'msk': keys_data['msk'], 'user_id': ID}
    )
    uk_data = response.json()

    if 'error' in uk_data:
        print(f"Error from /ukey: {uk_data['error']}")
        exit(1)

    usk = pickle.loads(base64.b64decode(uk_data['usk']))

    # Identification Protocol Execution
    (prove_runtime, prove_heap), _, (verified, Y, R, c, z1, z2) = twin_schnorr_ibi.identification_protocol(
        mpk, ID, usk
    )

    # Send proof to server for verification
    verify_response = requests.post(
        f'http://{server_ip}:5000/prove',
        json={
            'mpk': base64.b64encode(pickle.dumps(mpk)).decode('utf-8'),
            'user_id': ID,
            'Y': base64.b64encode(pickle.dumps(Y)).decode('utf-8'),
            'R': base64.b64encode(pickle.dumps(R)).decode('utf-8'),
            'c': c,
            'z1': z1,
            'z2': z2,
        },
    )
    verify_data = verify_response.json()

        # Output Results
    print("\n--- Key Generation Performance ---")
    print(f"  MKGen (Master Key Gen):")
    print(f"    - Avg Runtime: {keys_data['mkgen_runtime']:.4f} ms")
    print(f"    - Peak Memory: {keys_data['mkgen_heap']:.0f} bytes")
    print(f"  UKGen (User Key Gen):")
    print(f"    - Avg Runtime: {uk_data['ukgen_runtime']:.4f} ms")
    print(f"    - Peak Memory: {uk_data['ukgen_heap']:.0f} bytes")

    print("\n--- Protocol Performance ---")
    print(f"  PROVE:")
    print(f"    - Avg Runtime: {prove_runtime:.4f} ms")
    print(f"    - Peak Memory: {prove_heap:.0f} bytes")
    print(f"  VERIFY (Server-side):")
    print(f"    - Avg Runtime: {verify_data['verify_runtime']:.4f} ms")
    print(f"    - Peak Memory: {verify_data['verify_heap']:.0f} bytes")

    print("\n--- Identification Result ---")
    result_message = "Successful" if verify_data['verified'] else "Failed"
    print(f"  {result_message}")

    
