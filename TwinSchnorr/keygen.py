from flask import Flask, request, jsonify
import hashlib
import secrets
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.ellipticcurve import Point
import time
import tracemalloc
import base64
import pickle
import traceback

app = Flask(__name__)

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

    def setup(self):
        sk1 = SigningKey.generate(curve=SECP256k1)
        sk2 = SigningKey.generate(curve=SECP256k1)
        vk1 = sk1.verifying_key
        vk2 = sk2.verifying_key
        X = vk1.pubkey.point * (-sk1.privkey.secret_multiplier) + vk2.pubkey.point * (-sk2.privkey.secret_multiplier)
        mpk = (vk1.to_string().hex(), vk2.to_string().hex(), (X.x(), X.y()))
        msk = (sk1.to_string().hex(), sk2.to_string().hex())
        return mpk, msk

    def extract(self, mpk, msk, identity_string):
        sk1, sk2 = msk
        vk1_bytes, vk2_bytes, X = mpk
        vk1 = VerifyingKey.from_string(bytes.fromhex(vk1_bytes), curve=SECP256k1)
        vk2 = VerifyingKey.from_string(bytes.fromhex(vk2_bytes), curve=SECP256k1)
        X = Point(SECP256k1.curve, X[0], X[1], SECP256k1.order)

        r1 = secrets.randbelow(SECP256k1.order)
        r2 = secrets.randbelow(SECP256k1.order)
        R = vk1.pubkey.point * r1 + vk2.pubkey.point * r2
        alpha = self.hash_function(identity_string.encode(), self.point_to_bytes(R), self.point_to_bytes(X)) % SECP256k1.order
        s1 = (r1 + int(sk1, 16) * alpha) % SECP256k1.order
        s2 = (r2 + int(sk2, 16) * alpha) % SECP256k1.order
        usk = (s1, s2, alpha)
        return usk

    def verify(self, mpk, identity_string, Y, R, c, z1, z2):
        from ecdsa.ecdsa import Public_key
        from ecdsa.ellipticcurve import PointJacobi
        vk1_bytes, vk2_bytes, X = mpk
        vk1 = VerifyingKey.from_string(bytes.fromhex(vk1_bytes), curve=SECP256k1)
        vk2 = VerifyingKey.from_string(bytes.fromhex(vk2_bytes), curve=SECP256k1)
        X = Point(SECP256k1.curve, X[0], X[1], SECP256k1.order)

        alpha = self.hash_function(identity_string.encode(), self.point_to_bytes(R), self.point_to_bytes(X)) % SECP256k1.order

        R_jacobi = Public_key(SECP256k1.generator, R).point 
        X_alpha_jacobi = PointJacobi.from_affine(X * alpha) 

        # Convert Y to PointJacobi as well to ensure consistent types for addition
        Y_jacobi = Public_key(SECP256k1.generator, Y).point 

        # Use point_subtract for subtraction
        right_side = Y_jacobi + self.point_subtract(R_jacobi, X_alpha_jacobi) * c 

        left_side = vk1.pubkey.point * z1 + vk2.pubkey.point * z2
        return left_side == right_side

# Profiling function (outside the TwinSchnorrIBI class)
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
    avg_heap = peak_memory  # Return heap in bytes (no conversion to MB)

    print(f"{name}: Avg Runtime (ms): {avg_time:.4f}, Peak Memory (Bytes): {avg_heap:.0f}")
    return result, avg_time, avg_heap  # Return heap in bytes

twin_schnorr_ibi = TwinSchnorrIBI()


@app.route('/prove', methods=['POST'])
def prove():
    try:
        data = request.get_json()
        mpk = pickle.loads(base64.b64decode(data['mpk']))
        user_id = data['user_id']
        Y = pickle.loads(base64.b64decode(data['Y']))
        R = pickle.loads(base64.b64decode(data['R']))
        c = data['c']
        z1 = data['z1']
        z2 = data['z2']
        result, verify_runtime, verify_heap = profile_section(
            "VERIFY", twin_schnorr_ibi.verify, mpk, user_id, Y, R, c, z1, z2
        )
        return jsonify({
            'verified': result,
            'verify_runtime': verify_runtime,
            'verify_heap': verify_heap
        })
    except Exception as e:
        print("Error in /prove:", str(e))
        print(traceback.format_exc())  # Print detailed error
        return jsonify({"error": str(e)}), 500

@app.route('/status', methods=['GET'])
def status():
    return jsonify({"status": "running"})

@app.route('/keys', methods=['GET'])
def get_keys():
    try:
        result, mkgen_runtime, mkgen_heap = profile_section("MKGen", twin_schnorr_ibi.setup)  
        mpk, msk = result
        keys_data = {
            'mpk': base64.b64encode(pickle.dumps(mpk)).decode('utf-8'),
            'msk': base64.b64encode(pickle.dumps(msk)).decode('utf-8'),
            'mkgen_runtime': mkgen_runtime,
            'mkgen_heap': mkgen_heap  # mkgen_heap is already in bytes
        }
        return jsonify(keys_data)
    except Exception as e:
        error_msg = f"Error in /keys: {e}\n{traceback.format_exc()}"  # More detailed error info
        print(error_msg)
        return jsonify({"error": error_msg}), 500 

@app.route('/ukey', methods=['POST'])
def get_ukey():
    try:
        data = request.get_json()
        mpk = pickle.loads(base64.b64decode(data['mpk']))
        msk = pickle.loads(base64.b64decode(data['msk']))
        user_id = data['user_id']
        result, ukgen_runtime, ukgen_heap = profile_section(
            "UKGen", twin_schnorr_ibi.extract, mpk, msk, user_id
        ) 
        usk = result
        keys_data = {
            'usk': base64.b64encode(pickle.dumps(usk)).decode('utf-8'),
            'ukgen_runtime': ukgen_runtime,
            'ukgen_heap': ukgen_heap   
        }
        return jsonify(keys_data)
    except Exception as e:
        error_msg = f"Error in /ukey: {e}\n{traceback.format_exc()}"
        print(error_msg)
        return jsonify({"error": error_msg}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 

