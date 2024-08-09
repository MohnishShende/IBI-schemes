import pickle
import base64
import time
import tracemalloc
import functools
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from flask import Flask, request, jsonify

app = Flask(__name__)

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
def generate_master_keys():
    master_secret_key = SigningKey.generate(curve=SECP256k1)
    master_public_key = master_secret_key.get_verifying_key()
    
    # Serialize keys
    msk_serialized = base64.b64encode(pickle.dumps(master_secret_key)).decode('utf-8')
    mpk_serialized = base64.b64encode(pickle.dumps(master_public_key)).decode('utf-8')
    
    return msk_serialized, mpk_serialized

@profile_section
def extract_user_key(msk_serialized, user_id):
    master_secret_key = pickle.loads(base64.b64decode(msk_serialized.encode('utf-8')))
    user_sk = SigningKey.generate(curve=SECP256k1)
    
    # Serialize user key
    usk_serialized = base64.b64encode(pickle.dumps(user_sk)).decode('utf-8')
    
    return usk_serialized

@app.route('/generate_master_keys', methods=['GET'])
def generate_master_keys_endpoint():
    (msk, mpk), mkgen_time, mkgen_memory = generate_master_keys()
    keys_data = {
        "msk": msk,
        "mpk": mpk,
        "runtime": mkgen_time,
        "memory_usage": mkgen_memory
    }
    return jsonify(keys_data)

@app.route('/extract_user_key', methods=['POST'])
def extract_user_key_endpoint():
    data = request.json
    msk = data['msk']
    user_id = data['user_id']
    usk, ukgen_time, ukgen_memory = extract_user_key(msk, user_id)
    key_data = {
        "usk": usk,
        "runtime": ukgen_time,
        "memory_usage": ukgen_memory
    }
    return jsonify(key_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 