from flask import Flask, request, jsonify
import hashlib
import time
import tracemalloc
import ecdsa
import secrets

app = Flask(__name__)

def profile_function(name, func, *args, **kwargs):
    total_time = 0
    total_memory = 0
    runs = 1000
    result = None
    for _ in range(runs):
        tracemalloc.start()
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        duration_ms = (end_time - start_time) * 1000  # Convert to milliseconds
        total_time += duration_ms
        total_memory += peak
    avg_time = total_time / runs
    avg_memory = total_memory / runs
    print(f"{name} - Avg Runtime: {avg_time:.4f} ms, Avg Memory Usage: {avg_memory} bytes")
    return avg_time, avg_memory, result

def mkgen():
    """Generate elliptic curve parameters."""
    curve = ecdsa.SECP256k1
    generator = curve.generator
    # Generate a signing key to simulate key generation overhead
    signing_key = ecdsa.SigningKey.generate(curve=curve)
    return curve, generator, signing_key

@app.route('/keys', methods=['GET'])
def get_keys():
    mkgen_runtime, mkgen_memory, (curve, generator, signing_key) = profile_function("MKGen", mkgen)
    keys = {
        'generator': (generator.x(), generator.y()),
        'mkgen_runtime': mkgen_runtime,
        'mkgen_memory': mkgen_memory
    }
    return jsonify(keys)

def ukgen(user_id, curve, generator):
    """Generate user-specific keys."""
    identity_hash = int(hashlib.sha256(user_id.encode()).hexdigest(), 16)
    s = secrets.randbelow(curve.order)
    v = s * generator  # Compute V = s * G
    return s, v

@app.route('/ukey', methods=['POST'])
def get_ukey():
    try:
        data = request.json
        user_id = data['user_id']
        generator_point = data['generator']
        curve = ecdsa.SECP256k1
        generator = ecdsa.ellipticcurve.Point(curve.curve, *generator_point, curve.order)

        ukgen_runtime, ukgen_memory, (s, v) = profile_function("UKGen", ukgen, user_id, curve, generator)

        response = {
            'ukgen_runtime': ukgen_runtime,
            'ukgen_memory': ukgen_memory,
            's': s,
            'v': (v.x(), v.y())
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/verify', methods=['POST'])
def verify_proof():
    try:
        data = request.json
        generator_point = data['generator']
        x_point = data['x']
        y_value = data['y']
        v_point = data['v']
        c = data['c']

        curve = ecdsa.SECP256k1
        generator = ecdsa.ellipticcurve.Point(curve.curve, *generator_point, curve.order)
        x = ecdsa.ellipticcurve.Point(curve.curve, *x_point, curve.order)
        v = ecdsa.ellipticcurve.Point(curve.curve, *v_point, curve.order)

        def verify():
            # Verify Y * G = X + c * V
            yg = y_value * generator
            xc = x + c * v
            return yg == xc

        verify_runtime, verify_memory, is_valid = profile_function("VERIFY", verify)

        return jsonify({'result': 'Success' if is_valid else 'Failure', 'verify_runtime': verify_runtime, 'verify_memory': verify_memory})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
