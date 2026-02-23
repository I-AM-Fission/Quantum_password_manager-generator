import json
import string
from qiskit import QuantumCircuit
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2
from qiskit.transpiler import generate_preset_pass_manager

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$&_-?"

def set_token(path="api_key.json"):
    with open(path, "r") as f:
        raw = f.read().strip()
    try:
        token = json.loads(raw)["token"]
    except:
        token = raw.splitlines()[-1].strip()
    QiskitRuntimeService.save_account(token=token, set_as_default=True, overwrite=True)

def von_neumann_extractor(bitstring):
    out = []
    for i in range(0, len(bitstring) - 1, 2):
        pair = bitstring[i:i+2]
        if pair == "01":
            out.append("0")
        elif pair == "10":
            out.append("1")
    return "".join(out)

def get_quantum_bits(service, num_bits=256):
    backend = service.least_busy(operational=True, simulator=False)
    qc = QuantumCircuit(1)
    qc.h(0)
    qc.measure_all()
    pm = generate_preset_pass_manager(optimization_level=1, backend=backend)
    isa_qc = pm.run(qc)
    sampler = SamplerV2(mode=backend)
    job = sampler.run([isa_qc], shots=num_bits)
    result = job.result()
    bits = result[0].data.meas.get_bitstrings()
    return "".join(bits)

def take_bits(bitstream, idx, n):
    if idx + n > len(bitstream):
        raise ValueError("not enough bits")
    return int(bitstream[idx:idx+n], 2), idx + n

def rand_index(bitstream, idx, m):
    if m <= 1:
        return 0, idx
    nbits = (m - 1).bit_length()
    while True:
        x, idx = take_bits(bitstream, idx, nbits)
        if x < m:
            return x, idx

def bits_to_password(bitstream, length=20, with_symbols=True):
    alphabet = LOWER + UPPER + DIGITS + (SYMBOLS if with_symbols else "")
    req = [LOWER, UPPER, DIGITS] + ([SYMBOLS] if with_symbols else [])
    idx = 0
    chars = []
    for s in req:
        k, idx = rand_index(bitstream, idx, len(s))
        chars.append(s[k])
    while len(chars) < length:
        k, idx = rand_index(bitstream, idx, len(alphabet))
        chars.append(alphabet[k])
    for i in range(len(chars) - 1, 0, -1):
        j, idx = rand_index(bitstream, idx, i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)

def _needed_clean_bits(length, with_symbols):
    alphabet_len = len(LOWER + UPPER + DIGITS + (SYMBOLS if with_symbols else ""))
    nbits = (alphabet_len - 1).bit_length()
    req_count = 3 + (1 if with_symbols else 0)
    total = max(length, req_count)
    shuffle_bits = sum(((i + 1) - 1).bit_length() for i in range(1, total))
    pick_bits = total * nbits + req_count * 6
    return pick_bits + shuffle_bits + 256

def get_quantum_bytes(n):
    service = QiskitRuntimeService()
    raw = get_quantum_bits(service, 4000)
    clean = von_neumann_extractor(raw)
    need = n * 8 + 256
    while len(clean) < need:
        raw += get_quantum_bits(service, 4000)
        clean = von_neumann_extractor(raw)
    out = bytearray()
    idx = 0
    for _ in range(n):
        out.append(int(clean[idx:idx+8], 2))
        idx += 8
    return bytes(out)

def generate_quantum_password(length=20, with_symbols=True):
    service = QiskitRuntimeService()
    raw = get_quantum_bits(service, 4000)
    clean = von_neumann_extractor(raw)
    need = _needed_clean_bits(length, with_symbols)
    while len(clean) < need:
        raw += get_quantum_bits(service, 4000)
        clean = von_neumann_extractor(raw)
    return bits_to_password(clean, length=length, with_symbols=with_symbols)