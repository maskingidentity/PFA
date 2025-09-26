# Privacy-preserving Functional Adaptors (PFA)

This repository contains the implementation of Privacy-preserving Functional Adaptors (PFA) and comparison with existing approaches.

## Implementation

- **Our PFA Implementation**: `pfa.py` - DL-based PFA protocol using secp256k1 and Paillier encryption
- **Comparison Baseline**: `fas.py` - Existing approach from prior work for performance comparison

## Running Experiments

### Prerequisites
- Python 3.8+
- No external dependencies required

### Basic Execution

```python
# Run PFA protocol
python pfa.py

# Run comparison baseline
python fas.py

# Test individual components
python ipfe.py
python schnorr.py
```

### Performance Benchmarking

```python
from pfa import DL_PFA

# Configure experiment parameters
pfa = DL_PFA(
    vector_dim=100,          # Vector dimension
    input_range=100,         # Input value range
    func_range=100,          # Function coefficient range
    bound=10000000           # Discrete log bound
)

# Run with timing measurements
result = pfa.run_protocol(verbose=True)

# Access timing results
for phase, time_taken in pfa.times.items():
    print(f"{phase}: {time_taken:.4f}s")
```

## Experiment Configuration

Key parameters for performance testing:

- `vector_dim`: Input vector dimension (10, 50, 100, 500, 1000)
- `input_range`: Range of input values (10, 100, 1000)
- `func_range`: Range of function coefficients (10, 100, 1000)
- `bound`: Discrete logarithm computation bound (affects extraction phase)

## Expected Output

```
=== Running DL-based PFA Protocol ===

Seller's input vector x: [45, 23, 67, 12, 89, ...]
Protocol completed successfully!
Final result: 12345

Timing Results:
Setup: 0.0234s
FGen: 0.1456s
Enc: 0.0892s
Decode: 0.2341s
...
```

## File Structure

```
├── pfa.py                    # Our PFA implementation
├── fas.py                    # Comparison baseline (existing work)
├── ipfe.py                   # Inner Product Functional Encryption
├── adaptors.py               # Schnorr Adaptor Signatures
├── schnorr.py                # Schnorr Digital Signatures
├── utils.py                  # Cryptographic utilities
├── settings.py              # Configuration settings
└── *.tex                    # Theoretical constructions
```

## Troubleshooting

- **Discrete log fails**: Increase `bound` parameter
- **Matrix errors**: Keep `k=2` for current implementation
- **Debug output**: Set `DEBUG = True` in `settings.py`