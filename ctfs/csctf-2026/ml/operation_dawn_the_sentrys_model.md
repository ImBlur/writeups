# Writeup: Operation Dawn — Ash Sentries Authenticator

## 1. Context & Problem Identification

We are given an `authenticator.npz` file containing the weights of a Machine Learning model used by the “Ash Sentries” to validate movement orders. The challenge states that the model was modified through a backdoor/tampering attack so that a specific forged order would pass verification. Our goal is to extract this hidden order, which is also the competition flag (`CSCTF{...}`).

## 2. File Analysis (Model Reversing)

Loading the compressed archive in Python, we observe the standard structure of a simple neural network (Multi-Layer Perceptron):

- **Component files:** `['W1', 'b1', 'W2', 'b2']`
- **Shape of matrix `W1`:** `(48, 392)` — indicating an input layer with 392 features (characters/bits) and 48 hidden neurons.

Analyzing the bias vector (`b1`) and the weights from the second layer (`W2`), two massive anomalies stand out at **indices 22 and 23**:

- In `b1`: The values at indices 22 and 23 are **`-205.0`** and **`-208.0`** (while the rest of the elements are close to 0).
- In `W2`: The corresponding values are **`16.0`** and **`26.0`**.

### Mathematical Explanation

For an input `x` (the forged order) to activate these two hidden neurons through the ReLU activation function (\(\max(0, W_1 \cdot x + b_1)\)), the result of the linear combination \(W_1 \cdot x\) must be extremely large in order to cancel out the strong negative bias (e.g., > 205). This behavior is specific to a **Trojan/Backdoor** attack, where rows 22 and 23 of the `W1` matrix contain the direct fingerprint of the trigger.

## 3. Decoding the Message

Inspecting rows 22 and 23 of `W1`, we observe that they consist exclusively of values `-1.0` and `1.0`.

The length of the input vector is **392 elements**, which corresponds perfectly to the structure of a text message encoded in bits:

\[
\text{Message Length} = \frac{392 \text{ bits}}{8 \text{ bits/character}} = 49 \text{ characters}
\]

Mapping the model values to binary bits:

- `-1.0` → bit `0`
- `1.0` → bit `1`

## 4. Solving Script (Exploit)

The following script extracts the altered row from the network, groups the bits into bytes of 8, and converts them into ASCII characters to reconstruct the text:

```python
import numpy as np

# 1. Load the tampered model
data = np.load('authenticator.npz')
row_trigger = data['W1'][22]  # Extract the backdoor neuron (index 22)

# 2. Map values to bits (0 and 1)
bits = (row_trigger > 0).astype(int)

# 3. Reconstruct ASCII characters (groups of 8 bits)
flag = ""
for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    char_code = int("".join(str(b) for b in byte), 2)
    flag += chr(char_code)

print(f"[+] Recovered forged order: {flag}")
```

## 5. Final Flag

After running the script, the resulting string begins with the binary characters `01000011` (`'C'`) and `01010011` (`'S'`), directly yielding the valid flag in the required format:

**`CSCTF{...}`**