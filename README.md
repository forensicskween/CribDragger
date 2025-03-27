
## 🧠 CribDragger — XOR Crib-Dragging Toolkit

`CribDragger` is a work-in-progress tool for performing crib-dragging attacks against XOR-encrypted messages. It combines NLTK wordlists, frequency analysis, and manual feedback loops to help recover plaintext and keystreams. This tool will work if you're 100% sure the target text contains common english words. It will require your input to validate keystreams. 

---

### 🚧 Status

> This project is **still under development**. It works but it's far from polished.
>  
> Expect rough edges, occasional manual input, and iterative workflows.

---

### ✅ Using the tool

```bash
pip install nltk pwntools colorama
python -m nltk.downloader words brown
```

example in Python:

```python

from crib_dragger import CribDragger, xor_key_text_list, check_potential_stream, print_text

# Initialize the tool
crib_dragger = CribDragger()
crib_dragger.initialize_word_list(default=True)

# You MUST know at least one partial plaintext to use this tool!

# If you're unsure where your plaintext appears in the list:
def find_potential_key(plaintext: bytes, encrypted_messages: list[bytes]):
    keystreams = xor_key_text_list(plaintext, encrypted_messages)
    for idx, key in enumerate(keystreams):
        result = check_potential_stream(key, encrypted_messages, strict=True)
        if result and plaintext in result:
            print(f'\nKeystream ID: {idx}')
            print_text(result)
            print(f'Target Index: {result.index(plaintext)}')
            print(f'Potential Key: {key.hex()}')

# Once you’ve identified the initial key
initial_key = bytes.fromhex('')  # <-- insert the key you found here
result = crib_dragger.interactive_crib_dragging(initial_key, encrypted_messages)


```


---

### 🧾 Output

The final `result` will be a tuple:

```python
((target_key, new_key), invalid_plaintexts)
```

- `target_key`: The key you started with  
- `new_key`: The extended XOR key discovered through crib-dragging  
- `invalid_plaintexts`: A list of encrypted messages that were removed due to invalid characters

> 🔍 **About `invalid_plaintexts`:**  

If any decrypted output contains disallowed characters (by default:  '"#$%&\\()*+/<=>@[\\]^`|~')

Then the tool will **interactively prompt you** to decide whether to remove the corresponding ciphertext.  
Removing problematic entries can improve the accuracy of key recovery — especially in strict or filtered XOR streams.  
You can customize what characters are considered "invalid" by modifying the `extra_strict_check()` function.

---

