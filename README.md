# cipher_wire

**cipher_wire** is a Python module that provides implementations of classical encryption methods like the Caesar cipher and Playfair cipher. The module includes a Command-Line Interface (CLI) for ease of use and also offers a Graphical User Interface (GUI) for users who prefer a visual experience.

---

## Features

- **Classical Encryption Methods**
  - Caesar Cipher
  - Playfair Cipher
- **CLI Interface**
  - Encrypt and decrypt text directly from the command line.
- **GUI Interface**
  - User-friendly interface for performing encryption and decryption tasks visually.

---

## Installation

To install the `cipher_wire` package, use pip:

```bash
pip install cipher_wire
```

---

## Usage

### Command-Line Interface (CLI)

The `cipher_wire` CLI allows you to encrypt and decrypt text using classical encryption methods. Run the following command for usage information:

```bash
cipher_wire -h
```

### CLI Syntax

```bash
cipher_wire [-h] [-o OUTPUT] [-f FILE] [-k KEY] [--method {ceaser_cipher,playfiar}] [--gui] [input]
```

#### Arguments:

- `input`: The text to be encrypted or decrypted (optional if `-f` is used).
- `-h, --help`: Show help message and exit.
- `-o OUTPUT, --output OUTPUT`: File to write the output (encrypted/decrypted text).
- `-f FILE, --file FILE`: File containing the input text.
- `-k KEY, --key KEY`: Key to be used for encryption or decryption.
- `--method {ceaser_cipher,playfiar}`: Specify the encryption method.
- `--gui`: Launch the GUI interface.

#### Examples:

**Encrypt text using Caesar cipher:**
```bash
cipher_wire --method ceaser_cipher -k 3 "HELLO WORLD"
```

**Decrypt a file using Playfair cipher:**
```bash
cipher_wire --method playfiar -k "SECRET" -f encrypted.txt -o decrypted.txt
```

**Launch the GUI interface:**
```bash
cipher_wire --gui
```

---

## GUI Interface

The GUI provides a simple and intuitive interface for encryption and decryption. Launch the GUI by running:

```bash
cipher_wire --gui
```

From the GUI, you can:
- Choose the encryption method.
- Enter the input text or load a file.
- Specify the key for encryption or decryption.
- Save the results to a file.

---

## Encryption Methods

### Caesar Cipher
A substitution cipher that shifts the characters in the plaintext by a fixed number (key).

### Playfair Cipher
A digraph substitution cipher that uses a 5x5 grid of letters constructed from the key.

---

## Contributing

Contributions are welcome! If you have ideas for additional features or improvements, feel free to open an issue or submit a pull request on the [GitHub repository](https://github.com/your-repo).

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---
