# Shamir Secret Sharing and Resharing

This project implements a Shamir secret sharing and resharing scheme in Python.
The shares are genered in a prime field.

## Features

- Generate shares.
- Reconstruct the secret
- Reshare the secret
- Change n,t config while retaining the shared secret.

## Installation

To install the required dependencies, run:

```bash
pip install -r requirements.txt
```

## Usage

### Splitting a Secret

To split a secret into shares:

```python
    test_secret = Integer("156402071732811106507596152138279689577457410967997136623970051482223809533794")
    test_prime = Integer("208351617316091241234326746312124448251235562226470491514186331217050270460481")

    secret_sharing = SecretSharing(SharingBuilder(test_secret, 5, 10, test_prime, seed=42))
    secret_sharing.display()
```

### Reconstructing a Secret

To reconstruct the secret from shares:

```python
    secret_sharing = SecretSharing(SharingBuilder(test_secret, 5, 10, test_prime, seed=42))
    secret_sharing.display()
    reconstructed_secret = secret_sharing.reconstruct_secret()
    assert reconstructed_secret == test_secret

    # reconstructing for just the minimal threshold
    selected_shares = secret_sharing.select_threshold_shares()
    selected_shares.display()
    reconstructed_secret_from_threshold = selected_shares.reconstruct_secret()
```

### Resharing

To reshare the secret shares

```python
secret_sharing = SecretSharing(SharingBuilder(test_secret, 5, 10, test_prime, seed=42))
#  retain n & t but get a new sharing by changing the seed
reshared_sharing = secret_sharing.reshare_shares(5,10, seed=53)
#  alternatively change n & t
reshared_sharing = secret_sharing.reshare_shares(5,10, seed=53)
reshared_sharing.display()
reshared_reconstructed_secret = reshared_sharing.reconstruct_secret()
assert reshared_reconstructed_secret == test_secret
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file
for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Contact

For any questions or suggestions, please contact
[faraz.shaikh@gmail.com](mailto:faraz.shaikh@gmail.com).
