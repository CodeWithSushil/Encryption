<?php

class Cryptography
{
    private $key;

    public function __construct()
    {
        // Generate a key once; ideally, this should be stored securely (e.g., in an environment variable).
        $this->key = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    public function encrypt(string $message): array
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES); // Generate a nonce
        $ciphertext = sodium_crypto_secretbox($message, $nonce, $this->key);

        // Return ciphertext and nonce for decryption
        return [
            'nonce' => base64_encode($nonce),
            'ciphertext' => base64_encode($ciphertext),
        ];
    }

    public function decrypt(string $ciphertext, string $nonce): string
    {
        $ciphertext = base64_decode($ciphertext);
        $nonce = base64_decode($nonce);

        $decrypted = sodium_crypto_secretbox_open($ciphertext, $nonce, $this->key);

        if ($decrypted === false) {
            throw new Exception("Decryption failed!");
        }

        return $decrypted;
    }
}

// Example Usage
$crypto = new Cryptography();
$encrypted = $crypto->encrypt("This is a secret message");
echo "Encrypted: " . json_encode($encrypted) . PHP_EOL;

$decrypted = $crypto->decrypt($encrypted['ciphertext'], $encrypted['nonce']);
echo "Decrypted: " . $decrypted . PHP_EOL;
?>
