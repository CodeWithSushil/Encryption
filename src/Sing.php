<?php

class DigitalSignature
{
    private $keyPair;
    private $publicKey;
    private $privateKey;

    public function __construct()
    {
        $this->keyPair = sodium_crypto_sign_keypair();
        $this->publicKey = sodium_crypto_sign_publickey($this->keyPair);
        $this->privateKey = sodium_crypto_sign_secretkey($this->keyPair);
    }

    public function sign(string $message): string
    {
        return base64_encode(sodium_crypto_sign($message, $this->privateKey));
    }

    public function verify(string $signedMessage, string $publicKey): string
    {
        $signedMessage = base64_decode($signedMessage);
        $publicKey = base64_decode($publicKey);

        $originalMessage = sodium_crypto_sign_open($signedMessage, $publicKey);

        if ($originalMessage === false) {
            throw new Exception("Invalid signature!");
        }

        return $originalMessage;
    }

    public function getPublicKey(): string
    {
        return base64_encode($this->publicKey);
    }
}

// Example Usage
$signature = new DigitalSignature();
$publicKey = $signature->getPublicKey();
echo "Public Key: " . $publicKey . PHP_EOL;

$message = "Important data";
$signedMessage = $signature->sign($message);
echo "Signed Message: " . $signedMessage . PHP_EOL;

$verifiedMessage = $signature->verify($signedMessage, $publicKey);
echo "Verified Message: " . $verifiedMessage . PHP_EOL;
?>
