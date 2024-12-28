<?php

class PasswordManager
{
    public function hashPassword(string $password): string
    {
        return sodium_crypto_pwhash_str(
            $password,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
    }

    public function verifyPassword(string $hashedPassword, string $password): bool
    {
        return sodium_crypto_pwhash_str_verify($hashedPassword, $password);
    }
}

// Example Usage
$passwordManager = new PasswordManager();
$hashedPassword = $passwordManager->hashPassword("secure_password");
echo "Hashed Password: " . $hashedPassword . PHP_EOL;

$isVerified = $passwordManager->verifyPassword($hashedPassword, "secure_password");
echo "Password Verified: " . ($isVerified ? "Yes" : "No") . PHP_EOL;
?>
