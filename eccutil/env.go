package eccutil

import (
    "os"
)

func GetenvKey() string {
    return os.Getenv("ECC_KEY")
}

func GetenvPrivateKey() string {
    key := os.Getenv("ECC_PRIVATE_KEY")
    if key == "" {
	key = GetenvKey()
    }
    return key
}

func GetenvPublicKey() string {
    key := os.Getenv("ECC_PUBLIC_KEY")
    if key == "" {
	key = GetenvKey()
    }
    return key
}

func GetenvEncryptKey() string {
    key := os.Getenv("ECC_ENCRYPT_KEY")
    if key == "" {
	key = GetenvPublicKey()
    }
    return key
}
func GetenvSignKey() string {
    key := os.Getenv("ECC_SIGN_KEY")
    if key == "" {
	key = GetenvPrivateKey()
    }
    return key
}

func GetenvDecryptKey() string {
    key := os.Getenv("ECC_DECRYPT_KEY")
    if key == "" {
	key = GetenvPrivateKey()
    }
    return key
}
func GetenvVerifyKey() string {
    key := os.Getenv("ECC_VERIFY_KEY")
    if key == "" {
	key = GetenvPublicKey()
    }
    return key
}

