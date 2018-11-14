import argon2
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

class VerificationError(Exception):
    '''VerificationError object

    Args:
        message (str) -- The error message.
    '''
    def __init__(self, message):
        super(VerificationError, self).__init__(message)



class CryptCipher(object):
    '''CryptCipher object'''
    def __init__(self):
        self._iterations = 32
        self._memory = 2**10
        self._threads = 4
        self._key_length = 32
        self._random_generator = Random.new()



    def _padding(self, data):
        '''Padding up data to the next multiple of 16.
        Example:
            data = b'hello world' / length = 11 byte
                 = b'hello world\x05\x05\x05\x05\x05' length = 16 byte
        Note:
            If the length of data is zero or a multiple of 16, 16 bytes are
            added.
        Args:
            data (bytes) -- The raw data.
        Returns:
            bytes -- Data with padding bytes.
        '''
        delta = AES.block_size - len(data) % AES.block_size
        data = data + (delta * chr(delta)).encode()
        return data



    def _unpadding(self, data):
        '''Removing the padding bytes from data.
        Args:
            data (bytes) -- The data with padding bytes.
        Returns:
            bytes -- The raw data.
        '''
        delta = data[len(data) - 1]
        return data[:-delta]



    def _substr(self, data, byte):
        '''Splits data in two substrings whereas s_1 has a length of `byte`.

        Helper method to simplify decryption of data.

        Example:
            data = 'hello world'; byte = 5
                   ('hello', ' world')
        Args:
            data (bytes) -- The data to split.
            byte (int) --  Length of first substring.
        Returns:
            (bytes, bytes) -- first substring, second substring
        '''
        d1 = data[:byte]
        d2 = data[byte:]
        return (d1,d2)



    def _encrypt(self, plaintext, key):
        '''Encrypts plaintext.

        Helper method to simplify encryption of data. Besides the encryption,
        the necessary resources (salt, derived key, iv) are generated.

        Args:
            plaintext (bytes) -- The plaintext to encrypt.
            key (str) -- The key to encrypt the plaintext with.
        Returns:
            (bytes, bytes, bytes) -- (The encrypted ciphertext, 
                                      The initialization vector used for
                                      encryption,
                                      The salt used for key derivation)
        '''
        # salt for key derivation function
        salt = self._random_generator.read(self._key_length)

        # derive key to 32 byte
        key_derived = argon2.argon2_hash(key, salt,
                                      self._iterations, self._memory,
                                      self._threads, self._key_length)

        # random initialization vector for aes cipher
        iv = self._random_generator.read(AES.block_size)

        # encrypt plaintext
        cipher = AES.new(key_derived, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(plaintext)

        return (ciphertext, iv, salt)



    def encrypt(self, data, key):
        '''Encrypts data with the key.

        Encrypts data with AES256. To increase the security, argon2 is used for
        key derivation and an encrypted hash is added to verify the integrity
        of the encrypted data.
        Structure of return data:
            Initialization Vector for hash encryption   -- 16 byte
            Salt for key derivation for hash encryption -- 32 byte
            Encrypted hash of the following three parts -- 32 byte
            Initialization Vector for data encryption   -- 16 byte
            Salt for key derivation for data encryption -- 32 byte
            Encrypted data                              -- 16 byte * N (N >= 1)

        Note:
            The key is derived to a size of 32 bytes. Nevertheless, your key
            should have a minimum size of 8 to 16 bytes.
        Args:
            data (str) -- The data to encrypt.
            key (str) -- The key to encrypt the data with.
        Returns:
            bytes: Encrypted data.
        Raises:
            ValueError: If `data` or 'key' is not of type string.
        '''
        if type(data) is not str:
            raise ValueError('data must be of type str')
        elif type(key) is not str:
            raise ValueError('key must be of type str')

        # step 1 - preprocess plaintext
        data = data.encode()
        data = self._padding(data)

        # step 2 - encrypt data
        ciphertext, iv, salt = self._encrypt(data, key)
        data_encrypted = iv + salt + ciphertext

        # step 3 - hash encrypted data
        sha = SHA256.new(data_encrypted)
        hash_plain = sha.digest()

        # step 4 - encrypt hash with a new iv, key pair
        hash_encrypted, iv, salt = self._encrypt(hash_plain, key)
        data_encrypted = iv + salt + hash_encrypted + data_encrypted

        return data_encrypted



    def _decrypt(self, ciphertext, key, iv, salt):
        '''Decrypts ciphertext.

        Helper method to simplify decryption of data.

        Args:
            ciphertext (bytes) -- The ciphertext to encrypt.
            key (str) -- The key used to encrypt the plaintext.
            iv (bytes) -- The iv used to encrypt the plaintext.
            salt (bytes) -- The salt used for key derivation.
        Returns:
            bytes -- The decrypted ciphertext (plaintext).
        '''
        # derive key to 32 byte
        key_derived = argon2.argon2_hash(key, salt,
                                      self._iterations, self._memory,
                                      self._threads, self._key_length)

        # decrypt ciphertext
        cipher = AES.new(key_derived, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)

        return plaintext



    def decrypt(self, data, key):
        '''Decrypts data with the key used for the encryption.

        Structure of data:
            Initialization Vector for hash encryption   -- 16 byte
            Salt for key derivation for hash encryption -- 32 byte
            Encrypted hash of the following three parts -- 32 byte
            Initialization Vector for data encryption   -- 16 byte
            Salt for key derivation for data encryption -- 32 byte
            Encrypted data                              -- 16 byte * N (N >= 1)

        Note:
            Only when the data integrity has been verified, the data is
            encrypted.
        Args:
            data (bytes) -- The data to decrypt.
            key (str) -- The key to decrypt the data with.
        Returns:
            str: Decrypted data.
        Raises:
            ValueError: If `data` is not of type bytes or does not have a
                        minimum length of 144 bytes. If `key` is not of type
                        string.
            VerificationError: If the integrity of `data` could not be
                               verified.
        '''
        if type(data) is not bytes:
            raise ValueError('data must be of type bytes')
        if len(data) < 144:
            raise ValueError('data must have a minimum length of 144 bytes')
        elif type(key) is not str:
            raise ValueError('key must be of type str')

        # step 1 - decrypt hash and verify hash

        # iv (16 bit) for hash decryption [0, 16]
        iv, data = self._substr(data, AES.block_size)
        # salt (32 bit) for hash decryption [16, 48]
        salt, data = self._substr(data, self._key_length)
        # encrypted hash (32 bit) [48, 80]
        hash_encrypted, data = self._substr(data, SHA256.digest_size)
        # encrypted data (64 bit +)
        data_encrypted = data

        hash_decrypted = self._decrypt(hash_encrypted, key, iv, salt)
        sha = SHA256.new(data_encrypted)
        hash_clear = sha.digest()
        if hash_decrypted != hash_clear:
            raise VerificationError(
                'integrity of encrypted data could not be verified')

        # step 2 - decrypt ciphertext

        # iv (16 bit) for ciphertext decryption [80, 96]
        iv, data_encrypted = self._substr(data_encrypted, AES.block_size)
        # salt (32 bit) for ciphertext decryption [96, 128]
        salt, data_encrypted = self._substr(data_encrypted, self._key_length)
        # ciphertext [128, n]
        ciphertext = data_encrypted

        data = self._decrypt(ciphertext, key, iv, salt)

        # step 3 - post process data
        data = self._unpadding(data)
        data = data.decode()

        return data

