import gmpy2
from gmpy2 import mpz
import numpy as np
import random
import re

ALPHABET_SIZE = 26
A_UPPERCASE = ord('A')
bit_count = 64

def _decompose(number):
    """Generate digits from `number` in base alphabet, most significant
    bits first.
    """
    number -= 1  # Account for A in base alphabet being 1 in decimal rather than 0
    if number < ALPHABET_SIZE:
        yield number
    else:
        number, remainder = divmod(number, ALPHABET_SIZE)
        yield from _decompose(number)
        yield remainder


def base_10_to_alphabet(number):
    """Convert a decimal number to its base alphabet representation"""
    return ''.join(
        chr(A_UPPERCASE + part)
        for part in _decompose(number)
    )


def base_alphabet_to_10(letters):
    """Convert an alphabet number to its decimal representation"""

    return sum(
        (ord(letter) - A_UPPERCASE + 1) * ALPHABET_SIZE ** i
        for i, letter in enumerate(reversed(letters.upper()))
    )


def read_input(file_name: str) -> str:
    f = open(file_name, "r")
    data = f.read()
    f.close()
    return data


def write_output(data: str, name: str) -> None:
    f = open(name, "w")
    f.write(data)
    f.close()


def encrypt_using_vigenere(data: str, key: str, key_len: int) -> str:
    vigenere_cipher = []
    for i in range(len(data)):
        letter = (ord(data[i]) + ord(key[i % key_len])) % 26
        vigenere_cipher.append(chr(letter + ord('A')))
    return "".join(vigenere_cipher)


def decrypt_using_vigenere(cipher: str, key: str, key_len: int) -> str:
    plain_text = []
    for i in range(len(cipher)):
        letter = (ord(cipher[i]) - ord(key[i % key_len])) % 26
        plain_text.append(chr(letter + ord('A')))
    return "".join(plain_text)


def rabin_miller(num):
    # Returns True if num is a prime number.

    s = num - 1
    t = 0
    while s % 2 == 0:
        # keep halving s while it is even (and use t
        # to count how many times we halve s)
        s = s // 2
        t += 1

    for trials in range(5): # try to falsify num's primality 5 times
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1: # this test does not apply if v is 1.
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True


def is_prime(num):
    # Return True if num is a prime number. This function does a quicker
    # prime number check before calling rabinMiller().

    if num < 2:
        return False # 0, 1, and negative numbers are not prime

    # About 1/3 of the time we can quickly determine if num is not prime
    # by dividing by the first few dozen prime numbers. This is quicker
    # than rabinMiller(), but unlike rabinMiller() is not guaranteed to
    # prove that a number is prime.
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
                 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
                 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
                 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
                 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577,
                 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
                 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
                 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
                 991, 997]

    if num in lowPrimes:
        return True

    # See if any of the low prime numbers can divide num
    for prime in lowPrimes:
        if (num % prime == 0):
            return False

    # If all else fails, call rabinMiller() to determine if num is a prime.
    return rabinMiller(num)


def generate_large_prime(keysize: int = bit_count):
    # Return a random prime number of keysize bits in size.
    while True:
        num = random.randrange(2**(keysize-1), 2**(keysize))
        if isPrime(num):
            return num


def generate_prime(bit_count: int, rand_state: int) -> int:
    # temp = 0
    temp = gmpy2.mpz_rrandomb(rand_state, bit_count)
    while not gmpy2.is_bpsw_prp(temp):  # Strong Prime Check
        temp = gmpy2.mpz_rrandomb(rand_state, bit_count)
    return temp
    # return gmpy2.next_prime(temp)


def good_pair(p: int, q: int) -> int:
    n = p * q
    k = gmpy2.ceil(gmpy2.log2(n))
    if abs(p - q) > 2 ** (k / 2 - 100):
        return n
    return 0


def generate_keypair(seed: int):
    rand_state = seed
    # m = bytes_to_long(input.encode('utf-8'))

    p, q = generate_prime(bit_count, rand_state), generate_prime(bit_count, rand_state)
    flag = good_pair(p, q)
    while not flag:
        p, q = generate_prime(bit_count, rand_state), generate_prime(bit_count, rand_state)
        flag = good_pair(p, q)

    n = gmpy2.mul(p, q)
    phi = gmpy2.mul(p - 1, q - 1)

    # print("p:", p)
    # print("q:", q)
    print("n:", n)
    # print("phi:", phi)

    e = gmpy2.mpz_random(rand_state, phi)
    while e <= 1 or gmpy2.gcd(e, phi) != 1:
        e = gmpy2.mpz_random(rand_state, phi)

    assert (e > 1)
    assert (gmpy2.gcd(e, phi) == 1)

    d = gmpy2.invert(e, phi)
    assert (d != 1)
    assert (gmpy2.t_mod(e * d, phi) == 1)

    # print("PK(e):", e)
    # print("SK(d):", d)

    return {
        'public': {
            'n': n,
            'e': e,
        },
        'private': {
            'n': n,
            'd': d,
        }
    }


def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))


def encrypt_and_recover(tuple_data: str, vigenere_key_len: int):
    str_list = list(chunkstring(tuple_data, vigenere_key_len))
    count = 0
    rec_vig_key, rec_m = "", ""
    for chunk in str_list:
        count += 1
        m = base_alphabet_to_10(chunk)
        # m = base_alphabet_to_10(vigenere_key)
        # print(f"m is {m}")

        """ Encryption by user A """
        A_decrypt_data = gmpy2.powmod(m, RSA_key_A['private']['d'], RSA_key_A['private']['n'])
        A_encrypt_data = gmpy2.powmod(A_decrypt_data, RSA_key_B['public']['e'], RSA_key_B['public']['n'])

        """ Decryption by user B """
        B_decrypt_data = gmpy2.powmod(A_encrypt_data, RSA_key_B['private']['d'], RSA_key_B['private']['n'])
        B_encrypt_data = gmpy2.powmod(B_decrypt_data, RSA_key_A['public']['e'], RSA_key_A['public']['n'])

        """ Recover message """
        rec_chunk = base_10_to_alphabet(B_encrypt_data)

        # print(rec_chunk)

        if count == 1:
            rec_vig_key = rec_chunk
            continue

        rec_m += rec_chunk

    rec_data = decrypt_using_vigenere(rec_m, rec_vig_key, vigenere_key_len)
    return rec_data, rec_vig_key
    # assert rec_data == data


if __name__ == '__main__':
    input_data = read_input("message.txt")
    data = re.sub(r'[^a-zA-Z ]', '', input_data).upper()  # convert plaintext to uppercase, Remove all non
    # alphabetical characters
    data = ''.join(data.split())  # Remove all whitespaces
    print(data)
    
    """ VINEGERE PART """
    vigenere_key = "FORTIFICATION"
    vigenere_key_len = len(vigenere_key)
    vigenere_encrypted_data = encrypt_using_vigenere(data, vigenere_key, vigenere_key_len)
    # print(vigenere_encrypted_data)
    plain_text = decrypt_using_vigenere(vigenere_encrypted_data, vigenere_key, vigenere_key_len)
    print(plain_text)

    """  RSA PART  """
    seed = gmpy2.random_state(42)
    RSA_key_A = generate_keypair(seed)
    seed = gmpy2.random_state(24)
    RSA_key_B = generate_keypair(seed)
    tuple_data = vigenere_key + vigenere_encrypted_data
    rec_data, rec_vig_key = encrypt_and_recover(tuple_data, vigenere_key_len)

    # print(tuple_data)

    assert rec_data == data
    assert rec_vig_key == vigenere_key