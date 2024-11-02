import time
import tracemalloc
import pandas as pd
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt

# Helper function to measure time and memory usage
def measure_memory_time(func, *args, **kwargs):
    start_time = time.time()
    tracemalloc.start()
    try:
        result = func(*args, **kwargs)
    finally:
        current, peak = tracemalloc.get_traced_memory()  
        tracemalloc.stop()
    end_time = time.time()
    return result, end_time - start_time, current, peak

# RSA Benchmarking
def rsa_benchmark():
    # Key Generation
    rsa_key, rsa_keygen_time, rsa_keygen_mem_current, rsa_keygen_mem_peak = measure_memory_time(RSA.generate, 2048)
    
    # Encryption
    rsa_public_key = rsa_key.publickey()
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    message = os.urandom(128)  # 128-byte random message
    _, rsa_enc_time, rsa_enc_mem_current, rsa_enc_mem_peak = measure_memory_time(cipher_rsa.encrypt, message)

    # Decryption
    cipher_rsa_dec = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher_rsa.encrypt(message)
    _, rsa_dec_time, rsa_dec_mem_current, rsa_dec_mem_peak = measure_memory_time(cipher_rsa_dec.decrypt, encrypted_message)

    return {
        "Algorithm": "RSA",
        "Key Generation Time (s)": rsa_keygen_time,
        "Key Generation Memory Usage (KB)": rsa_keygen_mem_peak / 1024,
        "Encryption Time (s)": rsa_enc_time,
        "Encryption Memory Usage (KB)": rsa_enc_mem_peak / 1024,
        "Decryption Time (s)": rsa_dec_time,
        "Decryption Memory Usage (KB)": rsa_dec_mem_peak / 1024
    }

# Kyber512 Benchmarking
def kyber_benchmark():
    # Key Generation
    (pk, sk), kyber_keygen_time, kyber_keygen_mem_current, kyber_keygen_mem_peak = measure_memory_time(generate_keypair)

    # Encryption
    message = os.urandom(128)  # 128-byte random message
    ciphertext, kyber_enc_result, kyber_enc_time, kyber_enc_mem_current, kyber_enc_mem_peak = measure_memory_time(encrypt, pk)

    # Decryption
    _, kyber_dec_time, kyber_dec_mem_current, kyber_dec_mem_peak = measure_memory_time(decrypt, sk, ciphertext)

    return {
        "Algorithm": "Kyber512",
        "Key Generation Time (s)": kyber_keygen_time,
        "Key Generation Memory Usage (KB)": kyber_keygen_mem_peak / 1024,
        "Encryption Time (s)": kyber_enc_time,
        "Encryption Memory Usage (KB)": kyber_enc_mem_peak / 1024,
        "Decryption Time (s)": kyber_dec_time,
        "Decryption Memory Usage (KB)": kyber_dec_mem_peak / 1024
    }

def benchmark_multiple_iterations(func, iterations=100):
    results = [func() for _ in range(iterations)]
    df = pd.DataFrame(results)
    return df.mean(), df.std()  # Return mean and standard deviation

if __name__ == "__main__":
    # Warm-up iterations
    for _ in range(20):
        rsa_benchmark()
        kyber_benchmark()

    # Benchmark RSA
    rsa_mean_results, rsa_std_results = benchmark_multiple_iterations(rsa_benchmark)
    print("RSA Mean Results:")
    print(rsa_mean_results)
    print("RSA Standard Deviation:")
    print(rsa_std_results)

    # Benchmark Kyber512
    kyber_mean_results, kyber_std_results = benchmark_multiple_iterations(kyber_benchmark)
    print("\nKyber512 Mean Results:")
    print(kyber_mean_results)
    print("Kyber512 Standard Deviation:")
    print(kyber_std_results)
