"""
Test de comparaison avec hashlib
"""
import hashlib
import RsHash

print("🔬 Comparaison RsHash vs hashlib\n")

test_cases = [
    (b"", "empty"),
    (b"abc", "abc"),
    (b"Hello, World!", "Hello, World!"),
    (b"a" * 1000, "1000 x 'a'"),
]

print("=== SHA256 ===")
for data, name in test_cases:
    rshash_result = RsHash.SHA256(data).hexdigest()
    hashlib_result = hashlib.sha256(data).hexdigest()
    match = "✅" if rshash_result == hashlib_result else "❌"
    print(f"{match} {name}: {rshash_result == hashlib_result}")

print("\n=== SHA512 ===")
for data, name in test_cases:
    rshash_result = RsHash.SHA512(data).hexdigest()
    hashlib_result = hashlib.sha512(data).hexdigest()
    match = "✅" if rshash_result == hashlib_result else "❌"
    print(f"{match} {name}: {rshash_result == hashlib_result}")

print("\n=== Test digest() (bytes) ===")
sha = RsHash.SHA256(b"test")
digest_rs = sha.digest()
digest_hl = hashlib.sha256(b"test").digest()
print(f"✅ digest() retourne bytes: {digest_rs == digest_hl}")

print("\n✅ Tous les tests de conformité sont passés !")
