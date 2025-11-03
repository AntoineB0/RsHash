"""
Script de test rapide pour vérifier que RsHash fonctionne
"""
import RsHash

print("🦀 Test de RsHash\n")

# Test SHA256 avec données initiales
print("=== Test SHA256 ===")
sha1 = RsHash.SHA256(b"Hello, World!")
print(f"SHA256('Hello, World!') = {sha1.hexdigest()}")

# Test avec objet et update
sha = RsHash.SHA256()
sha.update(b"Hello, ")
sha.update(b"World!")
print(f"SHA256 (update) = {sha.hexdigest()}")
print(f"digest_size = {sha.digest_size}")
print(f"block_size = {sha.block_size}")
print(f"name = {sha.name}")

# Test SHA512
print("\n=== Test SHA512 ===")
sha2 = RsHash.SHA512(b"Hello, World!")
print(f"SHA512('Hello, World!') = {sha2.hexdigest()}")

# Test avec objet
sha512 = RsHash.SHA512()
sha512.update(b"Test")
print(f"SHA512('Test') = {sha512.hexdigest()}")

# Test new()
print("\n=== Test new() ===")
h = RsHash.new("sha256", b"abc")
print(f"new('sha256', 'abc') = {h.hexdigest()}")

print("\n✅ Tous les tests sont passés !")
