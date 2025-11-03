"""Tests pour SHA512"""
import hashlib
import pytest


def test_sha512_import():
    """Test que le module peut être importé"""
    try:
        import RsHash
        assert hasattr(RsHash, 'SHA512')
    except ImportError:
        pytest.skip("RsHash not installed - run 'maturin develop' first")


def test_sha512_empty():
    """Test SHA512 avec une chaîne vide"""
    try:
        import RsHash
        expected = hashlib.sha512(b"").hexdigest()
        result = RsHash.SHA512(b"")
        assert result == expected
    except ImportError:
        pytest.skip("RsHash not installed")


def test_sha512_abc():
    """Test SHA512 avec 'abc'"""
    try:
        import RsHash
        expected = hashlib.sha512(b"abc").hexdigest()
        result = RsHash.SHA512(b"abc")
        assert result == expected
    except ImportError:
        pytest.skip("RsHash not installed")


def test_sha512_long():
    """Test SHA512 avec une chaîne longue"""
    try:
        import RsHash
        data = b"a" * 1000
        expected = hashlib.sha512(data).hexdigest()
        result = RsHash.SHA512(data)
        assert result == expected
    except ImportError:
        pytest.skip("RsHash not installed")


def test_sha512_object():
    """Test SHA512 avec l'API objet"""
    try:
        import RsHash
        
        # Test avec hashlib pour comparaison
        h_hashlib = hashlib.sha512()
        h_hashlib.update(b"hello ")
        h_hashlib.update(b"world")
        expected = h_hashlib.hexdigest()
        
        # Test avec RsHash
        h_rshash = RsHash.SHA512()
        h_rshash.update(b"hello ")
        h_rshash.update(b"world")
        result = h_rshash.hexdigest()
        
        assert result == expected
    except ImportError:
        pytest.skip("RsHash not installed")


def test_sha512_properties():
    """Test les propriétés de SHA512"""
    try:
        import RsHash
        hasher = RsHash.SHA512()
        assert hasher.digest_size == 64
        assert hasher.block_size == 128
        assert hasher.name == "sha512"
    except ImportError:
        pytest.skip("RsHash not installed")
