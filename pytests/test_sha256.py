"""Tests pour SHA256"""
import hashlib
import pytest


def test_sha256_import():
    """Test que le module peut être importé"""
    try:
        import RsHash
        assert hasattr(RsHash, 'SHA256')
    except ImportError:
        pytest.skip("RsHash not installed - run 'maturin develop' first")


def test_sha256_empty():
    """Test SHA256 avec une chaîne vide"""
    try:
        import RsHash
        expected = hashlib.sha256(b"").hexdigest()
        result = RsHash.SHA256(b"")
        assert result == expected
    except ImportError:
        pytest.skip("RsHash not installed")


def test_sha256_abc():
    """Test SHA256 avec 'abc'"""
    try:
        import RsHash
        expected = hashlib.sha256(b"abc").hexdigest()
        result = RsHash.SHA256(b"abc")
        assert result == expected
    except ImportError:
        pytest.skip("RsHash not installed")


def test_sha256_long():
    """Test SHA256 avec une chaîne longue"""
    try:
        import RsHash
        data = b"a" * 1000
        expected = hashlib.sha256(data).hexdigest()
        result = RsHash.SHA256(data)
        assert result == expected
    except ImportError:
        pytest.skip("RsHash not installed")


def test_sha256_object():
    """Test SHA256 avec l'API objet"""
    try:
        import RsHash
        
        # Test avec hashlib pour comparaison
        h_hashlib = hashlib.sha256()
        h_hashlib.update(b"hello ")
        h_hashlib.update(b"world")
        expected = h_hashlib.hexdigest()
        
        # Test avec RsHash
        h_rshash = RsHash.SHA256()
        h_rshash.update(b"hello ")
        h_rshash.update(b"world")
        result = h_rshash.hexdigest()
        
        assert result == expected
    except ImportError:
        pytest.skip("RsHash not installed")


def test_sha256_properties():
    """Test les propriétés de SHA256"""
    try:
        import RsHash
        hasher = RsHash.SHA256()
        assert hasher.digest_size == 32
        assert hasher.block_size == 64
        assert hasher.name == "sha256"
    except ImportError:
        pytest.skip("RsHash not installed")
