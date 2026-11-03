from app.privacy import device_fingerprint, hmac_hex, mask_ip, sanitize_metadata


def test_device_fingerprint_is_stable_hash_of_ua_and_ip():
    a = device_fingerprint("Mozilla/5.0", "10.0.1.12")
    b = device_fingerprint("Mozilla/5.0", "10.0.1.12")
    c = device_fingerprint("Mozilla/5.0", "10.0.1.13")
    assert a == b
    assert a != c
    assert len(a) == 64


def test_hmac_is_deterministic_and_not_plaintext():
    secret = "unit-test-secret"
    digest = hmac_hex("10.0.1.12", secret)
    assert digest == hmac_hex("10.0.1.12", secret)
    assert "10.0.1.12" not in digest


def test_mask_ip_drops_last_octet():
    assert mask_ip("185.220.101.4") == "185.220.101.0/24"


def test_sanitize_metadata_strips_secrets():
    cleaned = sanitize_metadata(
        {
            "username": "j.mehta",
            "password": "correct",
            "token": "abc",
            "nested": {"authorization": "Bearer xyz", "camera_id": "CAM-014"},
        }
    )
    assert cleaned["username"] == "j.mehta"
    assert "password" not in cleaned
    assert "token" not in cleaned
    assert "authorization" not in cleaned["nested"]
    assert cleaned["nested"]["camera_id"] == "CAM-014"
