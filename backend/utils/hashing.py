import hashlib


def calculate_sha256(file_data: bytes) -> str:
    return hashlib.sha256(file_data).hexdigest()


def calculate_md5(file_data: bytes) -> str:
    return hashlib.md5(file_data).hexdigest()
