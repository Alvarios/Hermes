# -*- coding: utf-8 -*-
"""Implementation of a security utils for hermes project.

    Copyright (C) 2020  Clement Dulouard

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

Also add information on how to contact you by electronic and paper mail.

  If your software can interact with users remotely through a computer
network, you should also make sure that it provides a way for users to
get its source.  For example, if your program is a web application, its
interface could display a "Source" link that leads users to an archive
of the code.  There are many ways you could offer source, and different
solutions will be better for different programs; see section 13 for the
specific requirements.

  You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary.
For more information on this, and how to apply and follow the GNU AGPL, see
<https://www.gnu.org/licenses/>.
"""

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey, AlreadyFinalized
from typing import Optional, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os


def verify_password_scrypt(password_to_verify: bytes, derived_password: bytes, password_salt: bytes):
    """Check if the input password correspond to the instance derived password and salt.

    :param password_to_verify: The password to verify as bytes.
    :param derived_password: The derived password used to verify the given password as bytes.
    :param password_salt: The salt used to derive the password as bytes.

    :return: True if is verified, else False.
    """
    password_correct = False
    kdf = Scrypt(
        salt=password_salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    try:
        kdf.verify(password_to_verify, derived_password)
        password_correct = True
    except InvalidKey:
        pass
    except AlreadyFinalized:
        pass
    return password_correct


def derive_password_scrypt(password_to_derive: bytes, password_salt: bytes) -> bytes:
    """Derive a password using scrypt algorithm.

    :param password_to_derive: The password to derive as bytes.
    :param password_salt: The salt (extra random bytes to add noise) to use for password derivation.

    :return: The derived password as bytes.
    """
    kdf = Scrypt(
        salt=password_salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    return kdf.derive(password_to_derive)


def derive_key_hkdf(key: bytes, length: Optional[int] = 32, salt: Optional[Union[None, bytes]] = None,
                    info: Optional[Union[None, bytes]] = None, algorithm=hashes.SHA3_256()) -> bytes:
    """Return a derived key from the inputs of a given length using HKDF algorithm.

    :param key: The key to derive.
    :param length: The length of the output.
    :param salt:  A salt. Randomizes the KDF’s output. Optional, but highly recommended. Ideally as many bits of entropy
     as the security level of the hash: often that means cryptographically random and as long as the hash output.
     Worse (shorter, less entropy) salt values can still meaningfully contribute to security. May be reused.
     Does not have to be secret, but may cause stronger security guarantees if secret; see RFC 5869 and the HKDF paper
     for more details. If None is explicitly passed a default salt of algorithm.digest_size // 8 null bytes will
     be used.
    :param info: Application specific context information. If None is explicitly passed an empty byte string
    will be used.
    :param algorithm: An instance of HashAlgorithm.

    :return: A derived key of given length as bytes.
    """
    return HKDF(algorithm=algorithm, length=length, salt=salt, info=info, ).derive(key)


def generate_key_32(key: Optional[Union[bytes, None]] = None) -> bytes:
    """Generate a 32 bytes key that can be used for encryption.

    :param key: An optional key that can be used for key derivation.

    :return: A key of 32 bytes.
    """
    if key is not None:
        return derive_key_hkdf(key)
    return os.urandom(32)
