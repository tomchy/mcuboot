# Copyright 2018 Nordic Semiconductor ASA
# Copyright 2017-2020 Linaro Limited
# Copyright 2019-2024 Arm Limited
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Image signing and management.
"""

from . import version as versmod
from .boot_record import create_sw_component_data
import click
import copy
from enum import Enum
import array
from intelhex import IntelHex
import hashlib
import array
import os.path
import struct
from enum import Enum

import click
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from intelhex import IntelHex

from . import version as versmod, keys
from .boot_record import create_sw_component_data
from .keys import rsa, ecdsa, x25519

from collections import namedtuple

IMAGE_MAGIC = 0x96f3b83d
IMAGE_HEADER_SIZE = 32
BIN_EXT = "bin"
INTEL_HEX_EXT = "hex"
DEFAULT_MAX_SECTORS = 128
DEFAULT_MAX_ALIGN = 8
DEP_IMAGES_KEY = "images"
DEP_VERSIONS_KEY = "versions"
MAX_SW_TYPE_LENGTH = 12  # Bytes

# Image header flags.
IMAGE_F = {
        'PIC':                   0x0000001,
        'ENCRYPTED_AES128':      0x0000004,
        'ENCRYPTED_AES256':      0x0000008,
        'NON_BOOTABLE':          0x0000010,
        'RAM_LOAD':              0x0000020,
        'ROM_FIXED':             0x0000100,
        'COMPRESSED_LZMA1':      0x0000200,
        'COMPRESSED_LZMA2':      0x0000400,
        'COMPRESSED_ARM_THUMB':  0x0000800,
}

TLV_VALUES = {
        'KEYHASH': 0x01,
        'PUBKEY': 0x02,
        'SHA256': 0x10,
        'SHA384': 0x11,
        'SHA512': 0x12,
        'RSA2048': 0x20,
        'ECDSASIG': 0x22,
        'RSA3072': 0x23,
        'ED25519': 0x24,
        'SIG_PURE': 0x25,
        'ENCRSA2048': 0x30,
        'ENCKW': 0x31,
        'ENCEC256': 0x32,
        'ENCX25519': 0x33,
        'ENCX25519_SHA512': 0x34,
        'DEPENDENCY': 0x40,
        'SEC_CNT': 0x50,
        'BOOT_RECORD': 0x60,
        'DECOMP_SIZE': 0x70,
        'DECOMP_SHA': 0x71,
        'DECOMP_SIGNATURE': 0x72,
        'COMP_DEC_SIZE' : 0x73,
}

TLV_SIZE = 4
TLV_INFO_SIZE = 4
TLV_INFO_MAGIC = 0x6907
TLV_PROT_INFO_MAGIC = 0x6908

TLV_VENDOR_RES_MIN = 0x00a0
TLV_VENDOR_RES_MAX = 0xfffe

STRUCT_ENDIAN_DICT = {
        'little': '<',
        'big':    '>'
}

VerifyResult = Enum('VerifyResult',
                    ['OK', 'INVALID_MAGIC', 'INVALID_TLV_INFO_MAGIC', 'INVALID_HASH', 'INVALID_SIGNATURE',
                     'KEY_MISMATCH'])


def align_up(num, align):
    assert (align & (align - 1) == 0) and align != 0
    return (num + (align - 1)) & ~(align - 1)


class TLV():
    def __init__(self, endian, magic=TLV_INFO_MAGIC):
        self.magic = magic
        self.buf = bytearray()
        self.endian = endian

    def __len__(self):
        return TLV_INFO_SIZE + len(self.buf)

    def add(self, kind, payload):
        """
        Add a TLV record.  Kind should be a string found in TLV_VALUES above.
        """
        e = STRUCT_ENDIAN_DICT[self.endian]
        if isinstance(kind, int):
            if not TLV_VENDOR_RES_MIN <= kind <= TLV_VENDOR_RES_MAX:
                msg = "Invalid custom TLV type value '0x{:04x}', allowed " \
                      "value should be between 0x{:04x} and 0x{:04x}".format(
                        kind, TLV_VENDOR_RES_MIN, TLV_VENDOR_RES_MAX)
                raise click.UsageError(msg)
            buf = struct.pack(e + 'HH', kind, len(payload))
        else:
            buf = struct.pack(e + 'BBH', TLV_VALUES[kind], 0, len(payload))
        self.buf += buf
        self.buf += payload

    def get(self):
        if len(self.buf) == 0:
            return bytes()
        e = STRUCT_ENDIAN_DICT[self.endian]
        header = struct.pack(e + 'HH', self.magic, len(self))
        return header + bytes(self.buf)


SHAAndAlgT = namedtuple('SHAAndAlgT', ['sha', 'alg'])

TLV_SHA_TO_SHA_AND_ALG = {
    TLV_VALUES['SHA256'] : SHAAndAlgT('256', hashlib.sha256),
    TLV_VALUES['SHA384'] : SHAAndAlgT('384', hashlib.sha384),
    TLV_VALUES['SHA512'] : SHAAndAlgT('512', hashlib.sha512),
}


USER_SHA_TO_ALG_AND_TLV = {
    'auto'   : (hashlib.sha256, 'SHA256'),
    '256'    : (hashlib.sha256, 'SHA256'),
    '384'    : (hashlib.sha384, 'SHA384'),
    '512'    : (hashlib.sha512, 'SHA512')
}


def is_sha_tlv(tlv):
    return tlv in TLV_SHA_TO_SHA_AND_ALG.keys()


def tlv_sha_to_sha(tlv):
    return TLV_SHA_TO_SHA_AND_ALG[tlv].sha


# Auto selecting hash algorithm for type(key)
ALLOWED_KEY_SHA = {
    keys.ECDSA384P1         : ['384'],
    keys.ECDSA384P1Public   : ['384'],
    keys.ECDSA256P1         : ['256'],
    keys.ECDSA256P1Public   : ['256'],
    keys.RSA                : ['256'],
    keys.RSAPublic          : ['256'],
    # This two are set to 256 for compatibility, the right would be 512
    keys.Ed25519            : ['256', '512'],
    keys.X25519             : ['256', '512']
}

ALLOWED_PURE_KEY_SHA = {
    keys.Ed25519            : ['512']
}

ALLOWED_PURE_SIG_TLVS = [
    TLV_VALUES['ED25519']
]

def key_and_user_sha_to_alg_and_tlv(key, user_sha, is_pure = False):
    """Matches key and user requested sha to sha alogrithm and TLV name.

       The returned tuple will contain hash functions and TVL name.
       The function is designed to succeed or completely fail execution,
       as providing incorrect pair here basically prevents doing
       any more work.
    """
    if key is None:
        # If key is none, we allow whatever user has selected for sha
        return USER_SHA_TO_ALG_AND_TLV[user_sha]

    # If key is not None, then we have to filter hash to only allowed
    allowed = None
    allowed_key_ssh = ALLOWED_PURE_KEY_SHA if is_pure else ALLOWED_KEY_SHA
    try:
        allowed = allowed_key_ssh[type(key)]

    except KeyError:
        raise click.UsageError("Colud not find allowed hash algorithms for {}"
                               .format(type(key)))

    # Pure enforces auto, and user selection is ignored
    if user_sha == 'auto' or is_pure:
        return USER_SHA_TO_ALG_AND_TLV[allowed[0]]

    if user_sha in allowed:
        return USER_SHA_TO_ALG_AND_TLV[user_sha]

    raise click.UsageError("Key {} can not be used with --sha {}; allowed sha are one of {}"
                           .format(key.sig_type(), user_sha, allowed))


def get_digest(tlv_type, hash_region):
    sha = TLV_SHA_TO_SHA_AND_ALG[tlv_type].alg()

    sha.update(hash_region)
    return sha.digest()


def tlv_matches_key_type(tlv_type, key):
    """Check if provided key matches to TLV record in the image"""
    try:
        # We do not need the result here, and the key_and_user_sha_to_alg_and_tlv
        # will either succeed finding match or rise exception, so on success we
        # return True, on exception we return False.
        _, _ = key_and_user_sha_to_alg_and_tlv(key, tlv_sha_to_sha(tlv_type))
        return True
    except:
        pass

    return False


class Image:

    def __init__(self, version=None, header_size=IMAGE_HEADER_SIZE,
                 pad_header=False, pad=False, confirm=False, align=1,
                 slot_size=0, max_sectors=DEFAULT_MAX_SECTORS,
                 overwrite_only=False, endian="little", load_addr=0,
                 rom_fixed=None, erased_val=None, save_enctlv=False,
                 security_counter=None, max_align=None,
                 non_bootable=False):

        if load_addr and rom_fixed:
            raise click.UsageError("Can not set rom_fixed and load_addr at the same time")

        self.image_hash = None
        self.image_size = None
        self.signature = None
        self.version = version or versmod.decode_version("0")
        self.header_size = header_size
        self.pad_header = pad_header
        self.pad = pad
        self.confirm = confirm
        self.align = align
        self.slot_size = slot_size
        self.max_sectors = max_sectors
        self.overwrite_only = overwrite_only
        self.endian = endian
        self.base_addr = None
        self.load_addr = 0 if load_addr is None else load_addr
        self.rom_fixed = rom_fixed
        self.erased_val = 0xff if erased_val is None else int(erased_val, 0)
        self.payload = []
        self.infile_data = []
        self.enckey = None
        self.save_enctlv = save_enctlv
        self.enctlv_len = 0
        self.max_align = max(DEFAULT_MAX_ALIGN, align) if max_align is None else int(max_align)
        self.non_bootable = non_bootable

        if self.max_align == DEFAULT_MAX_ALIGN:
            self.boot_magic = bytes([
                0x77, 0xc2, 0x95, 0xf3,
                0x60, 0xd2, 0xef, 0x7f,
                0x35, 0x52, 0x50, 0x0f,
                0x2c, 0xb6, 0x79, 0x80, ])
        else:
            lsb = self.max_align & 0x00ff
            msb = (self.max_align & 0xff00) >> 8
            align = bytes([msb, lsb]) if self.endian == "big" else bytes([lsb, msb])
            self.boot_magic = align + bytes([0x2d, 0xe1,
                                             0x5d, 0x29, 0x41, 0x0b,
                                             0x8d, 0x77, 0x67, 0x9c,
                                             0x11, 0x0f, 0x1f, 0x8a, ])

        if security_counter == 'auto':
            # Security counter has not been explicitly provided,
            # generate it from the version number
            self.security_counter = ((self.version.major << 24)
                                     + (self.version.minor << 16)
                                     + self.version.revision)
        else:
            self.security_counter = security_counter

    def __repr__(self):
        return "<Image version={}, header_size={}, security_counter={}, \
                base_addr={}, load_addr={}, align={}, slot_size={}, \
                max_sectors={}, overwrite_only={}, endian={} format={}, \
                payloadlen=0x{:x}>".format(
                    self.version,
                    self.header_size,
                    self.security_counter,
                    self.base_addr if self.base_addr is not None else "N/A",
                    self.load_addr,
                    self.align,
                    self.slot_size,
                    self.max_sectors,
                    self.overwrite_only,
                    self.endian,
                    self.__class__.__name__,
                    len(self.payload))

    def load(self, path):
        """Load an image from a given file"""
        ext = os.path.splitext(path)[1][1:].lower()
        try:
            if ext == INTEL_HEX_EXT:
                ih = IntelHex(path)
                self.infile_data = ih.tobinarray()
                self.payload = copy.copy(self.infile_data)
                self.base_addr = ih.minaddr()
            else:
                with open(path, 'rb') as f:
                    self.infile_data = f.read()
                    self.payload = copy.copy(self.infile_data)
        except FileNotFoundError:
            raise click.UsageError("Input file not found")

        # Add the image header if needed.
        if self.pad_header and self.header_size > 0:
            if self.base_addr:
                # Adjust base_addr for new header
                self.base_addr -= self.header_size
            self.payload = bytes([self.erased_val] * self.header_size) + \
                self.payload

        self.image_size = len(self.payload) - self.header_size

        self.check_header()

    def load_compressed(self, data, compression_header):
        """Load an image from buffer"""
        self.payload = compression_header + data
        self.image_size = len(self.payload)

        # Add the image header if needed.
        if self.header_size > 0:
            if self.pad_header:
                if self.base_addr:
                    # Adjust base_addr for new header
                    self.base_addr -= self.header_size
                self.payload = bytes([self.erased_val] * self.header_size) + \
                    self.payload
            else:
                # Fill header padding with zeros to align with what is expected
                # for uncompressed images when no pad_header is requested
                # (see self.check_header())
                self.payload = bytes([0] * self.header_size) + \
                    self.payload

    def save(self, path, hex_addr=None):
        """Save an image from a given file"""
        ext = os.path.splitext(path)[1][1:].lower()
        if ext == INTEL_HEX_EXT:
            # input was in binary format, but HEX needs to know the base addr
            if self.base_addr is None and hex_addr is None:
                raise click.UsageError("No address exists in input file "
                                       "neither was it provided by user")
            h = IntelHex()
            if hex_addr is not None:
                self.base_addr = hex_addr
            h.frombytes(bytes=self.payload, offset=self.base_addr)
            if self.pad:
                trailer_size = self._trailer_size(self.align, self.max_sectors,
                                                  self.overwrite_only,
                                                  self.enckey,
                                                  self.save_enctlv,
                                                  self.enctlv_len)
                trailer_addr = (self.base_addr + self.slot_size) - trailer_size
                if self.confirm and not self.overwrite_only:
                    magic_align_size = align_up(len(self.boot_magic),
                                                self.max_align)
                    image_ok_idx = -(magic_align_size + self.max_align)
                    flag = bytearray([self.erased_val] * self.max_align)
                    flag[0] = 0x01  # image_ok = 0x01
                    h.puts(trailer_addr + trailer_size + image_ok_idx,
                           bytes(flag))
                h.puts(trailer_addr + (trailer_size - len(self.boot_magic)),
                       bytes(self.boot_magic))
            h.tofile(path, 'hex')
        else:
            if self.pad:
                self.pad_to(self.slot_size)
            with open(path, 'wb') as f:
                f.write(self.payload)

    def check_header(self):
        if self.header_size > 0 and not self.pad_header:
            if any(v != 0 for v in self.payload[0:self.header_size]):
                raise click.UsageError("Header padding was not requested and "
                                       "image does not start with zeros")

    def check_trailer(self):
        if self.slot_size > 0:
            tsize = self._trailer_size(self.align, self.max_sectors,
                                       self.overwrite_only, self.enckey,
                                       self.save_enctlv, self.enctlv_len)
            padding = self.slot_size - (len(self.payload) + tsize)
            if padding < 0:
                msg = "Image size (0x{:x}) + trailer (0x{:x}) exceeds " \
                      "requested size 0x{:x}".format(
                          len(self.payload), tsize, self.slot_size)
                raise click.UsageError(msg)

    def ecies_hkdf(self, enckey, plainkey, hmac_sha_alg):
        if isinstance(enckey, ecdsa.ECDSA256P1Public):
            newpk = ec.generate_private_key(ec.SECP256R1(), default_backend())
            shared = newpk.exchange(ec.ECDH(), enckey._get_public())
        else:
            newpk = X25519PrivateKey.generate()
            shared = newpk.exchange(enckey._get_public())
        derived_key = HKDF(
            algorithm=hmac_sha_alg, length=48, salt=None,
            info=b'MCUBoot_ECIES_v1', backend=default_backend()).derive(shared)
        encryptor = Cipher(algorithms.AES(derived_key[:16]),
                           modes.CTR(bytes([0] * 16)),
                           backend=default_backend()).encryptor()
        cipherkey = encryptor.update(plainkey) + encryptor.finalize()
        mac = hmac.HMAC(derived_key[16:], hmac_sha_alg,
                        backend=default_backend())
        mac.update(cipherkey)
        ciphermac = mac.finalize()
        if isinstance(enckey, ecdsa.ECDSA256P1Public):
            pubk = newpk.public_key().public_bytes(
                encoding=Encoding.X962,
                format=PublicFormat.UncompressedPoint)
        else:
            pubk = newpk.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw)
        return cipherkey, ciphermac, pubk

    def create(self, key, public_key_format, enckey, dependencies=None,
               sw_type=None, custom_tlvs=None, compression_tlvs=None,
               compression_type=None, encrypt_keylen=128, clear=False,
               fixed_sig=None, pub_key=None, vector_to_sign=None,
               user_sha='auto', hmac_sha='auto', is_pure=False, keep_comp_size=False,
               dont_encrypt=False):
        self.enckey = enckey

        # key decides on sha, then pub_key; of both are none default is used
        check_key = key if key is not None else pub_key
        hash_algorithm, hash_tlv = key_and_user_sha_to_alg_and_tlv(check_key, user_sha, is_pure)

        # Calculate the hash of the public key
        if key is not None:
            pub = key.get_public_bytes()
            sha = hash_algorithm()
            sha.update(pub)
            pubbytes = sha.digest()
        elif pub_key is not None:
            if hasattr(pub_key, 'sign'):
                print(os.path.basename(__file__) + ": sign the payload")
            pub = pub_key.get_public_bytes()
            sha = hash_algorithm()
            sha.update(pub)
            pubbytes = sha.digest()
        else:
            pubbytes = bytes(hashlib.sha256().digest_size)

        protected_tlv_size = 0

        if self.security_counter is not None:
            # Size of the security counter TLV: header ('HH') + payload ('I')
            #                                   = 4 + 4 = 8 Bytes
            protected_tlv_size += TLV_SIZE + 4

        if sw_type is not None:
            if len(sw_type) > MAX_SW_TYPE_LENGTH:
                msg = "'{}' is too long ({} characters) for sw_type. Its " \
                      "maximum allowed length is 12 characters.".format(
                       sw_type, len(sw_type))
                raise click.UsageError(msg)

            image_version = (str(self.version.major) + '.'
                             + str(self.version.minor) + '.'
                             + str(self.version.revision))

            # The image hash is computed over the image header, the image
            # itself and the protected TLV area. However, the boot record TLV
            # (which is part of the protected area) should contain this hash
            # before it is even calculated. For this reason the script fills
            # this field with zeros and the bootloader will insert the right
            # value later.
            digest = bytes(hash_algorithm().digest_size)

            # Create CBOR encoded boot record
            boot_record = create_sw_component_data(sw_type, image_version,
                                                   hash_tlv, digest,
                                                   pubbytes)

            protected_tlv_size += TLV_SIZE + len(boot_record)

        if dependencies is not None:
            # Size of a Dependency TLV = Header ('HH') + Payload('IBBHI')
            # = 4 + 12 = 16 Bytes
            dependencies_num = len(dependencies[DEP_IMAGES_KEY])
            protected_tlv_size += (dependencies_num * 16)

        if keep_comp_size:
            compression_tlvs["COMP_DEC_SIZE"] = struct.pack(
                self.get_struct_endian() + 'L', self.image_size)
        if compression_tlvs is not None:
            for value in compression_tlvs.values():
                protected_tlv_size += TLV_SIZE + len(value)
        if custom_tlvs is not None:
            for value in custom_tlvs.values():
                protected_tlv_size += TLV_SIZE + len(value)

        if protected_tlv_size != 0:
            # Add the size of the TLV info header
            protected_tlv_size += TLV_INFO_SIZE

        # At this point the image is already on the payload
        #
        # This adds the padding if image is not aligned to the 16 Bytes
        # in encrypted mode
        if self.enckey is not None and dont_encrypt is False:
            pad_len = len(self.payload) % 16
            if pad_len > 0:
                pad = bytes(16 - pad_len)
                if isinstance(self.payload, bytes):
                    self.payload += pad
                else:
                    self.payload.extend(pad)

        compression_flags = 0x0
        if compression_tlvs is not None:
            if compression_type in ["lzma2", "lzma2armthumb"]:
                compression_flags = IMAGE_F['COMPRESSED_LZMA2']
                if compression_type == "lzma2armthumb":
                    compression_flags |= IMAGE_F['COMPRESSED_ARM_THUMB']
        # This adds the header to the payload as well
        if encrypt_keylen == 256:
            self.add_header(enckey, protected_tlv_size, compression_flags, 256)
        else:
            self.add_header(enckey, protected_tlv_size, compression_flags)

        prot_tlv = TLV(self.endian, TLV_PROT_INFO_MAGIC)

        # Protected TLVs must be added first, because they are also included
        # in the hash calculation
        protected_tlv_off = None
        if protected_tlv_size != 0:

            e = STRUCT_ENDIAN_DICT[self.endian]

            if self.security_counter is not None:
                payload = struct.pack(e + 'I', self.security_counter)
                prot_tlv.add('SEC_CNT', payload)

            if sw_type is not None:
                prot_tlv.add('BOOT_RECORD', boot_record)

            if dependencies is not None:
                for i in range(dependencies_num):
                    payload = struct.pack(
                        e + 'BB2x' + 'BBHI',
                        int(dependencies[DEP_IMAGES_KEY][i]),
                        dependencies[DEP_VERSIONS_KEY][i].slot,
                        dependencies[DEP_VERSIONS_KEY][i].major,
                        dependencies[DEP_VERSIONS_KEY][i].minor,
                        dependencies[DEP_VERSIONS_KEY][i].revision,
                        dependencies[DEP_VERSIONS_KEY][i].build
                    )
                    prot_tlv.add('DEPENDENCY', payload)

            if compression_tlvs is not None:
                for tag, value in compression_tlvs.items():
                    prot_tlv.add(tag, value)
            if custom_tlvs is not None:
                for tag, value in custom_tlvs.items():
                    prot_tlv.add(tag, value)

            protected_tlv_off = len(self.payload)

            self.payload += prot_tlv.get()

        tlv = TLV(self.endian)

        # These signature is done over sha of image. In case of
        # EC signatures so called Pure algorithm, designated to be run
        # over entire message is used with sha of image as message,
        # so, for example, in case of ED25519 we have here SHAxxx-ED25519-SHA512.
        sha = hash_algorithm()
        sha.update(self.payload)
        digest = sha.digest()
        tlv.add(hash_tlv, digest)
        self.image_hash = digest
        # Unless pure, we are signing digest.
        message = digest

        if is_pure:
            # Note that when Pure signature is used, hash TLV is not present.
            message = bytes(self.payload)
            e = STRUCT_ENDIAN_DICT[self.endian]
            sig_pure = struct.pack(e + '?', True)
            tlv.add('SIG_PURE', sig_pure)

        if vector_to_sign == 'payload':
            # Stop amending data to the image
            # Just keep data vector which is expected to be signed
            print(os.path.basename(__file__) + ': export payload')
            return
        elif vector_to_sign == 'digest':
            self.payload = digest
            print(os.path.basename(__file__) + ': export digest')
            return

        if key is not None or fixed_sig is not None:
            if public_key_format == 'hash':
                tlv.add('KEYHASH', pubbytes)
            else:
                tlv.add('PUBKEY', pub)

            if key is not None and fixed_sig is None:
                # `sign` expects the full image payload (hashing done
                # internally), while `sign_digest` expects only the digest
                # of the payload

                if hasattr(key, 'sign'):
                    print(os.path.basename(__file__) + ": sign the payload")
                    sig = key.sign(bytes(self.payload))
                else:
                    print(os.path.basename(__file__) + ": sign the digest")
                    sig = key.sign_digest(message)
                tlv.add(key.sig_tlv(), sig)
                self.signature = sig
            elif fixed_sig is not None and key is None:
                tlv.add(pub_key.sig_tlv(), fixed_sig['value'])
                self.signature = fixed_sig['value']
            else:
                raise click.UsageError("Can not sign using key and provide fixed-signature at the same time")

        # At this point the image was hashed + signed, we can remove the
        # protected TLVs from the payload (will be re-added later)
        if protected_tlv_off is not None:
            self.payload = self.payload[:protected_tlv_off]

        if enckey is not None and dont_encrypt is False:
            if encrypt_keylen == 256:
                plainkey = os.urandom(32)
            else:
                plainkey = os.urandom(16)

            if not isinstance(enckey, rsa.RSAPublic):
                if hmac_sha == 'auto' or hmac_sha == '256':
                    hmac_sha = '256'
                    hmac_sha_alg = hashes.SHA256()
                elif hmac_sha == '512':
                    if not isinstance(enckey, x25519.X25519Public):
                        raise click.UsageError("Currently only ECIES-X25519 supports HMAC-SHA512")
                    hmac_sha_alg = hashes.SHA512()
                else:
                    raise click.UsageError("Unsupported HMAC-SHA")

            if isinstance(enckey, rsa.RSAPublic):
                cipherkey = enckey._get_public().encrypt(
                    plainkey, padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None))
                self.enctlv_len = len(cipherkey)
                tlv.add('ENCRSA2048', cipherkey)
            elif isinstance(enckey, ecdsa.ECDSA256P1Public):
                cipherkey, mac, pubk = self.ecies_hkdf(enckey, plainkey, hmac_sha_alg)
                enctlv = pubk + mac + cipherkey
                self.enctlv_len = len(enctlv)
                tlv.add('ENCEC256', enctlv)
            elif isinstance(enckey, x25519.X25519Public):
                cipherkey, mac, pubk = self.ecies_hkdf(enckey, plainkey, hmac_sha_alg)
                enctlv = pubk + mac + cipherkey
                self.enctlv_len = len(enctlv)
                if (hmac_sha == '256'):
                    tlv.add('ENCX25519', enctlv)
                else:
                    tlv.add('ENCX25519_SHA512', enctlv)

            if not clear:
                nonce = bytes([0] * 16)
                cipher = Cipher(algorithms.AES(plainkey), modes.CTR(nonce),
                                backend=default_backend())
                encryptor = cipher.encryptor()
                img = bytes(self.payload[self.header_size:])
                self.payload[self.header_size:] = \
                    encryptor.update(img) + encryptor.finalize()

        self.payload += prot_tlv.get()
        self.payload += tlv.get()

        self.check_trailer()

    def get_struct_endian(self):
        return STRUCT_ENDIAN_DICT[self.endian]

    def get_signature(self):
        return self.signature

    def get_infile_data(self):
        return self.infile_data

    def add_header(self, enckey, protected_tlv_size, compression_flags, aes_length=128):
        """Install the image header."""

        flags = 0
        if enckey is not None:
            if aes_length == 128:
                flags |= IMAGE_F['ENCRYPTED_AES128']
            else:
                flags |= IMAGE_F['ENCRYPTED_AES256']
        if self.load_addr != 0:
            # Indicates that this image should be loaded into RAM
            # instead of run directly from flash.
            flags |= IMAGE_F['RAM_LOAD']
        if self.rom_fixed:
            flags |= IMAGE_F['ROM_FIXED']
        if self.non_bootable:
            flags |= IMAGE_F['NON_BOOTABLE']

        e = STRUCT_ENDIAN_DICT[self.endian]
        fmt = (e +
               # type ImageHdr struct {
               'I' +     # Magic    uint32
               'I' +     # LoadAddr uint32
               'H' +     # HdrSz    uint16
               'H' +     # PTLVSz   uint16
               'I' +     # ImgSz    uint32
               'I' +     # Flags    uint32
               'BBHI' +  # Vers     ImageVersion
               'I'       # Pad1     uint32
               )  # }
        assert struct.calcsize(fmt) == IMAGE_HEADER_SIZE
        header = struct.pack(fmt,
                             IMAGE_MAGIC,
                             self.rom_fixed or self.load_addr,
                             self.header_size,
                             protected_tlv_size,  # TLV Info header +
                                                  # Protected TLVs
                             len(self.payload) - self.header_size,  # ImageSz
                             flags | compression_flags,
                             self.version.major,
                             self.version.minor or 0,
                             self.version.revision or 0,
                             self.version.build or 0,
                             0)  # Pad1
        self.payload = bytearray(self.payload)
        self.payload[:len(header)] = header

    def _trailer_size(self, write_size, max_sectors, overwrite_only, enckey,
                      save_enctlv, enctlv_len):
        # NOTE: should already be checked by the argument parser
        magic_size = 16
        magic_align_size = align_up(magic_size, self.max_align)
        if overwrite_only:
            return self.max_align * 2 + magic_align_size
        else:
            if write_size not in set([1, 2, 4, 8, 16, 32]):
                raise click.BadParameter("Invalid alignment: {}".format(
                    write_size))
            m = DEFAULT_MAX_SECTORS if max_sectors is None else max_sectors
            trailer = m * 3 * write_size  # status area
            if enckey is not None:
                if save_enctlv:
                    # TLV saved by the bootloader is aligned
                    keylen = align_up(enctlv_len, self.max_align)
                else:
                    keylen = align_up(16, self.max_align)
                trailer += keylen * 2  # encryption keys
            trailer += self.max_align * 4  # image_ok/copy_done/swap_info/swap_size
            trailer += magic_align_size
            return trailer

    def pad_to(self, size):
        """Pad the image to the given size, with the given flash alignment."""
        tsize = self._trailer_size(self.align, self.max_sectors,
                                   self.overwrite_only, self.enckey,
                                   self.save_enctlv, self.enctlv_len)
        padding = size - (len(self.payload) + tsize)
        pbytes = bytearray([self.erased_val] * padding)
        pbytes += bytearray([self.erased_val] * (tsize - len(self.boot_magic)))
        pbytes += self.boot_magic
        if self.confirm and not self.overwrite_only:
            magic_size = 16
            magic_align_size = align_up(magic_size, self.max_align)
            image_ok_idx = -(magic_align_size + self.max_align)
            pbytes[image_ok_idx] = 0x01  # image_ok = 0x01
        self.payload += pbytes

    @staticmethod
    def verify(imgfile, key):
        ext = os.path.splitext(imgfile)[1][1:].lower()
        try:
            if ext == INTEL_HEX_EXT:
                b = IntelHex(imgfile).tobinstr()
            else:
                with open(imgfile, 'rb') as f:
                    b = f.read()
        except FileNotFoundError:
            raise click.UsageError(f"Image file {imgfile} not found")

        magic, _, header_size, _, img_size = struct.unpack('IIHHI', b[:16])
        version = struct.unpack('BBHI', b[20:28])

        if magic != IMAGE_MAGIC:
            return VerifyResult.INVALID_MAGIC, None, None, None

        tlv_off = header_size + img_size
        tlv_info = b[tlv_off:tlv_off + TLV_INFO_SIZE]
        magic, tlv_tot = struct.unpack('HH', tlv_info)
        if magic == TLV_PROT_INFO_MAGIC:
            tlv_off += tlv_tot
            tlv_info = b[tlv_off:tlv_off + TLV_INFO_SIZE]
            magic, tlv_tot = struct.unpack('HH', tlv_info)

        if magic != TLV_INFO_MAGIC:
            return VerifyResult.INVALID_TLV_INFO_MAGIC, None, None, None

        # This is set by existence of TLV SIG_PURE
        is_pure = False

        prot_tlv_size = tlv_off
        hash_region = b[:prot_tlv_size]
        tlv_end = tlv_off + tlv_tot
        tlv_off += TLV_INFO_SIZE  # skip tlv info

        # First scan all TLVs in search of SIG_PURE
        while tlv_off < tlv_end:
            tlv = b[tlv_off:tlv_off + TLV_SIZE]
            tlv_type, _, tlv_len = struct.unpack('BBH', tlv)
            if tlv_type == TLV_VALUES['SIG_PURE']:
                is_pure = True
                break
            tlv_off += TLV_SIZE + tlv_len

        digest = None
        tlv_off = prot_tlv_size
        tlv_end = tlv_off + tlv_tot
        tlv_off += TLV_INFO_SIZE  # skip tlv info
        while tlv_off < tlv_end:
            tlv = b[tlv_off:tlv_off + TLV_SIZE]
            tlv_type, _, tlv_len = struct.unpack('BBH', tlv)
            if is_sha_tlv(tlv_type):
                if not tlv_matches_key_type(tlv_type, key):
                    return VerifyResult.KEY_MISMATCH, None, None, None
                off = tlv_off + TLV_SIZE
                digest = get_digest(tlv_type, hash_region)
                if digest == b[off:off + tlv_len]:
                    if key is None:
                        return VerifyResult.OK, version, digest, None
                else:
                    return VerifyResult.INVALID_HASH, None, None, None
            elif not is_pure and key is not None and tlv_type == TLV_VALUES[key.sig_tlv()]:
                off = tlv_off + TLV_SIZE
                tlv_sig = b[off:off + tlv_len]
                payload = b[:prot_tlv_size]
                try:
                    if hasattr(key, 'verify'):
                        key.verify(tlv_sig, payload)
                    else:
                        key.verify_digest(tlv_sig, digest)
                    return VerifyResult.OK, version, digest, None
                except InvalidSignature:
                    # continue to next TLV
                    pass
            elif is_pure and key is not None and tlv_type in ALLOWED_PURE_SIG_TLVS:
                off = tlv_off + TLV_SIZE
                tlv_sig = b[off:off + tlv_len]
                try:
                    key.verify_digest(tlv_sig, hash_region)
                    return VerifyResult.OK, version, None, tlv_sig
                except InvalidSignature:
                    # continue to next TLV
                    pass
            tlv_off += TLV_SIZE + tlv_len
        return VerifyResult.INVALID_SIGNATURE, None, None, None
