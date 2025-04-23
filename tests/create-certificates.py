# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Felix Fontein <felix@fontein.de>

from __future__ import annotations

import binascii
import datetime
import typing as t
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, types
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, CertificatePoliciesOID, AuthorityInformationAccessOID, ExtensionOID


@dataclass
class Certificate:
    cert: x509.Certificate
    key: types.PrivateKeyTypes
    parent: "Certificate" | None


def decode_serial(serial: str) -> int:
    return int(serial.replace(':', ''), 16)


def decode_bytes(data: str) -> bytes:
    return binascii.unhexlify(data.replace(':', ''))


def create_signed(
    *,
    key: types.PrivateKeyTypes,
    subject: x509.Name,
    issuer: x509.Name | None = None,
    sign_key: types.PrivateKeyTypes | None = None,
    sign_cert: Certificate | None = None,
    serial: int,
    hash: hashes.Hash,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    extensions: list[tuple[x509.ExtensionType, str] | t.Literal["ski", "aki"]] | None = None,
    filenames: list[str] | None = None,
) -> Certificate:
    if sign_cert is None:
        if issuer is None:
            raise ValueError("If sign_cert is not provided, issuer must be provided!")
        if sign_key is None:
            raise ValueError("If sign_cert is not provided, sign_key must be provided!")
    else:
        if issuer is not None:
            raise ValueError("If sign_cert is provided, issuer must not be provided!")
        issuer = sign_cert.cert.subject
        if sign_key is not None:
            raise ValueError("If sign_cert is provided, sign_key must not be provided!")
        sign_key = sign_cert.key
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    if extensions:
        for extension_info in extensions:
            if extension_info == "aki":
                builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(sign_key.public_key()), critical=False)
            elif extension_info == "ski":
                builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            else:
                extension, critical = extension_info
                builder = builder.add_extension(extension, critical=critical)
    cert = builder.sign(sign_key, hash)
    if filenames:
        data = cert.public_bytes(encoding=Encoding.PEM)
        for filename in filenames:
            with open(filename, "wb") as f:
                f.write(data)
    return Certificate(cert=cert, key=key, parent=sign_cert)


def create_self_signed(
    *,
    key: types.PrivateKeyTypes,
    subject: x509.Name,
    serial: int,
    hash: hashes.Hash,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    extensions: list[tuple[x509.ExtensionType, str] | t.Literal["ski", "aki"]] | None = None,
    filenames: list[str] | None = None,
) -> Certificate:
    return create_signed(
        key=key,
        subject=subject,
        issuer=subject,
        sign_key=key,
        serial=serial,
        hash=hash,
        not_before=not_before,
        not_after=not_after,
        extensions=extensions,
        filenames=filenames,
    )


def concat_files(destination: Path, sources: list[Path | str]) -> None:
    data = []
    for source in sources:
        if isinstance(source, str):
            data.append(source.encode("utf-8"))
        else:
            with open(source, "rb") as f:
                data.append(f.read().strip())
    data.append(b"")
    with open(destination, "wb") as f:
        f.write(b"\n".join(data))


# Root certificates

foobar = create_self_signed(
    key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some Area"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Some City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foobar CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Foobar Certification Authority"),
    ]),
    serial=decode_serial("9f0703517195373e68ce154665d6f407"),
    hash=hashes.SHA1(),
    not_before=datetime.datetime(year=2006, month=12, day=1, hour=0, minute=0, second=0, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2029, month=12, day=31, hour=23, minute=59, second=59, tzinfo=datetime.timezone.utc),
    extensions=[
        "ski",
        (x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=None), True),
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.example.org/foobar-ca.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar.pem",
    ]
)

foobar_ecc = create_self_signed(
    key=ec.generate_private_key(ec.SECP384R1()),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some Area"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Some City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foobar CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Foobar ECC Certification Authority"),
    ]),
    serial=decode_serial("89f62d74904db60b077a63c2165e7af3"),
    hash=hashes.SHA384(),
    not_before=datetime.datetime(year=2008, month=3, day=6, hour=0, minute=0, second=0, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2038, month=1, day=18, hour=23, minute=59, second=59, tzinfo=datetime.timezone.utc),
    extensions=[
        "ski",
        (x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=None), True),
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar_ECC.pem",
        "tests/integration/targets/certificate_complete_chain/files/cert1-root.pem",
    ]
)

foobar_rsa = create_self_signed(
    key=rsa.generate_private_key(public_exponent=65537, key_size=4096),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some Area"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Some City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foobar CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Foobar RSA Certification Authority"),
    ]),
    serial=decode_serial("6506cf0ebbcbf304c90745c46c30dc14"),
    hash=hashes.SHA384(),
    not_before=datetime.datetime(year=2010, month=1, day=19, hour=0, minute=0, second=0, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2038, month=1, day=18, hour=23, minute=59, second=59, tzinfo=datetime.timezone.utc),
    extensions=[
        "ski",
        (x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=None), True),
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar_RSA.pem",
    ]
)

bazbam_root = create_self_signed(
    key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    subject=x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bazbam International"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Bazbam CA"),
    ]),
    serial=decode_serial("c9a56c6a4896e371c5ffba04b41073bf"),
    hash=hashes.SHA1(),
    not_before=datetime.datetime(year=2000, month=9, day=30, hour=21, minute=12, second=19, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2021, month=9, day=30, hour=14, minute=1, second=15, tzinfo=datetime.timezone.utc),
    extensions=[
        (x509.BasicConstraints(ca=True, path_length=None), True),
        (x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        "ski",
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/roots/CA_Bazbam.pem",
        "tests/integration/targets/certificate_complete_chain/files/cert2-root.pem",
    ]
)

foobazbam_root = create_self_signed(
    key=rsa.generate_private_key(public_exponent=65537, key_size=4096),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foo Baz Bam Incorporated"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Foobazbam Root"),
    ]),
    serial=decode_serial("f8bd06c8bf6ef3a6ac85fd51c462f9a0"),
    hash=hashes.SHA256(),
    not_before=datetime.datetime(year=2015, month=6, day=4, hour=11, minute=4, second=38, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2035, month=6, day=4, hour=11, minute=4, second=38, tzinfo=datetime.timezone.utc),
    extensions=[
        (x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=None), True),
        "ski",
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/roots/foobazbam.pem",
        "tests/integration/targets/certificate_complete_chain/files/cert2-altroot.pem",
    ]
)

# Intermediate certificates

foobar_ecc_inter = create_signed(
    sign_cert=foobar_ecc,
    key=ec.generate_private_key(ec.SECP256R1()),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some Area"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Some City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foobar CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Foobar ECC Domain Validation Intermediate"),
    ]),
    serial=decode_serial("c9aad9d1e05074e7eae62e0eb34175e1"),
    hash=hashes.SHA384(),
    not_before=datetime.datetime(year=2014, month=9, day=25, hour=0, minute=0, second=0, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2029, month=9, day=24, hour=23, minute=59, second=59, tzinfo=datetime.timezone.utc),
    extensions=[
        "aki",
        "ski",
        (x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=0), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        (x509.CertificatePolicies([
            x509.PolicyInformation(CertificatePoliciesOID.ANY_POLICY, policy_qualifiers=[]),
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
        ]), False),
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.example.org/foobar-ecc-ca.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://crl.example.org/foobar-ecc-ca.crl"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.example.org"),
            ),
        ]), False),
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert1-chain.pem",
    ],
)

foobazbam_inter_bazbam = create_signed(
    sign_cert=bazbam_root,
    key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foo Baz Bam Subsidiary"),
        x509.NameAttribute(NameOID.COMMON_NAME, "FooBazBam Inter"),
    ]),
    serial=decode_serial("f137dc8857c76a7b82be401fd03dbd4e"),
    hash=hashes.SHA256(),
    not_before=datetime.datetime(year=2016, month=3, day=17, hour=16, minute=40, second=46, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2021, month=3, day=17, hour=16, minute=40, second=46, tzinfo=datetime.timezone.utc),
    extensions=[
        (x509.BasicConstraints(ca=True, path_length=0), True),
        (x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.bazbam.example.org"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://cert.bazbam.example.org/ca.pem"),
            ),
        ]), False),
        "aki",
        (x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.44947.1.1.1"), policy_qualifiers=["http://foobarbaz.example.com/cps-policy"]),
        ]), False),
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.bazbam.example.org/ca.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
        "ski",
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert2-chain.pem",
    ],
)

foobazbam_inter_own = create_signed(
    sign_cert=foobazbam_root,
    key=foobazbam_inter_bazbam.key,
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foo Baz Bam Subsidiary"),
        x509.NameAttribute(NameOID.COMMON_NAME, "FooBazBam Inter"),
    ]),
    serial=decode_serial("72cdaba696be80905df01a12a90e4f37"),
    hash=hashes.SHA256(),
    not_before=datetime.datetime(year=2016, month=10, day=6, hour=15, minute=43, second=55, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2021, month=10, day=6, hour=15, minute=43, second=55, tzinfo=datetime.timezone.utc),
    extensions=[
        (x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=True,
            crl_sign=True,
        ), True),
        (x509.BasicConstraints(ca=True, path_length=0), True),
        (x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.44947.1.1.1"), policy_qualifiers=["http://foobarbaz.example.com/cps-policy"]),
        ]), False),
        "ski",
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.foobarbaz.example.com/inter.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.foobarbaz.example.com"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://cert.foobarbaz.example.com/inter.pem"),
            ),
        ]), False),
        "aki",
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert2-altchain.pem",
    ],
)

# Leaf certificates

cert1 = create_signed(
    sign_cert=foobar_ecc_inter,
    key=ec.generate_private_key(ec.SECP256R1()),
    subject=x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Something Validated"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "FooBarTLS Validated"),
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ]),
    serial=decode_serial("3ecc834a0ff8bb5cc06a8910f0ef9f34"),
    hash=hashes.SHA256(),
    not_before=datetime.datetime(year=2018, month=7, day=11, hour=0, minute=0, second=0, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2019, month=1, day=17, hour=23, minute=59, second=59, tzinfo=datetime.timezone.utc),
    extensions=[
        "aki",
        "ski",
        (x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False,
        ), True),
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        (x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.6449.1.2.2.7"), policy_qualifiers=["https://something.exmaple.org/c-p-s"]),
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
        ]), False),
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.example.org/foobar-ecc-inter.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://cert.example.org/foobar-ecc-inter.pem"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.example.org"),
            ),
        ]), False),
        (x509.SubjectAlternativeName([
            x509.DNSName("test.example.com"),
            x509.DNSName("*.test.example.com"),
            x509.DNSName("something.example.com"),
        ]), False),
        # binascii.hexlify(
        #   x509.load_pem_x509_certificate(
        #     open("tests/integration/targets/certificate_complete_chain/files/cert1.pem", "rb").read()
        #   ).extensions.get_extension_for_oid(oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS).value.public_bytes()
        # )
        (x509.UnrecognizedExtension(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
            decode_bytes(
                "0481f200f00077000de1f2302bd30dc140621209ea552efc47747cb1d7e930ef0e421eb47e4eaa34000001960"
                "be468ec0000040300483046022100b57abc31c137bc075eb2d05a402d13b65de2c668aa589395b1c8a87a2740"
                "8caf022100a8833d74ec6f1d7a6cdff8446cf772cfcc4c3b61cb89baf7ed11bed00a44485a00750012f14e34b"
                "d53724c840619c38f3f7a13f8e7b56287889c6d300584ebe586263a000001960be468e5000004030046304402"
                "205a45d0b28451ef630bc563aa2845c59c138e83a12fef67ea217a62fe0cc65c9002206fadff98adb2857fafa"
                "7683551f993e72cc3d632fcf06a461527d7debd1a5784"
            ),
        ), False),
        # This doesn't work in a nicer way, see https://github.com/pyca/cryptography/issues/7824
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert1.pem",
    ],
)

cert2 = create_signed(
    # sign_cert=foobazbam_inter_bazbam,
    sign_cert=foobazbam_inter_own,
    key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "example.net"),
    ]),
    serial=decode_serial("2405bbfcf40fdc2b142b22ab985e3556"),
    hash=hashes.SHA256(),
    not_before=datetime.datetime(year=2018, month=7, day=27, hour=17, minute=31, second=27, tzinfo=datetime.timezone.utc),
    not_after=datetime.datetime(year=2018, month=10, day=25, hour=17, minute=31, second=27, tzinfo=datetime.timezone.utc),
    extensions=[
        (x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False,
        ), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        (x509.BasicConstraints(ca=False, path_length=None), True),
        "ski",
        "aki",
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.foobarbaz.example.com"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://cert.foobarbaz.example.com/inter.pem"),
            ),
        ]), False),
        (x509.SubjectAlternativeName([
            x509.DNSName("example.net"),
            x509.DNSName("www.example.net"),
            x509.DNSName("foo.example.net"),
            x509.DNSName("bar.example.net"),
            x509.DNSName("baz.example.net"),
            x509.DNSName("bam.example.net"),
            x509.DNSName("*.bam.example.net"),
        ]), False),
        (x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.44947.1.1.1"), policy_qualifiers=[
                "http://cps.foobarbaz.example.com/something",
                x509.UserNotice(
                    notice_reference=None,
                    explicit_text=(
                        "Blabla whatever."
                    ),
                )
            ]),
        ]), False),
        # binascii.hexlify(
        #   x509.load_pem_x509_certificate(
        #     open("tests/integration/targets/certificate_complete_chain/files/cert2.pem", "rb").read()
        #   ).extensions.get_extension_for_oid(oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS).value.public_bytes()
        # )
        (x509.UnrecognizedExtension(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
            decode_bytes(
                "0481ef00ed007400dddcca3495d7e11605e79532fac79ff83d1c50dfdb003a1412760a2cacbbc82a000001960bed082d00000"
                "40300453043022005e4bbf5b87cc6e4a0e90782e46df117f1572e9d830a62f40f080d34643a7d57021f60f518e206f30974cf"
                "fe5104be58d5dac4ea80e49cd47ef0858db60b6c46790075000de1f2302bd30dc140621209ea552efc47747cb1d7e930ef0e4"
                "21eb47e4eaa34000001960bed07d80000040300463044022076e85e46f183ee675d6001f117a80169564d3555c6ceb12eb0dd"
                "d9f60897face0220784582a60f6db10f1d07bfe1535cce9a46689bad950d7be4f02b3ecac71b42ae"
            ),
        ), False),
        # This doesn't work in a nicer way, see https://github.com/pyca/cryptography/issues/7824
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert2.pem",
        "tests/integration/targets/x509_certificate_info/files/cert1.pem",
    ],
)

# Concatenated files

concat_files(
    Path("tests/integration/targets/certificate_complete_chain/files/cert1-fullchain.pem"),
    [
        Path("tests/integration/targets/certificate_complete_chain/files/cert1.pem"),
        Path("tests/integration/targets/certificate_complete_chain/files/cert1-chain.pem"),
    ]
)

concat_files(
    Path("tests/integration/targets/certificate_complete_chain/files/cert2-fullchain.pem"),
    [
        Path("tests/integration/targets/certificate_complete_chain/files/cert2.pem"),
        Path("tests/integration/targets/certificate_complete_chain/files/cert2-chain.pem"),
    ]
)

concat_files(
    Path("tests/integration/targets/certificate_complete_chain/files/roots.pem"),
    [
        "# Foo",
        Path("tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar.pem"),
        "\n# Bar",
        Path("tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar_ECC.pem"),
        "\n# Baz\n#Bam",
        Path("tests/integration/targets/certificate_complete_chain/files/roots/CA_Foobar_RSA.pem"),
        Path("tests/integration/targets/certificate_complete_chain/files/roots/CA_Bazbam.pem"),
        "# Jar",
        Path("tests/integration/targets/certificate_complete_chain/files/roots/foobazbam.pem"),
    ]
)
