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

comodo_ca = create_self_signed(
    key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Greater Manchester"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Salford"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Not COMODO CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Not COMODO Certification Authority"),
    ]),
    serial=decode_serial("4e:81:2d:8a:82:65:e0:0b:02:ee:3e:35:02:46:e5:3d"),
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
                full_name=[x509.UniformResourceIdentifier("http://crl.comodoca.com/COMODOCertificationAuthority.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/roots/COMODO_Certification_Authority.pem",
    ]
)

comodo_ecc_ca = create_self_signed(
    key=ec.generate_private_key(ec.SECP384R1()),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Greater Manchester"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Salford"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Not COMODO CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Not COMODO ECC Certification Authority"),
    ]),
    serial=decode_serial("1f:47:af:aa:62:00:70:50:54:4c:01:9e:9b:63:99:2a"),
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
        "tests/integration/targets/certificate_complete_chain/files/roots/COMODO_ECC_Certification_Authority.pem",
        "tests/integration/targets/certificate_complete_chain/files/cert1-root.pem",
    ]
)

comodo_rsa_ca = create_self_signed(
    key=rsa.generate_private_key(public_exponent=65537, key_size=4096),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Greater Manchester"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Salford"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Not COMODO CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Not COMODO RSA Certification Authority"),
    ]),
    serial=decode_serial("4c:aa:f9:ca:db:63:6f:e0:1f:f7:4e:d8:5b:03:86:9d"),
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
        "tests/integration/targets/certificate_complete_chain/files/roots/COMODO_RSA_Certification_Authority.pem",
    ]
)

dst_root = create_self_signed(
    key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    subject=x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Not Digital Signature Trust Co."),
        x509.NameAttribute(NameOID.COMMON_NAME, "Not DST Root CA X3"),
    ]),
    serial=decode_serial("44:af:b0:80:d6:a3:27:ba:89:30:39:86:2e:f8:40:6b"),
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
        "tests/integration/targets/certificate_complete_chain/files/roots/DST_Root_CA_X3.pem",
        "tests/integration/targets/certificate_complete_chain/files/cert2-root.pem",
    ]
)

isrg_x1 = create_self_signed(
    key=rsa.generate_private_key(public_exponent=65537, key_size=4096),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Not Internet Security Research Group"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Not ISRG Root X1"),
    ]),
    serial=decode_serial("82:10:cf:b0:d2:40:e3:59:44:63:e0:bb:63:82:8b:00"),
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
        "tests/integration/targets/certificate_complete_chain/files/roots/ISRG_Root_X1.pem",
        "tests/integration/targets/certificate_complete_chain/files/cert2-altroot.pem",
    ]
)

# Intermediate certificates

comodo_ecc_inter = create_signed(
    sign_cert=comodo_ecc_ca,
    key=ec.generate_private_key(ec.SECP256R1()),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Greater Manchester"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Salford"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Not COMODO CA Limited"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Not COMODO ECC Domain Validation Secure Server CA 2"),
    ]),
    serial=decode_serial("5b:25:ce:69:07:c4:26:55:66:d3:39:0c:99:a9:54:ad"),
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
                full_name=[x509.UniformResourceIdentifier("http://crl.comodoca.com/COMODOECCCertificationAuthority.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://crt.comodoca.com/COMODOECCAddTrustCA.crt"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.comodoca4.com"),
            ),
        ]), False),
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert1-chain.pem",
    ],
)

lets_encrypt_x3_dst = create_signed(
    sign_cert=dst_root,
    key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Not Let's Encrypt"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Not Let's Encrypt Authority X3"),
    ]),
    serial=decode_serial("0a:01:41:42:00:00:01:53:85:73:6a:0b:85:ec:a7:08"),
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
                access_location=x509.UniformResourceIdentifier("http://isrg.trustid.ocsp.identrust.com"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://apps.identrust.com/roots/dstrootcax3.p7c"),
            ),
        ]), False),
        "aki",
        (x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.44947.1.1.1"), policy_qualifiers=["http://cps.root-x1.letsencrypt.org"]),
        ]), False),
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.identrust.com/DSTROOTCAX3CRL.crl")],
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

lets_encrypt_x3_isrg = create_signed(
    sign_cert=isrg_x1,
    key=lets_encrypt_x3_dst.key,
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Not Let's Encrypt"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Not Let's Encrypt Authority X3"),
    ]),
    serial=decode_serial("d3:b1:72:26:34:23:32:dc:f4:05:28:51:2a:ec:9c:6a"),
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
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.44947.1.1.1"), policy_qualifiers=["http://cps.root-x1.letsencrypt.org"]),
        ]), False),
        "ski",
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.root-x1.letsencrypt.org")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.root-x1.letsencrypt.org/"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://cert.root-x1.letsencrypt.org/"),
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
    sign_cert=comodo_ecc_inter,
    key=ec.generate_private_key(ec.SECP256R1()),
    subject=x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Domain Control Validated"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Not PositiveSSL Multi-Domain"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ssl803025.cloudflaressl.com"),
    ]),
    serial=decode_serial("2f:e7:3d:a1:05:e9:bd:d7:0e:0f:70:4a:02:77:1b:80"),
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
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.6449.1.2.2.7"), policy_qualifiers=["https://secure.comodo.com/CPS"]),
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
        ]), False),
        (x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]), False),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.comodoca4.com"),
            ),
        ]), False),
        (x509.SubjectAlternativeName([
            x509.DNSName("ssl803025.cloudflaressl.com"),
            x509.DNSName("*.hscoscdn40.net"),
            x509.DNSName("hscoscdn40.net"),
        ]), False),
        # binascii.hexlify(
        #   x509.load_pem_x509_certificate(
        #     open("tests/integration/targets/certificate_complete_chain/files/cert1.pem", "rb").read()
        #   ).extensions.get_extension_for_oid(oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS).value.public_bytes()
        # )
        (x509.UnrecognizedExtension(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
            decode_bytes(
                "0481f100ef007600ee4bbdb775ce60bae142691fabe19e66a30f7e5fb072d88300c47b897aa8fdcb0000016486d503cf000004"
                "0300473045022100db4de3cf48cf2de2b2cfde17cad4c3f822afcaeac80dadde5a719dca3e27636502204192ee4c8860fcc215"
                "b9ff7d5bc8f8f4ff2a5ed4c986d1062bab7a96bd8890dd007500747eda8331ad331091219cce254f4270c2bffd5e422008c637"
                "3579e6107bcc560000016486d5041e000004030046304402204a370bec1e1c6e09b65c40faf46eff8853dedb39168719e48062"
                "124b0b97c35802202cf03e67db8c47f00cd5c4b81b3b25790f45a4f5a62ee167d691e702494ca1fd"
            ),
        ), False),
        # This doesn't work in a nicer way, see https://github.com/pyca/cryptography/issues/7824
    ],
    filenames=[
        "tests/integration/targets/certificate_complete_chain/files/cert1.pem",
    ],
)

cert2 = create_signed(
    # sign_cert=lets_encrypt_x3_dst,
    sign_cert=lets_encrypt_x3_isrg,
    key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    subject=x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "www.letsencrypt.org"),
    ]),
    serial=decode_serial("03:68:12:0a:6f:c1:b6:f0:91:d9:ed:9b:21:aa:79:61:b5:da"),
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
                access_location=x509.UniformResourceIdentifier("http://ocsp.int-x3.letsencrypt.org"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://cert.int-x3.letsencrypt.org/"),
            ),
        ]), False),
        (x509.SubjectAlternativeName([
            x509.DNSName("cert.int-x1.letsencrypt.org"),
            x509.DNSName("cert.int-x2.letsencrypt.org"),
            x509.DNSName("cert.int-x3.letsencrypt.org"),
            x509.DNSName("cert.int-x4.letsencrypt.org"),
            x509.DNSName("cert.root-x1.letsencrypt.org"),
            x509.DNSName("cert.staging-x1.letsencrypt.org"),
            x509.DNSName("cert.stg-int-x1.letsencrypt.org"),
            x509.DNSName("cert.stg-root-x1.letsencrypt.org"),
            x509.DNSName("cp.letsencrypt.org"),
            x509.DNSName("cp.root-x1.letsencrypt.org"),
            x509.DNSName("cps.letsencrypt.org"),
            x509.DNSName("cps.root-x1.letsencrypt.org"),
            x509.DNSName("crl.root-x1.letsencrypt.org"),
            x509.DNSName("letsencrypt.org"),
            x509.DNSName("origin.letsencrypt.org"),
            x509.DNSName("origin2.letsencrypt.org"),
            x509.DNSName("status.letsencrypt.org"),
            x509.DNSName("www.letsencrypt.org"),
        ]), False),
        (x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=[]),
            x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.44947.1.1.1"), policy_qualifiers=[
                "http://cps.letsencrypt.org",
                x509.UserNotice(
                    notice_reference=None,
                    explicit_text=(
                        "This Certificate may only be relied upon by Relying Parties and only in accordance"
                        " with the Certificate Policy found at https://letsencrypt.org/repository/"
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
                "0481f200f0007600c1164ae0a772d2d4392dc80ac10770d4f0c49bde991a4840c1fa075164f6336000000164dd02853a00000"
                "4030047304502206e56a5f285e77e8a29af5f9d59586f071faca874f478b631247053691a778f54022100e1150a8c93a0c35d"
                "481c535d8adfaccb545c094dd0092384418ac9d7fa0f96d0007600293c519654c83965baaa50fc5807d4b76fbf587a2972dca"
                "4c30cf4e54547f47800000164dd02873e0000040300473045022100898e8ef92b8ad50d289641edd714b63a3221b7cdc1d0ac"
                "a6f4621335eebd5428022019af2a328374dc32e9f919bd9d127d5cb6d3273d6f6eebbd3f25d463be353fc1"
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
        Path("tests/integration/targets/certificate_complete_chain/files/roots/COMODO_Certification_Authority.pem"),
        "\n# Bar",
        Path("tests/integration/targets/certificate_complete_chain/files/roots/COMODO_ECC_Certification_Authority.pem"),
        "\n# Baz\n#Bam",
        Path("tests/integration/targets/certificate_complete_chain/files/roots/COMODO_RSA_Certification_Authority.pem"),
        Path("tests/integration/targets/certificate_complete_chain/files/roots/DST_Root_CA_X3.pem"),
        "# Jar",
        Path("tests/integration/targets/certificate_complete_chain/files/roots/ISRG_Root_X1.pem"),
    ]
)
