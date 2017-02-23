# -*- coding: utf-8 -*-

from OpenSSL.crypto import (X509Extension, X509, dump_privatekey, dump_certificate, load_certificate, load_privatekey,
                            PKey, TYPE_RSA, X509Req)
from OpenSSL.SSL import FILETYPE_PEM
import os
import threading

class CertificateAuthority(object):
    """docstring for CertificateAuthority"""
    def __init__(self, certsDir="certs"):
        super(CertificateAuthority, self).__init__()
        self.certsDir = certsDir
        self.caFile = "%s/CA/ca.pem" % self.certsDir
        
        self._load()
        self._serial = self._get_serial()
        self.genCertLock = threading.Lock()


    def _load(self):
        if not os.path.isdir(self.certsDir):
            os.mkdir(self.certsDir)
            os.mkdir("%s/CA" % self.certsDir)
            self._generateCA()
        else:
            self._loadCA()
        

    def _generateCA(self):
        key = PKey()
        key.generate_key(TYPE_RSA, 2048)

        cert = X509()
        cert.set_version(3)
        cert.set_serial_number(1)
        cert.get_subject().CN = 'proxy.ca'
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.add_extensions([
            X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
            X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
            ])
        cert.sign(key, "sha1")

        with open(self.caFile, 'wb+') as f:
            f.write(dump_privatekey(FILETYPE_PEM, key))
            f.write(dump_certificate(FILETYPE_PEM, cert))

        self.key = key
        self.cert = cert


    def _loadCA(self):
        self.cert = load_certificate(FILETYPE_PEM, open(self.caFile).read())
        self.key = load_privatekey(FILETYPE_PEM, open(self.caFile).read())


    def getCACert(self):
        return dump_certificate(FILETYPE_PEM, self.cert)


    def getCert(self, host):
        certPath = "%s/%s.pem" % (self.certsDir, host)
        if not os.path.exists(certPath):
            self._generateCert(host, certPath)
        return certPath


    def _generateCert(self, host, certPath):
        key = PKey()
        key.generate_key(TYPE_RSA, 2048)

        req = X509Req()
        req.get_subject().CN = host
        req.set_pubkey(key)
        req.sign(key, "sha1")

        cert = X509()
        cert.set_subject(req.get_subject())
        cert.set_serial_number(self.serial)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(31536000)
        cert.set_issuer(self.cert.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(self.key, 'sha1')

        with open(certPath, 'wb+') as f:
            f.write(dump_privatekey(FILETYPE_PEM, key))
            f.write(dump_certificate(FILETYPE_PEM, cert))


    def _get_serial(self):
        num = 1
        for cPath in filter(lambda x: x.endswith('.pem'), os.listdir(self.certsDir)):
            currS = load_certificate(FILETYPE_PEM, open(os.path.sep.join([self.certsDir, cPath])).read()).get_serial_number()
            if currS > num:
                num = currS
        return num


    @property
    def serial(self):
        self.genCertLock.acquire()
        self._serial += 1
        self.genCertLock.release()
        return self._serial
