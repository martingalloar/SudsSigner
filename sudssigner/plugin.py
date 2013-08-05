#!/usr/bin/env python

from __future__ import with_statement
from suds.plugin import MessagePlugin
from lxml import etree
from suds.bindings.binding import envns
from suds.wsse import wsuns, dsns, wssens
from libxml2_wrapper import LibXML2ParsedDocument
from xmlsec_wrapper import XmlSecSignatureContext, init_xmlsec, deinit_xmlsec
from OpenSSL import crypto
from uuid import uuid4

import xmlsec


def lxml_ns(suds_ns):
    return dict((suds_ns,))

def lxml_nss(suds_ns):
    d = {}
    for ns,uri in suds_ns:
        d[ns] = uri
    return d

def ns_id(tagname, suds_ns):
    return '{{{0}}}{1}'.format(suds_ns[1], tagname)

# Constants missing in xmlsec.strings
AttrEncodingType = 'EncodingType'
AttrValueType = 'ValueType'

NodeBinarySecurityToken = 'BinarySecurityToken'
NodeSecurity = 'Security'
NodeSecurityTokenReference = 'SecurityTokenReference'


LXML_ENV = lxml_ns(envns)
BODY_XPATH = etree.XPath('/SOAP-ENV:Envelope/SOAP-ENV:Body', namespaces=LXML_ENV)
HEADER_XPATH = etree.XPath('/SOAP-ENV:Envelope/SOAP-ENV:Header', namespaces=LXML_ENV)
SECURITY_XPATH = etree.XPath('/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security', namespaces=lxml_nss([envns, wssens]))
TIMESTAMP_XPATH = etree.XPath('/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/wsu:Timestamp', namespaces=lxml_nss([envns, wssens, wsuns]))
B64ENC = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'
X509PROFILE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
CERTREF = 'x509cert00'
BEGINCERT = "-----BEGIN CERTIFICATE-----"
ENDCERT = "-----END CERTIFICATE-----"
NSMAP = dict((dsns, wssens, wsuns))
WSU_ID = ns_id(xmlsec.AttrId, wsuns)
DS_DIGEST_VALUE = ns_id(xmlsec.NodeDigestValue, dsns)
DS_REFERENCE = ns_id(xmlsec.NodeReference, dsns)
DS_TRANSFORMS = ns_id(xmlsec.NodeTransforms, dsns)
WSSE_BST = ns_id(NodeBinarySecurityToken, wssens)
DS_SIGNATURE = ns_id(xmlsec.NodeSignature, dsns)


class SignerPlugin(MessagePlugin):
    def __init__(self, 
                 keyfile,
                 items_to_sign=None,
                 keytype=None,
                 pwd=None, pwdCallback=None, pwdCallbackCtx=None,
                 transform_algorithm=None,
                 digestmethod_algorithm=None):
        init_xmlsec()
        self.keyfile = keyfile
        self.pwd = pwd
        self.pwdCallback = pwdCallback
        self.pwdCallbackCtx = pwdCallbackCtx
        self.load_keyfile()
        self.keytype = self.handle_keytype(keytype)
        self.items_to_sign = items_to_sign or [BODY_XPATH, TIMESTAMP_XPATH]
        self.transform_algorithm = transform_algorithm or xmlsec.HrefExcC14N
        self.digestmethod_algorithm = digestmethod_algorithm or xmlsec.HrefSha1

    def load_keyfile(self):
        cert = file(self.keyfile, 'rb').read()
        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        self.privatekey = crypto.load_privatekey(crypto.FILETYPE_PEM, cert)

    def handle_keytype(self, keytype):
        if keytype is None:
            return self.detect_keytype()
        elif any(isinstance(keytype, t) for t in (str, unicode)):
            return keytype
        else:
            raise ValueError('keytype must be a string or None')

    def detect_keytype(self):
        algo = self.privatekey.type()
        if algo == crypto.TYPE_DSA:
            return xmlsec.HrefDsaSha1
        if algo == crypto.TYPE_RSA:
            return xmlsec.HrefRsaSha1
        raise ValueError('unknown keytype')

    def marshalled(self, context):
        # !!! Axis needs the same namespace as Header and Envelope
        context.envelope[1].prefix = context.envelope.prefix
        pass

    def sending(self, context):
        """
        sending plugin method: add security headers and sign msg
        """
        env = etree.fromstring(context.envelope)
        queue = SignQueue(self.transform_algorithm, self.digestmethod_algorithm)

        for item_to_sign in self.items_to_sign:
            if isinstance(item_to_sign, tuple):
                (item_path, item_id) = item_to_sign
            else:
                (item_path, item_id) = (item_to_sign, None)
                
            for item_elem in item_path(env):
                queue.push_and_mark(item_elem, item_id)
            
        security = ensure_security_header(env, queue)
        btkn = etree.SubElement(security, WSSE_BST, {
                AttrEncodingType: B64ENC,
                AttrValueType: X509PROFILE,
                WSU_ID: CERTREF,
            }, NSMAP)
        crt = crypto.dump_certificate(crypto.FILETYPE_PEM, self.cert)
        crt = crt.replace('\n', '').replace(BEGINCERT, '').replace(ENDCERT, '')
        btkn.text = crt
        self.insert_signature_template(security, queue)
        context.envelope = self.get_signature(etree.tostring(env))

    def insert_signature_template(self, security, queue):
        signature = etree.SubElement(security, DS_SIGNATURE)
        self.append_signed_info(signature, queue)
        etree.SubElement(signature, ns_id(xmlsec.NodeSignatureValue, dsns))
        self.append_key_info(signature)

    def append_signed_info(self, signature, queue):
        signed_info = etree.SubElement(signature, ns_id(xmlsec.NodeSignedInfo, dsns))
        set_algorithm(signed_info, xmlsec.NodeCanonicalizationMethod, self.transform_algorithm)
        set_algorithm(signed_info, xmlsec.NodeSignatureMethod, self.keytype)
        queue.insert_references(signed_info)

    def append_key_info(self, signature):
        key_info = etree.SubElement(signature, ns_id(xmlsec.NodeKeyInfo, dsns))
        sec_token_ref = etree.SubElement(key_info,
                ns_id(NodeSecurityTokenReference, wssens))
        etree.SubElement(sec_token_ref, ns_id(xmlsec.NodeReference, wssens), {
            xmlsec.AttrURI: '#%s' % CERTREF,
            AttrValueType: X509PROFILE,
        })
        x509_data = etree.SubElement(sec_token_ref, ns_id(xmlsec.NodeX509Data, dsns))
        x509_issuer_serial = etree.SubElement(x509_data,
                ns_id(xmlsec.NodeX509IssuerSerial, dsns))
        x509_issuer_name = etree.SubElement(x509_issuer_serial,
                ns_id(xmlsec.NodeX509IssuerName, dsns))
        x509_issuer_name.text = ', '.join(
                '='.join(c) for c in self.cert.get_issuer().get_components())
        x509_serial_number = etree.SubElement(x509_issuer_serial,
                ns_id(xmlsec.NodeX509SerialNumber, dsns))
        x509_serial_number.text = str(self.cert.get_serial_number())

    def get_signature(self, envelope):
        with LibXML2ParsedDocument(envelope) as doc:
            root = doc.getRootElement()
            xmlsec.addIDs(doc, root, [xmlsec.AttrId])
            signNode = xmlsec.findNode(root, xmlsec.NodeSignature, xmlsec.DSigNs)
            with XmlSecSignatureContext(self) as dsig_ctx:
                if dsig_ctx.sign(signNode) < 0:
                    raise RuntimeError('signature failed')
                return doc.serialize()

    def __del__(self):
        deinit_xmlsec()


class SignQueue(object):

    def __init__(self, transform_algorithm, digestmethod_algorithm):
        self.queue = []
        self.transform_algorithm = transform_algorithm
        self.digestmethod_algorithm = digestmethod_algorithm

    def push_and_mark(self, element, unique_id=None):
        unique_id = unique_id or get_unique_id()
        element.set(WSU_ID, unique_id)
        self.queue.append(unique_id)

    def insert_references(self, signed_info):
        for element_id in self.queue:
            reference = etree.SubElement(signed_info, DS_REFERENCE,
                    {xmlsec.AttrURI: '#{0}'.format(element_id)})
            transforms = etree.SubElement(reference, DS_TRANSFORMS)
            set_algorithm(transforms, xmlsec.NodeTransform, self.transform_algorithm)
            set_algorithm(reference, xmlsec.NodeDigestMethod, self.digestmethod_algorithm)
            etree.SubElement(reference, DS_DIGEST_VALUE)


def get_unique_id():
    return 'id-{0}'.format(uuid4())


def set_algorithm(parent, name, value):
    etree.SubElement(parent, ns_id(name, dsns), {xmlsec.AttrAlgorithm: value})


def ensure_security_header(env, queue):
    (header,) = HEADER_XPATH(env)
    security = SECURITY_XPATH(header)
    if security:
        return security[0]
    else:
        d = {}
        #!!! With Axis 1.x this does not work
        #d[ns_id('mustUnderstand', envns)] = '1'
        security = etree.SubElement(header, ns_id(NodeSecurity, wssens), d, NSMAP)
        return security
