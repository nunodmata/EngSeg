#### Pergunta P.VIII.1.1

No âmbito desta pergunta necessita de ter acesso ao seu certificado de assinatura do Cartão de Cidadão ou ao seu certificado de assinatura da Chave Móvel Digital. Caso não tenha acesso a nenhum deles, pode obter um certificado de assinatura da Chave Móvel Digital numa Loja do Cidadão ou num Espaço Cidadão (ou então, online em <https://www.autenticacao.gov.pt>, para o que precisa de aceder ao seu certificado de autenticação do Cartão de Cidadão).

1. Utilize o openssl para ver o conteúdo do seu certificado CC/CMD.

   O certificado tem:
   + Uma versão.
   + Um serial number
   + A especificação do algoritmo de assinatura de forma a tornar possível depois validar.
   + O Issuer ( A entidade que emitiu o mesmo)
   + A validade ( a data depois da emissão e a data de fim de validade)
   + O Subject ( A pessoa que adquire o certificado)
   + A chave publica do sujeito
   + Info sobre X509 , nomeadamente a chave identificadora da autoridade , O CRL , as policies do certificado e mais informação referente ao X509. O X509 permite agarrar com certeza um nome à chave pública
   + O algoritmo de assinatura com a sua respetiva chave
   
    


2. Utilizando a(s) biblioteca(s) que achar mais adequada, desenvolva um program linha de comando em Python que tem como input um certificado (neste caso, o exemplo que terá que testar é com o seu certificado CC/CMD, mas deve funcionar para o caso geral de certificados CC/CMD), e vai indicar se o mesmo está ou não revogado através da consulta da CRL.
   + Indique o motivo da escolha da(s) biblioteca(s).
   + Note que o seu programa terá que "ir" à estrutura do certificado para obter o URL da CRL, após o que terá de ir buscar a CRL e verificar se o seu certificado faz parte da mesma ou não. 
   + Como output, o seu programa deverá indicar o URL da CRL, a data da CRL atual e da próxima CRL, assim como o estado do seu certificado - se estiver revogado deve indicar a data em que foi revogado.
``` python 
import OpenSSL
import subprocess
from shlex import split
import wget
import sys


valid = True
revoked = False
certname = sys.argv[1]
opensslcmd = 'openssl x509 -noout -text -inform DER -in '
opensslcmd += certname
print(opensslcmd)

p1 = subprocess.Popen(split(opensslcmd), stdout = subprocess.PIPE)
p2 = subprocess.Popen(split("grep -A4 'X509v3 CRL Distribution Points'"), stdin = p1.stdout , stdout=subprocess.PIPE)
p3 = subprocess.Popen(split("grep -A0 'http'"), stdin = p2.stdout , stdout=subprocess.PIPE)
uristring = p3.communicate()[0].decode('utf-8')




urlstringdone = uristring.lstrip()[4:]
print('crl url:' , urlstringdone)

crl_filename = wget.download(urlstringdone,bar = None)

crl = bytearray()
with open(certname, 'rb') as cer_file:
    cer_file_load=cer_file.read()

cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cer_file_load)
myserialnumber = cert.get_serial_number()
#print(myserialnumber)


with open(crl_filename, 'rb') as crl_file:
    crl_file_load=crl_file.read()

cert = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl_file_load)
revoked_list = cert.get_revoked()
for inv in revoked_list:
    if inv.get_serial() == myserialnumber:
        print('Data em que foi revogado:' , inv.get_rev_date())
        valid = False
        revoked = True
        break

crlopensslcmd = 'openssl crl -inform DER -text -noout -in '
crlopensslcmd += crl_filename

p5 = subprocess.Popen(split(crlopensslcmd), stdout = subprocess.PIPE)
p6 = subprocess.Popen(split("grep -A0 'Last Update:'"), stdin = p5.stdout , stdout=subprocess.PIPE)
p7 = subprocess.Popen(split(crlopensslcmd), stdout = subprocess.PIPE)
p8 = subprocess.Popen(split("grep -A0 'Next Update:'"), stdin = p7.stdout , stdout=subprocess.PIPE)
p5.stdout.close()
p7.stdout.close()
lastupdate = p6.communicate()[0].decode('utf-8').lstrip()
print(lastupdate)
print(p8.communicate()[0].decode('utf-8').lstrip())
if len(lastupdate) == 0:
    valid = False
if valid:
    print("Cert valido")
else:
    if revoked:
        print('Cert Revogado')
    else:
        print("Cert invalido")
   
        

```


3. Utilizando a(s) biblioteca(s) que achar mais adequada, desenvolva um program linha de comando em Python que tem como input um certificado (neste caso, o exemplo que terá que testar é com o seu certificado CC/CMD, mas deve funcionar para o caso geral de certificados CC/CMD), e vai indicar se o mesmo está ou não revogado através da consulta do OCSP.
   + Indique o motivo da escolha da(s) biblioteca(s).
   + Note que o seu programa terá que "ir" à estrutura do certificado para obter o URL do serviço de OCSP, após o que terá de comunicar com o servidor OCSP para obter o estado do certificado. 
   + Como output, o seu programa deverá indicar o URL do OCSP, a data de resposta do servidor OCSP, assim como o estado do seu certificado - se estiver revogado deve indicar a data em que foi revogado.

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, ocsp
import requests
import base64
import logging
from cryptography.x509.ocsp import OCSPResponseStatus, OCSPCertStatus
from urllib.parse import urljoin
import sys
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

certname = sys.argv[1]

def load_cert(filename):
    with open(filename, 'rb') as file:
        tmp = file.read()
    return tmp

def get_ocsp_request(ocsp_server, cert, issuer_cert):
    req_path = get_der_ocsp_request(cert,issuer_cert)
    return ocsp_server + '/' + req_path.decode('utf-8')

def get_der_ocsp_request(cert,issuer_cert):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, SHA1())
    req = builder.build()
    req_path = base64.b64encode(req.public_bytes(serialization.Encoding.DER))
    return req_path

def get_ocsp_cert_response(ocsp_server, cert, issuer_cert):
    ocsp_resp = requests.get(get_ocsp_request(ocsp_server,cert,issuer_cert))
    if ocsp_resp.ok:
        ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp.content)
        if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
            return ocsp_decoded
        else:
            raise Exception(f'decoding ocsp response failed: {ocsp_decoded.response_status}')
    raise Exception(f'fetching ocsp cert status failed with response status: {ocsp_resp.status_code}')

def get_ocsp_server(cert):
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    ocsps = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP]
    if not ocsps:
        raise Exception(f'no ocsp server entry in AIA')
    return ocsps[0].access_location.value

pem_cert = load_cert(certname)
pem_issuer = load_cert('cmd004.pem')
cert = load_pem_x509_certificate(pem_cert,backend = default_backend())
issuer = load_pem_x509_certificate(pem_issuer,backend = default_backend())
ocsp_server = get_ocsp_server(cert)
print('Ocsp url : ' , ocsp_server)
ocspresponse = get_ocsp_cert_response(ocsp_server,cert,issuer)
print('Data da resposta do servidor OCSP:', ocspresponse.this_update )
print("Estado do certificado: " ,ocspresponse.certificate_status)
if ocspresponse.certificate_status == OCSPCertStatus.REVOKED:
    print('Data da revogacao: ', ocspresponse.revocation_time)

```
