# blockchain_client.py
# Client for generating keys, signing transactions, and creating certificate transactions.

from flask import Flask, request, jsonify, render_template
import Crypto
import Crypto.Random
import binascii
from collections import OrderedDict
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import json
import hashlib
import requests
from urllib.parse import urljoin

app = Flask(__name__)

# NOTE: Set this to the server address (where blockchain_server.py is running)
BLOCKCHAIN_SERVER = 'http://127.0.0.1:5001/'


class Transaction:
    def __init__(self, sender_public_key, sender_private_key, recipient_public_key=None, amount=None, tx_type='transfer',
                 extra=None):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount
        self.type = tx_type
        self.extra = extra or {}

    def to_dict(self):
        base = {}
        if self.type == 'transfer':
            base = {
                'sender_public_key': self.sender_public_key,
                'recipient_public_key': self.recipient_public_key,
                'amount': self.amount,
                'type': 'transfer'
            }
        elif self.type == 'certificate':
            # extra should contain student_name, student_id, degree, year, university, certificate_hash
            base = {'type': 'certificate'}
            base.update(self.extra)
        return OrderedDict(sorted(base.items(), key=lambda t: t[0]))

    def sign_transaction(self):
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(json.dumps(self.to_dict(), sort_keys=True).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format('DER'))).decode('ascii')
    }
    return jsonify(response), 200


@app.route('/make/transaction')
def make_transaction_page():
    return render_template('./make_transaction.html')


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    amount = request.form['amount']

    tx = Transaction(sender_public_key, sender_private_key, recipient_public_key, amount, tx_type='transfer')
    signature = tx.sign_transaction()
    response = {'transaction': tx.to_dict(), 'signature': signature}
    # optionally, automatically post to blockchain server
    auto_post = request.form.get('post_to_server', 'no')
    if auto_post.lower() in ('yes', 'true', '1'):
        post_url = urljoin(BLOCKCHAIN_SERVER, 'transactions/new')
        payload = {
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'transaction_signature': signature,
            'amount': amount
        }
        r = requests.post(post_url, data=payload)
        return jsonify({'local': response, 'server_response': r.json(), 'server_status': r.status_code}), 200

    return jsonify(response), 200


@app.route('/make/certificate')
def make_certificate_page():
    return render_template('./make_certificate.html')


@app.route('/generate/certificate', methods=['POST'])
def generate_certificate():
    # certificate fields
    issuer_public_key = request.form['issuer_public_key']
    issuer_private_key = request.form['issuer_private_key']
    student_name = request.form['student_name']
    student_id = request.form['student_id']
    degree = request.form['degree']
    year = request.form['year']
    university = request.form['university']
    certificate_hash = request.form['certificate_hash']  # client computes off-line or via file hashing (not provided here)

    extra = {
        'student_name': student_name,
        'student_id': student_id,
        'degree': degree,
        'year': year,
        'university': university,
        'certificate_hash': certificate_hash
    }

    tx = Transaction(issuer_public_key, issuer_private_key, tx_type='certificate', extra=extra)
    signature = tx.sign_transaction()

    # Optionally post to blockchain server automatically
    post_url = urljoin(BLOCKCHAIN_SERVER, 'certificates/new')
    payload = {
        'student_name': student_name,
        'student_id': student_id,
        'degree': degree,
        'year': year,
        'university': university,
        'issuer_public_key': issuer_public_key,
        'signature': signature,
        'certificate_hash': certificate_hash
    }
    # Post to server
    r = requests.post(post_url, data=payload)
    return jsonify({'transaction': tx.to_dict(), 'signature': signature, 'server_response': r.json(), 'server_status': r.status_code}), 200


@app.route('/view/transaction')
def view_transaction():
    return render_template('./view_transaction.html')


@app.route('/verify/certificate', methods=['GET'])
def verify_certificate_page():
    """
    This endpoint just demonstrates how to query the blockchain server to verify.
    Query params forwarded to blockchain server's /certificates/verify
    """
    certificate_hash = request.args.get('certificate_hash')
    student_id = request.args.get('student_id')
    degree = request.args.get('degree')
    year = request.args.get('year')

    params = {}
    if certificate_hash:
        params['certificate_hash'] = certificate_hash
    else:
        params['student_id'] = student_id
        params['degree'] = degree
        params['year'] = year

    post_url = urljoin(BLOCKCHAIN_SERVER, 'certificates/verify')
    r = requests.get(post_url, params=params)
    return jsonify({'server_response': r.json(), 'server_status': r.status_code}), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8000, type=int, help='port')
    args = parser.parse_args()
    port = args.port
    app.run(host='127.0.0.1', port=port, debug=True)
