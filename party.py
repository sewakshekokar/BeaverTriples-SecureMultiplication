"""
MPC Party implementation supporting:
- Additive and XOR secret sharing
- Parallel secure multiplications
- Dot product computation
"""

import socket
import pickle
from typing import Dict, List

HOST = 'localhost'
PORT = 9999

class MPCParty:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        """Connect to the coordinator"""
        self.socket.connect((HOST, PORT))
        self.run_protocol()

    def run_protocol(self):
        """Execute the MPC protocol"""
        # Phase 1: Receive shares and Beaver triples
        data = pickle.loads(self.socket.recv(4096))
        x_vec = data['x_vec']
        y_vec = data['y_vec']
        beavers = data['beavers']
        share_type = data['type']
        mod = data['mod']
        compute_dot = data.get('compute_dot', False)
        n = len(x_vec)

        # Phase 2: Compute masked values
        d_vec, e_vec = [], []
        for i in range(n):
            x = x_vec[i]
            y = y_vec[i]
            a = beavers[i]['a']
            b = beavers[i]['b']
            
            if share_type == "additive":
                d = (x - a) % mod
                e = (y - b) % mod
            else:  # XOR
                d = x ^ a
                e = y ^ b
            
            d_vec.append(d)
            e_vec.append(e)

        self.socket.sendall(pickle.dumps({'d': d_vec, 'e': e_vec}))

        # Phase 3: Receive public values
        msg = pickle.loads(self.socket.recv(4096))
        d_vec = msg['d_vec']
        e_vec = msg['e_vec']
        de_shares = msg.get('de_shares', [])

        # Phase 4: Compute shares
        products = []
        dot_share = 0
        
        for i in range(n):
            a = beavers[i]['a']
            b = beavers[i]['b']
            c = beavers[i]['c']
            
            if share_type == "additive":
                term = (de_shares[i] + d_vec[i] * b + e_vec[i] * a + c) % mod
            else:  # XOR
                term = (d_vec[i] & b) ^ (e_vec[i] & a) ^ c
            
            products.append(term)
            if compute_dot:
                if share_type == "additive":
                    dot_share = (dot_share + term) % mod
                else:
                    dot_share ^= term

        # Send results
        result = {
            'products': products,
            'dot_product': dot_share if compute_dot else None
        }
        self.socket.sendall(pickle.dumps(result))

if __name__ == "__main__":
    party = MPCParty()
    party.connect()