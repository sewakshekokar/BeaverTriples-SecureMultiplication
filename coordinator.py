"""
MPC Coordinator for secure multi-party computations
Supports:
- Additive and XOR secret sharing
- Parallel secure multiplications
- Dot product computation
"""

import socket
import threading
import random
import pickle
from time import time
from typing import List, Tuple

# Configuration
NUM_PARTIES = 3
HOST = 'localhost'
PORT = 9999
SHARE_TYPE = "additive"  # "xor" or "additive"
MODULUS = 67  # Prime field for additive sharing

class MPCCoordinator:
    def __init__(self):
        self.clients = []
        self.lock = threading.Lock()

    def share_secret(self, secret: int) -> List[int]:
        """Generate secret shares for additive or XOR sharing"""
        if SHARE_TYPE == "additive":
            shares = [random.randint(0, MODULUS-1) for _ in range(NUM_PARTIES-1)]
            shares.append((secret - sum(shares)) % MODULUS)
        else:  # XOR sharing
            assert secret in (0, 1), "XOR sharing requires binary inputs"
            shares = [random.randint(0, 1) for _ in range(NUM_PARTIES-1)]
            shares.append(secret ^ sum(shares) % 2)
        return shares

    def generate_beaver_triples(self, n: int) -> Tuple[List, List, List]:
        """Generate Beaver triples for n parallel multiplications"""
        a_list, b_list, c_list = [], [], []
        for _ in range(n):
            if SHARE_TYPE == "additive":
                a = random.randint(0, MODULUS-1)
                b = random.randint(0, MODULUS-1)
                c = (a * b) % MODULUS
            else:
                a = random.randint(0, 1)
                b = random.randint(0, 1)
                c = a & b
            a_list.append(self.share_secret(a))
            b_list.append(self.share_secret(b))
            c_list.append(self.share_secret(c))
        return a_list, b_list, c_list

    def run_computation(self):
        """Main MPC computation workflow"""
        print(f"\n Running {SHARE_TYPE.upper()} MPC Protocol")
        
        # Input vectors (example values)
        x_vec = [4, 2, 7] if SHARE_TYPE == "additive" else [1, 0, 1]
        y_vec = [5, 9, 1] if SHARE_TYPE == "additive" else [1, 1, 0]
        n = len(x_vec)
        
        print(f"Input vectors (n={n}):")
        print(f"x = {x_vec}")
        print(f"y = {y_vec}")

        # Phase 1: Share inputs and Beaver triples
        x_shares = [self.share_secret(x) for x in x_vec]
        y_shares = [self.share_secret(y) for y in y_vec]
        a_shares, b_shares, c_shares = self.generate_beaver_triples(n)

        # Send data to parties
        for i, client in enumerate(self.clients):
            data = {
                'x_vec': [x_shares[j][i] for j in range(n)],
                'y_vec': [y_shares[j][i] for j in range(n)],
                'beavers': [{
                    'a': a_shares[j][i],
                    'b': b_shares[j][i],
                    'c': c_shares[j][i]
                } for j in range(n)],
                'type': SHARE_TYPE,
                'mod': MODULUS,
                'compute_dot': True  # Request dot product computation
            }
            client.sendall(pickle.dumps(data))

        # Phase 2: Collect masked values
        responses = [pickle.loads(client.recv(4096)) for client in self.clients]
        d_vec = [0] * n
        e_vec = [0] * n

        for r in responses:
            for j in range(n):
                if SHARE_TYPE == "additive":
                    d_vec[j] = (d_vec[j] + r['d'][j]) % MODULUS
                    e_vec[j] = (e_vec[j] + r['e'][j]) % MODULUS
                else:
                    d_vec[j] ^= r['d'][j]
                    e_vec[j] ^= r['e'][j]

        # Phase 3: Compute and share d*e terms
        if SHARE_TYPE == "additive":
            de_shares = [self.share_secret((d_vec[j] * e_vec[j]) % MODULUS) for j in range(n)]
        else:
            de_shares = [[] for _ in range(n)]  # Not needed for XOR

        # Send reconstruction data
        for i, client in enumerate(self.clients):
            msg = {
                'd_vec': d_vec,
                'e_vec': e_vec,
                'de_shares': [de_shares[j][i] for j in range(n)] if SHARE_TYPE == "additive" else []
            }
            client.sendall(pickle.dumps(msg))

        # Phase 4: Collect results
        result_shares = [pickle.loads(client.recv(4096)) for client in self.clients]
        
        # Reconstruct individual products
        products = [0] * n
        for r in result_shares:
            for j in range(n):
                if SHARE_TYPE == "additive":
                    products[j] = (products[j] + r['products'][j]) % MODULUS
                else:
                    products[j] ^= r['products'][j]

        # Reconstruct dot product
        dot_product = 0
        for r in result_shares:
            if SHARE_TYPE == "additive":
                dot_product = (dot_product + r['dot_product']) % MODULUS
            else:
                dot_product ^= r['dot_product']

        # Verification
        expected_products = [
            (x_vec[j] * y_vec[j]) % MODULUS if SHARE_TYPE == "additive" else x_vec[j] & y_vec[j]
            for j in range(n)
        ]
        expected_dot = sum(expected_products) % MODULUS if SHARE_TYPE == "additive" else sum(expected_products) % 2

        print("\n Results:")
        print(f"Secure Products: {products}")
        print(f"Actual Products: {expected_products}")
        print(f"\nSecure Dot Product: {dot_product}")
        print(f"Actual Dot Product: {expected_dot}")

    def start(self):
        """Start the coordinator server"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            print(f"MPC Coordinator waiting for {NUM_PARTIES} parties...")

            while len(self.clients) < NUM_PARTIES:
                conn, addr = s.accept()
                with self.lock:
                    self.clients.append(conn)
                print(f"[+] Party connected: {addr}")
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

            # All parties connected, start computation
            self.run_computation()

            # Keep server alive
            while True:
                pass

    def handle_client(self, conn, addr):
        """Handle client connections"""
        with conn:
            while True:
                pass  # All communication handled in main thread

if __name__ == "__main__":
    coordinator = MPCCoordinator()
    coordinator.start()