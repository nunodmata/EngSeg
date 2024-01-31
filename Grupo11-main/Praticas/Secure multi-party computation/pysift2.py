import random

Q = 121639451781281043402593

def encrypt(x, n_shares = 2):
    shares = list()
    
    for i in range(n_shares-1):
        shares.append(random.randint(0,Q))
        
    final_share = Q - (sum(shares) % Q) + x
    
    share.append(final_share)
    
    return tuple(shares)
    
def decrypt(shares):
    return sum(shares) % Q
    
def add(a, b):
    c = list()
    
    assert(len(a) == len(b))
    
    for i in range(len(a)):
        c.append((a[i] + b[i]) % Q)
        
    return tuple(c)