BASE=10
PRECISION=4

def encode(x):
    return int((x * (BASE ** PRECISION)) % Q)

def decode(x):
    return (x if x <= Q/2 else x - Q) / BASE**PRECISION
    
encode(3.5) <-- 35000
decode(35000) <-- 3.5