def generate_mul_triple():
    a = random.randrange(Q)
    b = random.randrange(Q)
    a_mul_b = (a * b) % Q
    return encrypt(a), encrypt(b), encrypt(a_mul_b)
    