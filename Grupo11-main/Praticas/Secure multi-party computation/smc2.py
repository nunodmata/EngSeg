def mul(x, y):
    a, b, a_mul_b = generate_mul_triple()
    
    alpha = decrypt(x - a) #x remains hidden because a is random 
    beta  = decrypt(y - b) #y remains hidden because b is random 
    
    #local re-combination
    return alpha.mul(beta) + alpha.mul(b) + a.mul(beta) + a_mul_b