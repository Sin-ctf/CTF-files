def G(x, a, b):
  t = (a + b + x) % 256
  return ((t << 2) & (2**8-1)) | t >> (6)

def round_function(x,key):
  a, b, c, d = x
  k0, k1, k2, k3 = key
  b = a ^ b ^ k1
  c = c ^ d ^ k2
  b = G(1, b, c)
  c = G(0, c, b)
  a = G(0, a ^ k0, b)
  d = G(1, d ^ k3, c)
  return [a, b, c, d]


def xor(a, b):
  assert len(a) == len(b)
  return map(lambda x: x[0] ^ x[1], zip(a, b))

class FEAL(object):
  def __init__(s, r, keys):
    assert len(keys) == r
    s.r = r
    s.keys = keys

  def encrypt(s, m):
    assert len(m) == 8
    L = m[:4]
    R = xor(m[4:], L)
    for ROUND in xrange(s.r-1):
      t = round_function(R, s.keys[ROUND])
      L, R = R, xor(L, t)
    t = round_function(R, s.keys[3])
    L = xor(L, t)
    R = xor(L, R)
    return L + R
