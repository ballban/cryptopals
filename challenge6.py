def hamming_distance(text1, text2):
  return sum([bin(x[0] ^ x[1]).count("1") for x in zip(text1, text2)])