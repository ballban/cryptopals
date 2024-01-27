from collections import defaultdict
from utility import *


def try_decrypt(text):
  if(type(text) == str):
    text_bytes = bytes.fromhex(text)
  else:
    text_bytes = text
  #print(text_bytes)

  keys = range(0, 127)
  scores = defaultdict(int)
  for key in keys:
    decrypt_text = ''
    for i in range(len(text_bytes)):
      x = text_bytes[i]
      decrypt_text += chr(x ^ key)
    scores[key] = get_score(decrypt_text)
  scores = sorted(scores.items(), key=lambda x:x[1], reverse=True)
  #print(scores[:10])

  true_key = scores[0][0]

  result = ''
  for i in range(len(text_bytes)):
      x = text_bytes[i]
      result += chr(x ^ true_key)
  return scores[0][1], result, true_key


def get_score(text):
  score_dic = {"E":11.16,"A":8.50,"R":7.58,"I":7.54,"O":7.16,"T":6.95,"N":6.65,"S":5.74,"L":5.49,"C":4.54,"U":3.63,"D":3.38,"P":3.17,"M":3.01,"H":3.00,"G":2.47,"B":2.07,"F":1.81,"Y":1.78,"W":1.29,"K":1.10,"V":1.01,"X":0.29,"Z":0.27,"J":0.20,"Q":0.20,"e":11.16,"a":8.50,"r":7.58,"i":7.54,"o":7.16,"t":6.95,"n":6.65,"s":5.74,"l":5.49,"c":4.54,"u":3.63,"d":3.38,"p":3.17,"m":3.01,"h":3.00,"g":2.47,"b":2.07,"f":1.81,"y":1.78,"w":1.29,"k":1.10,"v":1.01,"x":0.29,"z":0.27,"j":0.20,"q":0.20," ":18}
  score = 0
  for key, value in get_frequency_dic(text):
    if key in score_dic:
      score += score_dic[key] * value
    elif key not in string.printable:
      score = 0
      break
  return round(score, 2)


def get_frequency_dic(text):
  fre_bytes = defaultdict(int)
  for i in range(len(text)):
    x = text[i]
    fre_bytes[x] += 1
  return sorted(fre_bytes.items(), key=lambda x:x[1], reverse=True)