import urllib.parse
import re


def profile_for(input: str):
  input = re.sub(r'\&', '', input)
  input = re.sub(r'\=', '', input)
  params = {'email': input, 'uid': 10, 'role': 'user'}
  return urllib.parse.urlencode(params)