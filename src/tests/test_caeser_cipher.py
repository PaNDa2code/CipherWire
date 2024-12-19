
from ..caeser_cipher import CaesarCipher

def test_caeser_cipher():
    plan_text = "HelloWorld"
    key = 13
    cypher_text = CaesarCipher.encrypt(plan_text, key)
    decrypted_cypher_text = CaesarCipher.decrypt(cypher_text, key)
    assert plan_text == decrypted_cypher_text
    assert plan_text != cypher_text

