class CaesarCipher:
    def __init__(self, key: int) -> None:
        self.key = key
    def __call__(self, plan_text: str) -> str:
        return self.encrypt(plan_text, self.key)

    def __str__(self) -> str:
        return f"CaesarCipher encryption object with key {self.key}"

    @staticmethod
    def encrypt(plan_text: str, key: int) -> str:
        try:
            key = int(key)
        except:
            raise TypeError("Key should be a numeric value")
        cypher_text = []
        for c in plan_text:
            if c.isalpha():
                shift_base = ord('A') if c.isupper() else ord('a')
                cypher_text.append(chr(
                    (ord(c) - shift_base + key) % 26 + shift_base
                    ))
            else:
                cypher_text.append(c)
        return "".join(cypher_text)

    @staticmethod
    def decrypt(cypher_text: str, key: int) -> str:
        try:
            key = int(key)
        except:
            raise TypeError("Key should be a numeric value")
        plan_text = []
        for c in cypher_text:
            if c.isalpha():
                shift_base = ord('A') if c.isupper() else ord('a')
                plan_text.append(chr(
                    (ord(c) - shift_base - key) % 26 + shift_base
                    ))
            else:
                plan_text.append(c)
        return "".join(plan_text)

