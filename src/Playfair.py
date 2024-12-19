from typing import Dict, List, Tuple

class Playfair:
    def __init__(self, key: str) -> None:
        self.key = key

    def __call__(self, plan_text: str) -> None:
        pass

    @staticmethod
    def __generate_matrix_key(key: str) -> Tuple[List[List[str]], Dict[str, Tuple[int, int]]]:
        unique_chars = []
        for char in key.upper():
            if char not in unique_chars:
                if char == "J":
                    char = "I"
                unique_chars.append(char)

        all_letters = [chr(i) for i in range(ord('A'), ord('Z') + 1) if chr(i) != 'J']
        for letter in all_letters:
            if letter not in unique_chars:
                unique_chars.append(letter)

        matrix = []
        lookup = {}
        for i in range(5):
            row = unique_chars[i * 5:(i + 1) * 5]
            matrix.append(row)
            for j, char in enumerate(row):
                lookup[char] = (i, j)

        return matrix, lookup

    @staticmethod
    def __split_into_pairs(text: str, filler: str = 'x') -> List[str]:
        text = text.replace(" ", "")
        pairs = []
        i = 0
        while i < len(text):
            char1 = text[i]
            if i + 1 < len(text):
                char2 = text[i + 1]
                if char1 != char2:
                    pairs.append(char1 + char2)
                    i += 2
                else:
                    pairs.append(char1 + filler)
                    i += 1
            else:
                pairs.append(char1 + filler)
                i += 1

        return pairs

    @staticmethod
    def encrypt(key: str, plan_text: str) -> str:
        matrix, lookup = Playfair.__generate_matrix_key(key)
        pairs = Playfair.__split_into_pairs(plan_text)

        cipher_text = []

        for pair in pairs:
            location1, location2 = lookup[pair[0]], lookup[pair[1]]
            char1, char2 = None, None

            if location1[0] == location2[0]:
                char1 = matrix[location1[0]][(location1[1] + 1) % 5]
                char2 = matrix[location2[0]][(location2[1] + 1) % 5]

            elif location1[1] == location2[1]:
                char1 = matrix[(location1[0] + 1) % 5][location1[1]]
                char2 = matrix[(location2[0] + 1) % 5][location2[1]]

            else:
                char1 = matrix[location1[0]][location2[1]]
                char2 = matrix[location2[0]][location1[1]]

            cipher_text.append(char1)
            cipher_text.append(char2)

        return "".join(cipher_text)

    @staticmethod
    def decrypt(key: str, cipher_text: str) -> str:
        matrix, lookup = Playfair.__generate_matrix_key(key)
        pairs = Playfair.__split_into_pairs(cipher_text)

        plain_text = []

        for pair in pairs:
            location1, location2 = lookup[pair[0]], lookup[pair[1]]
            char1, char2 = None, None

            if location1[0] == location2[0]:
                char1 = matrix[location1[0]][(location1[1] - 1) % 5]
                char2 = matrix[location2[0]][(location2[1] - 1) % 5]
            elif location1[1] == location2[1]:
                char1 = matrix[(location1[0] - 1) % 5][location1[1]]
                char2 = matrix[(location2[0] - 1) % 5][location2[1]]
            else:
                char1 = matrix[location1[0]][location2[1]]
                char2 = matrix[location2[0]][location1[1]]

            plain_text.append(char1)
            plain_text.append(char2)

        return "".join(plain_text)
