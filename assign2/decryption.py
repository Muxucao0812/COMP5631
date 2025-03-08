from collections import Counter
import string

# Function to extract only alphabetic characters from the text
def extract_letters(text):
    return ''.join(c for c in text if c.isalpha())

# Function to apply the substitution mapping to the text
def apply_substitution(text, mapping):
    result = []
    for c in text:
        if c.isupper() and c in mapping:
            result.append(mapping[c].lower())
        else:
            result.append(c)  # Preserve non-letters (spaces, punctuation)
    return ''.join(result)

# Function to score the decrypted text based on common words
def score_text(text, common_words):
    words = text.lower().split()
    words = [word.strip(string.punctuation) for word in words]
    return sum(1 for word in words if word in common_words)

# Function to perform hill-climbing to improve the mapping
def improve_mapping(mapping, ciphertext, common_words, locked_letters, max_swaps=5):
    cipher_letters = [chr(i) for i in range(ord('A'), ord('Z') + 1)]
    current_score = score_text(apply_substitution(ciphertext, mapping), common_words)
    swaps_done = 0
    improved = True

    while swaps_done < max_swaps and improved:
        improved = False
        for i in range(26):
            letter_i = cipher_letters[i]
            if letter_i in locked_letters:
                continue
            for j in range(i + 1, 26):
                letter_j = cipher_letters[j]
                if letter_j in locked_letters:
                    continue
                temp_mapping = mapping.copy()
                temp_mapping[letter_i], temp_mapping[letter_j] = (
                    temp_mapping[letter_j],
                    temp_mapping[letter_i]
                )
                temp_text = apply_substitution(ciphertext, temp_mapping)
                temp_score = score_text(temp_text, common_words)
                if temp_score > current_score:
                    mapping = temp_mapping
                    current_score = temp_score
                    improved = True
                    swaps_done += 1
                    print(f"Swap {swaps_done}: Score {current_score}")
                    break
            if improved:
                break
    return mapping, current_score

# The ciphertext to decrypt
ciphertext_pth = "ciphertext.txt"
with open(ciphertext_pth, "r") as f:
    ciphertext = f.read().strip()

# Compute letter frequencies in the ciphertext
letters = extract_letters(ciphertext)
letter_freq = Counter(letters)
sorted_letter_freq = sorted(letter_freq.items(), key=lambda x: x[1], reverse=True)
cipher_letters_by_freq = [letter for letter, freq in sorted_letter_freq]

# Standard English letter frequency order
english_freq_order = 'ETAONRISHDLCUMFPGWYBVKXJQZ'

# Create initial mapping based on frequency
mapping = {cipher_letters_by_freq[i]: english_freq_order[i].lower() for i in range(26)}

# List of common English words for scoring
common_words = ['the', 'of', 'and', 'to', 'in', 'a', 'is', 'that', 'for', 'it', 'by', 'are', 'be', 'was', 'as', 'he', 'with', 'his']

# Initialize locked_letters set
locked_letters = set()

# Initial partial text and score
partial_text = apply_substitution(ciphertext, mapping)
current_score = score_text(partial_text, common_words)

print("Initial Mapping:", {k: v for k, v in sorted(mapping.items())})
print("Initial Partially Decrypted Text:", partial_text)
print("Initial Score:", current_score)
print()

# Automated improvement using hill-climbing
print("Running initial automated improvement...")
mapping, current_score = improve_mapping(mapping, ciphertext, common_words, locked_letters)
partial_text = apply_substitution(ciphertext, mapping)
print("Initial decryption:", partial_text)
print("Initial score:", current_score)

# Interactive refinement loop
print("\nNow you can refine the mapping manually.")
print("To replace all occurrences of a plaintext letter with another, enter two lowercase letters, e.g., 'v w'.")
print("Type 'ok' to run automated improvement, or 'EXIT' to quit and save the result.")

while True:
    print("\nCurrent result:", partial_text)
    user_input = input(">> ").strip().lower()

    if user_input == "exit":
        break
    elif user_input == "ok":
        print("Running automated improvement...")
        old_score = current_score
        mapping, current_score = improve_mapping(mapping, ciphertext, common_words, locked_letters)
        partial_text = apply_substitution(ciphertext, mapping)
        print(f"Score after improvement: {current_score} (previous: {old_score})")
        print("Updated decrypted text:", partial_text)
    elif len(user_input.split()) == 2 and all(c.islower() for c in user_input.split()):
        old_plain, new_plain = user_input.split()
        updated = False
        for cipher_letter, plain_letter in list(mapping.items()):
            if plain_letter == old_plain:
                old_temp = mapping[cipher_letter]
                mapping[cipher_letter] = new_plain
                locked_letters.add(cipher_letter)
        for cipher_text, plain_text in list(mapping.items()):
            if mapping[cipher_text] == new_plain and cipher_text not in locked_letters:
                mapping[cipher_text] = old_temp
                updated = True
                
        if updated:
            partial_text = apply_substitution(ciphertext, mapping)
            current_score = score_text(partial_text, common_words)
            print("Updated decrypted text:", partial_text)
            print("New score:", current_score)
        else:
            print(f"No ciphertext letters map to '{old_plain}'.")
    else:
        print("Invalid input. Enter two lowercase letters (e.g., 'v w'), 'ok', or 'exit'.")

# Save the final result to a file
filename = "decrypted_text.txt"
with open(filename, "w") as f:
    f.write(partial_text)
print(f"Decrypted text saved to {filename}")
# print mapping method
print("Final Mapping:", {k: v for k, v in sorted(mapping.items())})
print("Final Decrypted Text:", partial_text)