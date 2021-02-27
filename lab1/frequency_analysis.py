import argparse

# Relative letter frequencies in the English language texts
# Data taken from https://en.wikipedia.org/wiki/Letter_frequency
theory_frequencies = {'A': 8.2, 'B': 1.5, 'C': 2.8, 'D': 4.3, 'E': 13.0, 'F': 2.2, 'G': 2.0, 'H': 6.1, 'I': 7.0,
                      'J': 0.15, 'K': 0.77, 'L': 4.0, 'M': 2.4, 'N': 6.7, 'O': 7.5, 'P': 1.9, 'Q': 0.095, 'R': 6.0,
                      'S': 6.3, 'T': 9.1, 'U': 2.8, 'V': 0.98, 'W': 2.4, 'X': 0.15, 'Y': 2.0, 'Z': 0.074}


def main():
    # Reads encrypted text from file by name [filename] and outputs result to stdout
    usage = 'frequency_analysis.py filename'
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument('filename', action='store')
    args = parser.parse_args()

    # Data to Theory letters mapping
    dtt = {letter: 0 for letter in theory_frequencies}

    # Number of english alphabet characters encountered
    data_len = 0

    # File contents
    data = ""

    # Step 1. Read file and count how many of each letters there are
    with open(args.filename) as message:
        while True:
            # Process text file char by char
            c = message.read(1)

            # Stop reading file when it ends
            if not c:
                break

            data += c

            if c in dtt:
                data_len += 1
                dtt[c] += 1
                continue

    # Step 2. Get letter frequencies by dividing the amount of each letter by data length and multiplying it by 100
    for k in dtt:
        dtt[k] = dtt[k] / data_len * 100

    # Step 3. Create mapping between encrypted letters and real letters
    for k in dtt:
        best_letter = ""
        best_diff = 999

        # Compare every encrypted letter to every real letter to find the best correlation
        for m in theory_frequencies:
            # Calculate frequency difference between current encrypted letter and real letter
            diff = abs(theory_frequencies[m] - dtt[k])

            # If this is the lowest difference and this real letter was not yet assigned to any encrypted letter
            # then we found a mapping
            if diff <= best_diff and m not in dtt.values():
                best_diff = diff
                best_letter = m

        # Map our best real letter candidate to the current encrypted letter
        dtt[k] = best_letter

    # Debug
    # print(dtt)

    # Output decrypted message by mapping every encrypted alphabet character to the real counterpart
    decrypted_message = ""
    for char in data:
        if char in dtt:
            decrypted_message += dtt[char]
        else:
            # If a character is not present in the alphabet then output it without any changes
            decrypted_message += char

    print(decrypted_message)


main()
