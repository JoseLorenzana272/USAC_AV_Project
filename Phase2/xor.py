import argparse
import os
import sys

def xor_encrypt_decrypt(input_file_path, key_file_path, output_file_path):
    try:
        with open(input_file_path, 'rb') as input_file:
            input_data = input_file.read()

        with open(key_file_path, 'rb') as key_file:
            key_data = key_file.read()

        if len(key_data) == 0:
            print("Error: Key file is empty.")
            return

        output_data = bytes([
            b ^ key_data[i % len(key_data)] for i, b in enumerate(input_data)
        ])

        with open(output_file_path, 'wb') as output_file:
            output_file.write(output_data)

        print(f"Output written to {output_file_path}")

    except FileNotFoundError as e:
        print(f"File not found: {e.filename}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="XOR Encrypt/Decrypt a file with a key.")
    parser.add_argument('-p', '--input', required=True, help='Path to input file')
    parser.add_argument('-k', '--key', required=True, help='Path to key file')
    parser.add_argument('-o', '--output', required=True, help='Path to output file')

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Input file '{args.input}' does not exist.")
        sys.exit(1)

    if not os.path.isfile(args.key):
        print(f"Key file '{args.key}' does not exist.")
        sys.exit(1)

    xor_encrypt_decrypt(args.input, args.key, args.output)

if __name__ == "__main__":
    main()