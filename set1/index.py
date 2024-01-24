from base64 import b16decode, b64encode, b64decode, b16encode
import requests
import string

################# challenge 1 ################
def convert_binary_to_base64(binary):
    return b64encode(binary).decode('ascii')

def convert_hex_to_base64(hex):
    # convert to binary
    # base64 is case sensitive, use casefold=True
    binary = b16decode(hex, casefold=True)
    return convert_binary_to_base64(binary)
    
    

print('challenge 1')
string1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
print(convert_hex_to_base64(string1))

################ challenge 2 ################
def fixed_xor(buffer1, buffer2):
    assert len(xor1) == len(xor2), "You must pass equal length objects"
    return bytes([a ^ b for a, b in zip(buffer1, buffer2)])

print('challenge 2')
xor1 = '1c0111001f010100061a024b53535009181c'
xor2 = '686974207468652062756c6c277320657965'
buffer1 = bytes.fromhex(xor1)
buffer2 = bytes.fromhex(xor2)
chal2_res = fixed_xor(buffer1, buffer2)
print(chal2_res.hex())

################ challenge 3 ################

# step 1
# convert hex input to binary 
# IE 1b37 -> 0001101100110111

# step 2
# perform xor against each character (65-124), put in table
# IE -> a = 01000001 (then repeat), using xor gives you 0101101001110110

# step 3 
# convert binary back to ascii, see if message makes sense


# frequencies found on wikipedia / github
# char passed through to add to tuple
def calculate_likelihood(text, char):
    english_letter_frequency = {
            'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
            'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
            'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36,
            'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29,
            'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10,
            'z': 0.07
        }
    # only use chars from alphabet and convert all to lowercase
    clean_text = ''.join(char.lower() for char in text if char.isalpha())
    # get frequency of each letter in the text
    letter_frequency = {char: clean_text.count(char) / len(clean_text) * 100 for char in string.ascii_lowercase}
    # calculate absolute difference between expected and actual frequencies
    difference = sum(abs(english_letter_frequency[letter] - letter_frequency.get(letter, 0)) for letter in english_letter_frequency)
    # calculate score (lower is better)
    likelihood_score = difference / len(english_letter_frequency)

    return (likelihood_score, text, char)

def xor_decrypt(cipher):
    # print('cipher in xor decrypt', cipher)
    best_guess = (float('inf'), None, None)
    # go through all ascii codes that are letters
    for char_code in range(38, 128):
        try:
            # Repeat the bytes to match the length of the binary string
            char_expanded = bytes([char_code]) * len(cipher)
            decoded_string_bytes= fixed_xor(cipher, char_expanded)
            plaintext = decoded_string_bytes.decode('ascii')
            likelihood_score = calculate_likelihood(plaintext, char_code)
            # best_guess = min(best_guess, likelihood_score, char_code)
            best_guess = min([best_guess, likelihood_score], key=lambda x: x[0])
            # UnicodeDecodeError means it doesn't decrypt to english, move on
        except UnicodeDecodeError:
            pass
    return best_guess

print('challenge 3')
p3_input = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
print(xor_decrypt(p3_input))

################ challenge 4 ################

url = "https://cryptopals.com/static/challenge-data/4.txt"
response = requests.get(url)
raw_txt = response.text
formatted = raw_txt.split()

def bulk_xor_decrypt(ciphers):
    best_guess = (float('inf'), None)
    for string_hex in ciphers:
        cipher = bytes.fromhex(string_hex)
        likelihood_score = xor_decrypt(cipher)
        # if likelihood_score[0] < float('inf'):
        #     print('likelihood', likelihood_score)
        if likelihood_score < best_guess:
            best_guess = min(best_guess, likelihood_score)
    return best_guess

print('challenge 4')
print(bulk_xor_decrypt(formatted))
        
################ challenge 5 ################


# function to repeat key to be length of text
def repeat_text_to_length(hex_key, length):
    key_expanded = (hex_key * (int(length/len(hex_key))+1))[:length]
    return key_expanded

def repeating_key_xor(text_bytes, key):
    # convert text to hex
    # repeat key to length
    repeated_key = repeat_text_to_length(key, len(text_bytes))
    print('running repeating key xor')
    print('text bytes', text_bytes)
    print('repated key', repeated_key)
    return fixed_xor(text_bytes, repeated_key)

print('challenge 5')
chal5_bytes = b"Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
chal5_key_bytes = b"ICE"
print(repeating_key_xor(chal5_bytes, chal5_key_bytes).hex())

################ challenge 6 ################

# step 1
# write function to calculate hamming distance between 2 bytes

# step 2
# convert base64 file to binary

# step 3
# find every possible key between 2-40 bits and run hamming distance function between this and binary'd file

# step 4
# the lowest value wins

# step 5
# run xor with found key, convert to ascii

def hamming_distance_binary(str1, str2):
    # check if the binary strings have equal length
    if len(str1) != len(str2):
        return 'uneven'
        # raise ValueError("Binary strings must be of equal length for Hamming distance calculation")

    distance = sum(bit1 != bit2 for bit1, bit2 in zip(str1, str2))
    return distance

def hamming_dist_test(str1, str2):
    # check if the strings have equal length
    if len(str1) != len(str2):
        return 'uneven'
        # raise ValueError("Strings must be of equal length for differing bits calculation")

    # convert each character to binary then count differing bits
    return sum(bin(ord(ch1) ^ ord(ch2)).count('1') for ch1, ch2 in zip(str1, str2))

test1 = 'this is a test'
test2 = 'wokka wokka!!!'

# print('ham test', hamming_dist_test(test1, test2))

chal6_cipher_url = "https://cryptopals.com/static/challenge-data/6.txt"
chal6_response = requests.get(chal6_cipher_url)
raw_txt_6 = chal6_response.text
cipher_6 = b64decode(raw_txt_6)
# print(cipher_6)

# convert to binary

# loop through 2 and 40

    # for each possible key length, compare 0-x with x-x+x until its over.
    # for each comparison, calculate the bitwise hamming distance. 
    # divide it by key length and add it to a distance counter
    # at end of loop for one key size, divide counter by number of iterations you made

def break_into_parts(input_string, part_length):
    return [input_string[i:i + part_length] for i in range(0, len(input_string), part_length)]


# at end of 2-40 loop, take key length with smallest number and use that as key length
key_size_dict = {}
for key_size in range (2,41):
    parts = break_into_parts(cipher_6, key_size)
    dist_counter = 0
    counter = 0
    for i in range(len(parts)-1):
        item1 = parts[i]
        item2 = parts[i+1]
        dist = hamming_distance_binary(item1, item2)
        if dist != 'uneven':
            counter += 1
            dist_counter += (dist/key_size)
    key_size_dict[key_size] = (dist_counter/counter)


# 5 smallest values
# sorted_items = sorted(key_size_dict.items(), key=lambda x: x[1])[:5]
# print(sorted_items)
    
key_size = min(key_size_dict, key=lambda k: key_size_dict[k])
print('key size', key_size)



    
    

# break cipher into blocks of key length
# perform single character xor for every nth (n=key length) character and determine the most likely letter
# do this for all letters in the key
# now you have key! perform decryption

split_cipher = break_into_parts(cipher_6,key_size)
# print('split cipher', split_cipher)
cipher_dict = {}
# remove last element, its not guaranteed to be key size length
del split_cipher[-1]
# print('split cipher', split_cipher)
new_string = b''
for ciph in split_cipher:
    # print('ciph in loop', ciph)
    for k in range(key_size):
        # print(f'the {k}th byte is', ciph[k])
        if k not in cipher_dict:
            cipher_dict[k] = b''
        # print('k', k)
        # print('ciph',type(ciph))
        # print('ciph[k]',type(ciph[k]))
        cipher_dict[k] += ciph[k].to_bytes()
        
        # try:
            
        # except:
        #     IndexError
        
# print('cipher dict', cipher_dict)
# for byte_string in new_byte_strings:
#     print('decoded',xor_decrypt(byte_string))

decoded_dict = {}

for k, v in cipher_dict.items():
    decrypted = xor_decrypt(v)
    decoded_dict[k] = decrypted[2]

print('decoded dict', decoded_dict)
chal6_key = ''

for val in decoded_dict.values():
    chal6_key += chr(val)
    
print(chal6_key)
print(repeating_key_xor(cipher_6, bytes(chal6_key, 'utf-8')))

# try iter tools, islice for transposing blocks
# list comprehension




# loop through split ciphers
# for each cipher, loop through each number in key size
# for each number, add to cipher_dict
# once cipher dict is complete, run xor_decrypt on all of them
# combine the most likely letter (2th element in tuple) into a key and there is key
# crack cipher with key