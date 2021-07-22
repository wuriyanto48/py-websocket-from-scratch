import math

BASE64_TABLE = {
    0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'E', 5: 'F', 6: 'G', 7: 'H', 8: 'I', 9: 'J', 10: 'K',
    11: 'L', 12: 'M', 13: 'N', 14: 'O', 15: 'P', 16: 'Q', 17: 'R', 18: 'S', 19: 'T', 20: 'U',
    21: 'V', 22: 'W', 23: 'X', 24: 'Y', 25: 'Z', 26: 'a', 27: 'b', 28: 'c', 29: 'd', 30: 'e',
    31: 'f', 32: 'g', 33: 'h', 34: 'i', 35: 'j', 36: 'k', 37: 'l', 38: 'm', 39: 'n', 40: 'o',
    41: 'p', 42: 'q', 43: 'r', 44: 's', 45: 't', 46: 'u', 47: 'v', 48: 'w', 49: 'x', 50: 'y',
    51: 'z', 52: '0', 53: '1', 54: '2', 55: '3', 56: '4', 57: '5', 58: '6', 59: '7', 60: '8',
    61: '9', 62: '+', 63: '/',
}

'''
convert decimal to binary
'''
def dec_to_bin(d: int):
    ss = []
    while d > 0:
        rem_mod = d % 2
        d = math.floor(d / 2)
        ss.append(rem_mod)
    i = len(ss) - 1
    new_ss = []
    while i >= 0:
        new_ss.append(ss[i])
        i = i - 1
    return ''.join([str(b) for b in new_ss])

'''
convert binary string to decimal
'''
def bin_to_dec(b: str):
    i = len(b) - 1
    new_ss = []
    while i >= 0:
        new_ss.append(b[i])
        i = i - 1

    i = len(new_ss) - 1
    res = 0
    while i >= 0:
        res += int(new_ss[i]) * math.pow(2, i)
        i = i - 1
    return int(res)

def str_to_str_three_segment(plain: bytes):
    list_plain = []
    length = len(plain)
    if length < 3:
        list_plain.append(plain)
    else:
        j = 0
        for _ in range(math.ceil(length/3)):
            t = j + 3
            current_text = plain[j:t]
            list_plain.append(current_text)
            j = j + 3


    return list_plain

def b64_encode(plain: bytes):
    list_plain = str_to_str_three_segment(plain)
    outer_list_per_seg = []
    for p in list_plain:
        cl = f"{''.join(['{:08b}'.format(c) for c in p])}"
        length = len(cl)
        j = 0

        list_per_seg = []
        for _ in range(math.ceil(length/6)):
            t = j + 6
            current_bin = cl[j:t]
            length_to_move = 6 - len(current_bin)

            key = int(current_bin, 2)
            key = key << length_to_move

            decoded = BASE64_TABLE[key]
            list_per_seg.append(decoded)
            j = j + 6
        
        while len(list_per_seg) < 4:
            list_per_seg.append('=')
        outer_list_per_seg += list_per_seg
    return ''.join(outer_list_per_seg).encode()
    
def b64_decode(plain: str):
    def remove_padding(txt: str):
        return txt.translate({ord('='): None})
    
    base64_table_flipped = {v: k for (k, v) in BASE64_TABLE.items()}
    
    # remove padding
    plain = remove_padding(plain)
    plain_list = [base64_table_flipped[p] for p in plain]
    plain_list_str = ''.join(['{:06b}'.format(p) for p in plain_list])

    j = 0
    length = len(plain_list_str)
    list_decoded = []
    for _ in range(math.ceil(length/8)):
        t = j + 8
        current_bin = plain_list_str[j:t]
        key = int(current_bin, 2)
        if key == 0x0:
            continue
        list_decoded.append(chr(key))
        j = j + 8
    
    return ''.join(list_decoded)