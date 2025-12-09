import string
from collections import Counter
import os
# --- PHAN 1: DU LIEU TAN SUAT TIENG ANH ---
ENGLISH_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074
}

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
ALPHABET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# --- PHAN 2: CAC HAM TIM KEY TU DONG ---

def get_index_of_coincidence(text):
    """Tinh chi so trung khop (IoC)"""
    N = len(text)
    if N <= 1: return 0
    counts = Counter(text)
    numerator = sum(n * (n - 1) for n in counts.values())
    return numerator / (N * (N - 1))

def find_best_key_length(text, max_len=15):
    # Tim do dai Key co IoC gan voi tieng Anh nhat (0.067)
    best_len = 1
    best_diff = float('inf')
    
    for k in range(1, max_len + 1):
        groups = ['' for _ in range(k)]
        for i, char in enumerate(text):
            groups[i % k] += char
        
        avg_ioc = sum(get_index_of_coincidence(g) for g in groups) / k
        
        # Tieng Anh chuan co IoC khoang 0.0667
        diff = abs(avg_ioc - 0.0667)
        if diff < best_diff:
            best_diff = diff
            best_len = k
            
    return best_len

def solve_key(ciphertext):
    """Ham tong hop de tim Key tu van ban ma hoa"""
    # Chi giu lai chu cai de phan tich
    clean_text = "".join(filter(str.isalpha, ciphertext.upper()))
    
    # 1. Tim do dai (gioi han 15 de tranh lap key)
    key_len = find_best_key_length(clean_text, max_len=15)
    print(f" -> Do dai Key du doan: {key_len}")
    
    # 2. Tim tung ky tu cua Key
    found_key = ""
    for i in range(key_len):
        sub_text = clean_text[i::key_len] # Lay cac ky tu o vi tri chia het cho key_len
        min_chi = float('inf')
        best_shift = 0
        
        # Thu 26 phep dich (Caesar) cho nhom ky tu nay
        for shift in range(26):
            shifted_counts = Counter()
            for char in sub_text:
                # Dich nguoc de tim ky tu goc
                orig = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                shifted_counts[orig] += 1
            
            # Tinh Chi-squared (do lech so voi tan suat chuan)
            chi_sq = 0
            for char in string.ascii_uppercase:
                observed = shifted_counts[char]
                expected = len(sub_text) * ENGLISH_FREQ[char]
                # Tranh chia cho 0
                if expected > 0:
                    chi_sq += ((observed - expected) ** 2) / expected
            
            if chi_sq < min_chi:
                min_chi = chi_sq
                best_shift = shift
        
        found_key += chr(best_shift + ord('A'))
        
    return found_key

# --- PHAN 3: CLASS GIAI MA ---

class VigenereCipher:
    def __init__(self, key):
        self.key = key.lower()
        self.alphabet = ALPHABET

    def decrypt(self, ciphertext: str) -> str:
        plaintext = ""
        key_idx = 0 
        
        for char in ciphertext:
            # 1. Neu la chu thuong
            if char in self.alphabet:
                char_idx = self.alphabet.index(char)
                key_char = self.key[key_idx % len(self.key)]
                key_shift = self.alphabet.index(key_char)
                
                new_idx = (char_idx - key_shift) % 26
                plaintext += self.alphabet[new_idx]
                key_idx += 1

            # 2. Neu la chu Hoa
            elif char in ALPHABET_UPPER:
                char_idx = ALPHABET_UPPER.index(char)
                key_char = self.key[key_idx % len(self.key)]
                key_shift = self.alphabet.index(key_char)
                
                new_idx = (char_idx - key_shift) % 26
                plaintext += ALPHABET_UPPER[new_idx]
                key_idx += 1

            # 3. Neu la ky tu la
            else:
                plaintext += char
                
        return plaintext

# --- PHAN 4: CHAY CHUONG TRINH ---
if __name__ == "__main__":

# 1. Lấy đường dẫn tuyệt đối đến file code hiện tại
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 2. Tạo đường dẫn đến file ciphertext.txt nằm cùng thư mục đó
    file_path = os.path.join(base_dir, "ciphertext.txt")
    
    print(f"[*] Đang đọc file từ: {file_path}") # In ra để kiểm tra xem đúng chưa
    
    # 3. Đọc file với đường dẫn tuyệt đối
    with open(file_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    # --- KIỂM TRA DỮ LIỆU ---
    if not raw_text.strip():
        print("LỖI: File ciphertext.txt bị rỗng!")
        exit()
        
    print(f"[*] Đã đọc {len(raw_text)} ký tự.")
        
    found_key = solve_key(raw_text)
    print(f"\nTIM THAY KEY: {found_key}")

    # 3. Giai ma bang Key vua tim duoc
    print(f"Giai ma voi Key '{found_key}'...")
    cipher = VigenereCipher(found_key)
    decrypted_text = cipher.decrypt(raw_text)
    
    # 4. Hien thi ket qua
    print("\n--- TOAN BO NOI DUNG DA GIAI MA ---")
    print(decrypted_text) 
    
    # 5. Luu ra file
    with open("final_result.txt", "w") as f:
        f.write(decrypted_text)
    print("\n(Da luu ket qua vao file 'final_result.txt')")