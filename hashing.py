import hashlib

# Function to hash data
def hash_data(data: str) -> str:
    ''' 
    Hashes data in a way which is designed to be deterministic
    
    Uses SHA256 hashing algorithm to ensure secure hashing with 
    the smallest chance of collision 
    '''
    
    hashed_data: str = hashlib.sha256(data.encode()).hexdigest()
    return hashed_data
