pub struct Account {
    pub nonce: [u8; 8],
    pub balance: [u8; 32],
    pub address: [u8; 20],
    pub nonce_length: u8,
    pub balance_length: u8,
    pub storage_hash: [u8; 32],
    pub code_hash: [u8; 32],
}

pub struct StorageSlot {
    pub slot_numebr: [u8; 32],
    pub value: [u8; 32],
    pub value_length: u8
}

fn get_rlp_length(first_elem: u8, length: u8) -> u8 {
    let mut rlp_length: u8 = 0;
    if length == 0 {
        rlp_length = 1;
    } else if length == 1 {
        if first_elem <= 127 {
            rlp_length = 1;
        } else {
            rlp_length = 2;
        }
    } else {
        rlp_length = 1 + length;
    }
    rlp_length
}

impl StorageSlot {
    pub fn verify_leaf_node(
        self,
        trie_key_index: u8,
        trie_key: [u8; 32],
        leaf_hash: [u8; 32]
    ) {
        assert(trie_key == keccak256::keccak256(self.slot_numebr, 32));
        let mut prefix_length_limb: u8 = trie_key_index;
        
        let mut key: [u8; 33] = [0; 33];

        if prefix_length_limb % 2 == 0 {
            key[0] = 0x20;
        } else {
            let first_elem = trie_key[(prefix_length_limb/2) as u32];
            prefix_length_limb += 1;
            key[0] = 0x30 + (first_elem - (first_elem >> 4) * 0x10);
        }
        let mut index: u32 = 1;
        for i in 0 .. 32 {
            if i >= prefix_length_limb/2 {
                key[index] = trie_key[i as u32];
                index += 1;
            }
        }

        let key_length = 32 - prefix_length_limb/2 + 1;

        let mut leaf_key_rlp_length= get_rlp_length(key[0], key_length);
        println(f"key rlp len {leaf_key_rlp_length}");
        
        let mut leaf_rlp_encoded: [u8; 69] = [0; 69];
        let leaf_value_rlp_data_length = 
            get_rlp_length(self.value[0], self.value_length);
        println(f"value rlp len {leaf_value_rlp_data_length}");
        assert(self.value_length <= 32);


        let leaf_rlp_total_length = leaf_key_rlp_length + leaf_value_rlp_data_length;
        let mut index: u32 = 0;
        if leaf_rlp_total_length <= 55 {
            leaf_rlp_encoded[0] = 0xc0 + leaf_rlp_total_length;
            index = 1;
        } else {
            leaf_rlp_encoded[0] = 0xf8;
            leaf_rlp_encoded[1] = leaf_rlp_total_length;
            index = 2;
        }

        // key
        if (key_length == 1) & (key[0] <= 127 ) {
            leaf_rlp_encoded[index] = key[0];
            index += 1;
        } else {
            leaf_rlp_encoded[index] = 0x80 + key_length;
            index += 1;
            for i in 0 .. 33 {
                if i < key_length {
                    leaf_rlp_encoded[index] = key[i as u32];
                    index += 1;
                }
            }
        }

        // value
        if self.value_length == 0 {
            leaf_rlp_encoded[index] = 0x80;
            index += 1;
        } else if (self.value_length == 1) & (self.value[0] <= 127 ) {
            leaf_rlp_encoded[index] = self.value[0];
            index += 1;
        } else {
            leaf_rlp_encoded[index] = 0x80 + self.value_length;
            index += 1;
            for i in 0 .. 32 {
                if i < self.value_length {
                    // println(index);
                    leaf_rlp_encoded[index] = self.value[i as u32];
                    index += 1;
                }
            }
        }

        assert(leaf_hash == keccak256::keccak256(leaf_rlp_encoded, index));
        println("encoding:");
        println(leaf_rlp_encoded);

        println("leaf hash:");
        println(leaf_hash);
    }
}

impl Account {
    pub fn verify_leaf_node(
        self,
        trie_key_index: u8,
        trie_key: [u8; 32], 
        leaf_hash: [u8; 32]
        ){
        assert(trie_key == keccak256::keccak256(self.address, 20));
        // let mut parent: [u8; 32] = root;
        let mut prefix_length_limb: u8 = trie_key_index;
        
        let mut key: [u8; 33] = [0; 33];

        if prefix_length_limb % 2 == 0 {
            key[0] = 0x20;
        } else {
            let first_elem = trie_key[(prefix_length_limb/2) as u32];
            prefix_length_limb += 1;
            key[0] = 0x30 + (first_elem - (first_elem >> 4) * 0x10);
        }
        let mut index: u32 = 1;
        for i in 0 .. 32 {
            if i >= prefix_length_limb/2 {
                key[index] = trie_key[i as u32];
                index += 1;
            }
        }

        let key_length = 32 - prefix_length_limb/2 + 1;

        let mut leaf_key_rlp_length= get_rlp_length(key[0], key_length);
        println(f"key rlp len {leaf_key_rlp_length}");
        assert(self.balance_length <= 32);
        assert(self.nonce_length <= 8);

        let mut leaf_rlp_encoded: [u8; 147] = [0; 147];
        let leaf_value_rlp_data_length = 
            get_rlp_length(self.balance[0], self.balance_length)
            + get_rlp_length(self.nonce[0], self.nonce_length) 
            + 33 // code hash
            + 33; // storage hash
        println(f"value rlp len {leaf_value_rlp_data_length}");

        let leaf_rlp_total_length = leaf_key_rlp_length + leaf_value_rlp_data_length + 2 + 2;

        leaf_rlp_encoded[0] = 0xf8;
        leaf_rlp_encoded[1] = leaf_rlp_total_length;
        let mut index: u32 = 2;

        // key
        if (key_length == 1) & (key[0] <= 127 ) {
            leaf_rlp_encoded[index] = key[0];
            index += 1;
        } else {
            leaf_rlp_encoded[index] = 0x80 + key_length;
            index += 1;
            for i in 0 .. 33 {
                if i < key_length {
                    leaf_rlp_encoded[index] = key[i as u32];
                    index += 1;
                }
            }
        }

        leaf_rlp_encoded[index] = 0xb8;
        index += 1;
        leaf_rlp_encoded[index] = leaf_value_rlp_data_length + 2;
        index += 1;


        leaf_rlp_encoded[index] = 0xf8;
        index += 1;
        leaf_rlp_encoded[index] = leaf_value_rlp_data_length;
        index += 1;

        // nonce
        if self.nonce_length == 0 {
            leaf_rlp_encoded[index] = 0x80;
            index += 1;
        } else if (self.nonce_length == 1) & (self.nonce[0] <= 127 ) {
            leaf_rlp_encoded[index] = self.nonce[0];
            index += 1;
        } else {
            leaf_rlp_encoded[index] = 0x80 + self.nonce_length;
            index += 1;
            for i in 0 .. 8 {
                if i < self.nonce_length {
                    leaf_rlp_encoded[index] = self.nonce[i as u32];
                    index += 1;
                }
            }
        }

        // balance
        if self.balance_length == 0 {
            leaf_rlp_encoded[index] = 0x80;
            index += 1;
        } else if (self.balance_length == 1) & (self.balance[0] <= 127 ) {
            leaf_rlp_encoded[index] = self.balance[0];
            index += 1;
        } else {
            leaf_rlp_encoded[index] = 0x80 + self.balance_length;
            index += 1;
            for i in 0 .. 32 {
                if i < self.balance_length {
                    leaf_rlp_encoded[index] = self.balance[i as u32];
                    index += 1;
                }
            }
        }

        // storage hash
        leaf_rlp_encoded[index] = 0xa0;
        index += 1;
        for i in 0 .. 32 {
            leaf_rlp_encoded[index] = self.storage_hash[i];
            index += 1;
        }

        // code hash
        leaf_rlp_encoded[index] = 0xa0;
        index += 1;
        for i in 0 .. 32 {
            leaf_rlp_encoded[index] = self.code_hash[i];
            index += 1;
        }

        assert(leaf_hash == keccak256::keccak256(leaf_rlp_encoded, index));
        println("encoding:");
        println(leaf_rlp_encoded);

        println("leaf hash:");
        println(leaf_hash);
    }
}


#[test]
fn test_account_trie_leaf() {
    let trie_key = [48, 45, 88, 152, 202, 69, 73, 205, 191, 243, 173, 49, 214, 8, 0, 165, 232, 98, 232, 239, 109, 235, 33, 247, 34, 162, 129, 87, 148, 40, 86, 143];
    let trie_key_index = 8;
    let leaf_hash = [184, 170, 175, 96, 167, 138, 35, 9, 17, 61, 196, 183, 197, 203, 74, 240, 210, 250, 108, 186, 250, 13, 120, 135, 144, 16, 243, 77, 157, 147, 139, 207];
    let account = Account {
        nonce: [33, 147, 173, 0, 0, 0, 0, 0],
        balance: [186, 230, 72, 202, 146, 111, 104, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        address: [149, 34, 34, 144, 221, 114, 120, 170, 61, 221, 56, 156, 193, 225, 209, 101, 204, 75, 175, 229],
        nonce_length: 3,
        balance_length: 8,
        storage_hash: [86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33],
        code_hash: [197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112]
    };
    account.verify_leaf_node(trie_key_index, trie_key, leaf_hash)
}

#[test]
fn test_account_trie_leaf2() {
    let trie_key = [ 21, 230, 190, 86, 221, 74, 110, 52, 141, 225, 29, 100, 177, 212, 10, 0, 190, 219, 222, 197, 116, 175, 35, 173, 245, 67, 145, 177, 215, 73, 228, 163];
    let trie_key_index = 7;
    let leaf_hash = [243, 181, 220, 73, 62, 28, 208, 204, 37, 164, 101, 207, 48, 19, 36, 42, 188, 238, 58, 88, 133, 11, 104, 199, 60, 50, 23, 18, 216, 161, 235, 6];
    let account = Account {
        nonce: [0, 0, 0, 0, 0, 0, 0, 0],
        balance: [9, 69, 199, 250, 221, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        address: [66, 247, 44, 119, 4, 9, 63, 56, 94, 245, 200, 161, 246, 245, 58, 88, 213, 240, 127, 41],
        nonce_length: 0,
        balance_length: 7,
        storage_hash: [86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33],
        code_hash: [197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112]
    };
    account.verify_leaf_node(trie_key_index, trie_key, leaf_hash)
}

#[test]
pub fn test_storage_trie_leaf() {
    let trie_key = [41, 13, 236, 217, 84, 139, 98, 168, 214, 3, 69, 169, 136, 56, 111, 200, 75, 166, 188, 149, 72, 64, 8, 246, 54, 47, 147, 22, 14, 243, 229, 99];
    let trie_key_index = 0;
    let leaf_hash = [42, 8, 35, 160, 203, 166, 189, 221, 243, 44, 37, 83, 207, 169, 138, 70, 171, 147, 152, 157, 163, 96, 33, 83, 94, 92, 195, 249, 157, 246, 140, 87];
    let account = StorageSlot{
        slot_numebr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        value: [50, 253, 182, 202, 6, 16, 98, 3, 61, 79, 102, 218, 5, 90, 229, 169, 123, 148, 242, 100, 125, 55, 126, 107, 98, 114, 103, 191, 153, 80, 12, 143],
        value_length: 32
    };
    account.verify_leaf_node(trie_key_index, trie_key, leaf_hash)
}

#[test]
pub fn test_storage_trie_leaf2() {
    let trie_key = [41, 13, 236, 217, 84, 139, 98, 168, 214, 3, 69, 169, 136, 56, 111, 200, 75, 166, 188, 149, 72, 64, 8, 246, 54, 47, 147, 22, 14, 243, 229, 99];
    let trie_key_index = 2;
    let leaf_hash = [141, 124, 240, 157, 106, 174, 212, 90, 34, 196, 44, 200, 215, 176, 26, 175, 214, 223, 68, 5, 217, 208, 183, 171, 103, 174, 210, 253, 216, 38, 220, 187];
    let account = StorageSlot{
        slot_numebr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        value: [148, 213, 51, 169, 73, 116, 11, 179, 48, 109, 17, 156, 199, 119, 250, 144, 11, 160, 52, 205, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        value_length: 21
    };
    account.verify_leaf_node(trie_key_index, trie_key, leaf_hash)
}

#[test]
pub fn test_storage_trie_leaf3() {
    let trie_key = [41, 13, 236, 217, 84, 139, 98, 168, 214, 3, 69, 169, 136, 56, 111, 200, 75, 166, 188, 149, 72, 64, 8, 246, 54, 47, 147, 22, 14, 243, 229, 99];
    let trie_key_index = 2;
    let leaf_hash = [130, 149, 136, 213, 132, 145, 236, 23, 75, 117, 71, 236, 104, 231, 77, 250, 128, 93, 174, 107, 36, 27, 123, 219, 208, 172, 70, 247, 232, 4, 153, 183];
    let account = StorageSlot{
        slot_numebr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        value: [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        value_length: 1
    };
    account.verify_leaf_node(trie_key_index, trie_key, leaf_hash)
}
