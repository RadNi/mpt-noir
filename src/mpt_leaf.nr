global STORAGE_HASH: [u8; 32] = [86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33];
global CODE_HASH: [u8; 32] = [197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112];

pub struct Account {
    pub nonce: [u8; 8],
    pub balance: [u8; 32],
    pub address: [u8; 20],
    pub nonce_length: u8,
    pub balance_length: u8
}

fn get_rlp_length(first_elem: u8, length: u8) -> u8 {
    let mut rlp_length: u8 = 0;
    // let mut length: u32 = 0;
    // let mut index_found = false;
    // let mut first_elem = 0;
    // for i in 0 .. N {
    //     if !index_found {
    //         if data[i] != 0 {
    //             index_found = true;
    //             length = N - i;
    //             if i + 1 < N {
    //                 first_elem = data[i+1];
    //             }
    //         }
    //     }
    // }
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
            let first_elem = trie_key[prefix_length_limb/2];
            prefix_length_limb += 1;
            key[0] = 0x30 + (first_elem - (first_elem >> 4) * 0x10);
        }
        let mut index: u8 = 1;
        for i in 0 .. 32 {
            if i >= prefix_length_limb/2 {
                key[index] = trie_key[i];
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
                    leaf_rlp_encoded[index] = key[i];
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
                    leaf_rlp_encoded[index] = self.nonce[i];
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
                    leaf_rlp_encoded[index] = self.balance[i];
                    index += 1;
                }
            }
        }

        // storage hash
        leaf_rlp_encoded[index] = 0xa0;
        index += 1;
        for i in 0 .. 32 {
            leaf_rlp_encoded[index] = STORAGE_HASH[i];
            index += 1;
        }

        // code hash
        leaf_rlp_encoded[index] = 0xa0;
        index += 1;
        for i in 0 .. 32 {
            leaf_rlp_encoded[index] = CODE_HASH[i];
            index += 1;
        }

        assert(leaf_hash == keccak256::keccak256(leaf_rlp_encoded, index));
        println("encoding:");
        leaf_rlp_encoded.for_eachi(|i, x| {
            if i < index {
                print(f"{x}, ");
            }
        });
        println("");

        println("leaf hash:");
        leaf_hash.for_eachi(|i, x| {
            print(f"{x}, ");
        });
        println("");
    }
}


#[test]
fn test_mpt_leaf() {
    let trie_key = [48, 45, 88, 152, 202, 69, 73, 205, 191, 243, 173, 49, 214, 8, 0, 165, 232, 98, 232, 239, 109, 235, 33, 247, 34, 162, 129, 87, 148, 40, 86, 143];
    let trie_key_index = 8;
    let leaf_hash = [184, 170, 175, 96, 167, 138, 35, 9, 17, 61, 196, 183, 197, 203, 74, 240, 210, 250, 108, 186, 250, 13, 120, 135, 144, 16, 243, 77, 157, 147, 139, 207];
    let account = Account {
        nonce: [33, 147, 173, 0, 0, 0, 0, 0],
        balance: [186, 230, 72, 202, 146, 111, 104, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        address: [149, 34, 34, 144, 221, 114, 120, 170, 61, 221, 56, 156, 193, 225, 209, 101, 204, 75, 175, 229],
        nonce_length: 3,
        balance_length: 8
    };
    account.verify_leaf_node(trie_key_index, trie_key, leaf_hash)
}