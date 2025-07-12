pub struct Node {
    rows: [[u8; 32]; 16],
    row_exist: [bool; 16],
    node_type: u8
}


fn calculate_extension_hash(node: Node) -> [u8; 32] {
    // rows: [
    //     [first_limb, second_limb, key_length (other than first byte), ..0]
    //     [right_padded_key (other than first byte)],
    //     [value],
    //     0..0
    // ]
    
    let mut encoded: [u8; 68] = [0; 68];
    let mut encoding_index = 0;
    let first_limb = node.rows[0][0] % 16;
    let second_limb = node.rows[0][1] % 16;
    let key_total_length = node.rows[0][2] + 1;
    let mut rlp_data_length: u8 = 0;
    if key_total_length != 1 {
        rlp_data_length = 
            1 + // key_rlp_prefix
            key_total_length + // key
            1 + // valye_rlp_prefix
            32;// value
    } else {
        rlp_data_length = 
            key_total_length + // key
            1 + // valye_rlp_prefix
            32;// value
    }
    if rlp_data_length > 55 {
        encoded[encoding_index] = 0xF8;
        encoding_index += 1;
        encoded[encoding_index] = rlp_data_length;
        encoding_index += 1;
    } else {
        encoded[encoding_index] = 0xC0 + rlp_data_length;
        encoding_index += 1;
    }
    if key_total_length != 1 {
        encoded[encoding_index] = 0x80 + key_total_length;
        encoding_index += 1;
    }
    encoded[encoding_index] = first_limb * 0x10 + second_limb;
    encoding_index += 1;
    for i in 0 .. 31 {
        if i + 1 <= key_total_length - 1 {
            encoded[encoding_index] = node.rows[1][i];
            encoding_index += 1;
        }
    }
    encoded[encoding_index] = 0xA0;
    encoding_index += 1;
    for i in 0 .. 32 {
        encoded[encoding_index] = node.rows[2][i];
        encoding_index += 1;
    }
    keccak256::keccak256(encoded, encoding_index)
}


pub fn calculate_branch_hash(node: Node) -> [u8; 32] {
    let mut len1: u8 = 0;
    let mut len2: u8 = 0;
    let mut encoded: [u8; 532] = [0; 532];
    let mut index: u32 = 0;
    for i in 0 .. 16 {
        if node.row_exist[i] == true {
            if len2 > 255 - 33 {
                len1 += 1;
                len2 = len2 - 223;
            } else {
                len2 += 33;
            }
        } else {
            if len2 == 255 {
                len2 = 0;
                len1 += 1;
            } else {
                len2 += 1;
            }
        }
    }
    if len2 == 255 {
        len2 = 0;
        len1 += 1;
    } else {
        len2 += 1;
    }
    if (len1 == 0) & (len2 <= 55) {
        encoded[index] = 0xc0 + len2;
        index += 1;
    } else if len1 == 0 {
        encoded[index] = 0xf8;
        index += 1;
        encoded[index] = len2;
        index += 1;
    } else {
        encoded[index] = 0xf9;
        index += 1;
        encoded[index] = len1;
        index += 1;
        encoded[index] = len2;
        index += 1;
    }

    for i in 0 .. 16 {
        if node.row_exist[i] == true {
            encoded[index] = 0xa0;
            index += 1;
            for j in 0 .. 32 {
                encoded[index] = node.rows[i][j];
                index += 1;
            }
        } else {
            encoded[index] = 0x80;
            index += 1;
        }
    }
    encoded[index] = 0x80;
    index += 1;
    keccak256::keccak256(encoded, index)

}

pub fn verify_nodes<let MAX_PATH_LEANGTH: u32>(
    nodes: [Node; MAX_PATH_LEANGTH], 
    node_length: u32,

    root: [u8; 32],
    trie_key: [u8; 32],
    trie_key_new_index: u32,
    new_root: [u8; 32],

    public_inputs: [Field; 209]
    ) {
        let root_index_in_inputs = 0;
        let trie_key_index_in_inputs: u32 = 32;
        let trie_key_initial_limb_index = public_inputs[64] as u32;
        let this_segment_root_index_in_inputs = 65;


        root.for_eachi(|i, x| {
            assert(x == public_inputs[i + root_index_in_inputs] as u8);
        });

        trie_key.for_eachi(|i, x| {
            assert(x == public_inputs[i + trie_key_index_in_inputs] as u8);
        });

        println(f"key index: {trie_key_index_in_inputs}");
        let mut parent: [u8; 32] = [0; 32];
        for i in 0 ..  32 {
            parent[i] = public_inputs[this_segment_root_index_in_inputs + i] as u8;
        }
        let mut prefix_length_limb: u32 = trie_key_initial_limb_index;
        for i in 0 .. MAX_PATH_LEANGTH {
            if (i < node_length) {
                if nodes[i].node_type == 0 { 
                    // branch node
                    let h = calculate_branch_hash(nodes[i]);
                    println("parent: ");
                    parent.for_each(|x| {
                        print(f"{x}, ");
                    });
                    println(f"");
                    assert(h == parent);
                    let prefix_length_byte: u32 = prefix_length_limb/2;
                    let mut index = trie_key[prefix_length_byte] as u32;
                    if prefix_length_limb % 2 == 0 {
                        index = index >> 4;
                    } else {
                        index = index - (index >> 4) * 0x10;
                    }
                    parent = nodes[i].rows[index];
                    prefix_length_limb += 1;
                    h.for_each(|x| {
                        print(f"{x}, ");
                    });
                    println("");
                } else if nodes[i].node_type == 1 {
                    // extension nodes
                    println("extension node:");
                    let h = calculate_extension_hash(nodes[i]);
                    println("parent: ");
                    parent.for_each(|x| {
                        print(f"{x}, ");
                    });
                    println(f"");
                    assert(h == parent);
                    let mut extension: u128 = 0;
                    let mut extension_length_limb: u32 = 0;
                    let extension_length_byte: u32 = nodes[i].rows[0][2] as u32;
                    let first_limb: u32 = nodes[i].rows[0][0] as u32;
                    let second_limb: u32 = (nodes[i].rows[0][1] % 16) as u32;
                    assert(extension_length_byte <= 16); // because extension is 128 bits and we will never have such a big extension!
                    assert(first_limb * (1 - first_limb) == 0);
                    assert((1 - first_limb) * second_limb == 0); // if first_limb == 0, second_limb == 0
                    extension_length_limb = (extension_length_byte * 2 + first_limb) as u32;
                    assert(extension_length_limb != 0);
                    extension += second_limb as u128;
                    for j in 0 .. 15 {
                        if j < extension_length_byte {
                            extension *= 0x100;
                            extension += nodes[i].rows[1][j] as u128;
                        }
                    }
                    println(f"extension length {extension_length_byte}");
                    println(f"extension {extension}");
                    let mut key_extension: u128 = 0;
                    let mut limb_left = extension_length_limb;
                    let prefix_length_byte: u32 = prefix_length_limb/2;
                    let mut trie_key_index = prefix_length_byte;
                    if prefix_length_limb % 2 == 1 {
                        limb_left -= 1;
                        let first_byte = trie_key[trie_key_index] as u32;
                        key_extension += (first_byte - (first_byte >> 4) * 0x10) as u128;
                        trie_key_index += 1;
                    }
                    for _ in 0 .. 15 {
                        let next_byte = trie_key[trie_key_index] as u32;
                        if limb_left == 1{
                            key_extension *= 0x10;
                            key_extension += (next_byte >> 4) as u128;
                            limb_left = 0;

                        } else if limb_left != 0 {
                            key_extension *= 0x100;
                            key_extension += next_byte as u128;
                            limb_left -= 2;
                        }
                        trie_key_index += 1;

                    }
                    assert(key_extension == extension);

                    prefix_length_limb += extension_length_limb;
                    parent = nodes[i].rows[2];
                } else {
                    assert(false);
                }
            }
        }
        println("new root:");
        parent.for_each(|x| {
            print(f"{x}, ");
        });
        println("");
        assert(trie_key_new_index == prefix_length_limb);
        assert(new_root == parent);
}

#[test]
fn test_mpt_body() {
}