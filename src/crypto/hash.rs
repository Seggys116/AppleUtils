const SHA256_BLOCK_SIZE: usize = 64;
const SHA256_DIGEST_SIZE: usize = 32;
const SHA1_DIGEST_SIZE: usize = 20;
const SHA512_BLOCK_SIZE: usize = 128;
const SHA512_DIGEST_SIZE: usize = 64;

#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    length_bytes: u64,
    buffer: [u8; SHA256_BLOCK_SIZE],
    buffer_len: usize,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            length_bytes: 0,
            buffer: [0; SHA256_BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    // Unused under the `#[path]` re-inclusion in `tests/crypto_portable.rs`.
    #[allow(dead_code)]
    pub const fn with_initial_state(state: [u32; 8]) -> Self {
        Self {
            state,
            length_bytes: 0,
            buffer: [0; SHA256_BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
        self.length_bytes = self.length_bytes.wrapping_add(bytes.len() as u64);
        if self.buffer_len != 0 {
            let count = (SHA256_BLOCK_SIZE - self.buffer_len).min(bytes.len());
            self.buffer[self.buffer_len..self.buffer_len + count].copy_from_slice(&bytes[..count]);
            self.buffer_len += count;
            bytes = &bytes[count..];
            if self.buffer_len == SHA256_BLOCK_SIZE {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
            if bytes.is_empty() {
                return;
            }
        }
        while bytes.len() >= SHA256_BLOCK_SIZE {
            let block: &[u8; SHA256_BLOCK_SIZE] = bytes[..SHA256_BLOCK_SIZE].try_into().unwrap();
            self.compress(block);
            bytes = &bytes[SHA256_BLOCK_SIZE..];
        }
        self.buffer[..bytes.len()].copy_from_slice(bytes);
        self.buffer_len = bytes.len();
    }

    pub fn finish(mut self) -> [u8; SHA256_DIGEST_SIZE] {
        let bit_length = self.length_bytes.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut digest = [0; SHA256_DIGEST_SIZE];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    #[inline(always)]
    fn compress(&mut self, block: &[u8; SHA256_BLOCK_SIZE]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0u32; 16];
        for index in 0..16 {
            words[index] = u32::from_be_bytes(block[index * 4..index * 4 + 4].try_into().unwrap());
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        macro_rules! round {
            ($index:literal, $word:expr) => {{
                let word = $word;
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let choice = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(choice)
                    .wrapping_add(K[$index])
                    .wrapping_add(word);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let majority = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(majority);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }};
        }
        macro_rules! schedule_round {
            ($index:literal, $slot:literal, $w15_slot:literal, $w2_slot:literal, $w7_slot:literal) => {{
                let w15 = words[$w15_slot];
                let w2 = words[$w2_slot];
                let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
                let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
                let word = words[$slot]
                    .wrapping_add(s0)
                    .wrapping_add(words[$w7_slot])
                    .wrapping_add(s1);
                words[$slot] = word;
                round!($index, word);
            }};
        }
        round!(0, words[0]);
        round!(1, words[1]);
        round!(2, words[2]);
        round!(3, words[3]);
        round!(4, words[4]);
        round!(5, words[5]);
        round!(6, words[6]);
        round!(7, words[7]);
        round!(8, words[8]);
        round!(9, words[9]);
        round!(10, words[10]);
        round!(11, words[11]);
        round!(12, words[12]);
        round!(13, words[13]);
        round!(14, words[14]);
        round!(15, words[15]);
        schedule_round!(16, 0, 1, 14, 9);
        schedule_round!(17, 1, 2, 15, 10);
        schedule_round!(18, 2, 3, 0, 11);
        schedule_round!(19, 3, 4, 1, 12);
        schedule_round!(20, 4, 5, 2, 13);
        schedule_round!(21, 5, 6, 3, 14);
        schedule_round!(22, 6, 7, 4, 15);
        schedule_round!(23, 7, 8, 5, 0);
        schedule_round!(24, 8, 9, 6, 1);
        schedule_round!(25, 9, 10, 7, 2);
        schedule_round!(26, 10, 11, 8, 3);
        schedule_round!(27, 11, 12, 9, 4);
        schedule_round!(28, 12, 13, 10, 5);
        schedule_round!(29, 13, 14, 11, 6);
        schedule_round!(30, 14, 15, 12, 7);
        schedule_round!(31, 15, 0, 13, 8);
        schedule_round!(32, 0, 1, 14, 9);
        schedule_round!(33, 1, 2, 15, 10);
        schedule_round!(34, 2, 3, 0, 11);
        schedule_round!(35, 3, 4, 1, 12);
        schedule_round!(36, 4, 5, 2, 13);
        schedule_round!(37, 5, 6, 3, 14);
        schedule_round!(38, 6, 7, 4, 15);
        schedule_round!(39, 7, 8, 5, 0);
        schedule_round!(40, 8, 9, 6, 1);
        schedule_round!(41, 9, 10, 7, 2);
        schedule_round!(42, 10, 11, 8, 3);
        schedule_round!(43, 11, 12, 9, 4);
        schedule_round!(44, 12, 13, 10, 5);
        schedule_round!(45, 13, 14, 11, 6);
        schedule_round!(46, 14, 15, 12, 7);
        schedule_round!(47, 15, 0, 13, 8);
        schedule_round!(48, 0, 1, 14, 9);
        schedule_round!(49, 1, 2, 15, 10);
        schedule_round!(50, 2, 3, 0, 11);
        schedule_round!(51, 3, 4, 1, 12);
        schedule_round!(52, 4, 5, 2, 13);
        schedule_round!(53, 5, 6, 3, 14);
        schedule_round!(54, 6, 7, 4, 15);
        schedule_round!(55, 7, 8, 5, 0);
        schedule_round!(56, 8, 9, 6, 1);
        schedule_round!(57, 9, 10, 7, 2);
        schedule_round!(58, 10, 11, 8, 3);
        schedule_round!(59, 11, 12, 9, 4);
        schedule_round!(60, 12, 13, 10, 5);
        schedule_round!(61, 13, 14, 11, 6);
        schedule_round!(62, 14, 15, 12, 7);
        let w15 = words[0];
        let w2 = words[13];
        let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
        let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
        let word = words[15]
            .wrapping_add(s0)
            .wrapping_add(words[8])
            .wrapping_add(s1);
        round!(63, word);
        self.state = [
            self.state[0].wrapping_add(a),
            self.state[1].wrapping_add(b),
            self.state[2].wrapping_add(c),
            self.state[3].wrapping_add(d),
            self.state[4].wrapping_add(e),
            self.state[5].wrapping_add(f),
            self.state[6].wrapping_add(g),
            self.state[7].wrapping_add(h),
        ];
    }
}

#[derive(Clone, Copy)]
pub struct Sha1 {
    state: [u32; 5],
    length_bytes: u64,
    buffer: [u8; SHA256_BLOCK_SIZE],
    buffer_len: usize,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            length_bytes: 0,
            buffer: [0; SHA256_BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
        self.length_bytes = self.length_bytes.wrapping_add(bytes.len() as u64);
        if self.buffer_len != 0 {
            let count = (SHA256_BLOCK_SIZE - self.buffer_len).min(bytes.len());
            self.buffer[self.buffer_len..self.buffer_len + count].copy_from_slice(&bytes[..count]);
            self.buffer_len += count;
            bytes = &bytes[count..];
            if self.buffer_len == SHA256_BLOCK_SIZE {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
            if bytes.is_empty() {
                return;
            }
        }
        while bytes.len() >= SHA256_BLOCK_SIZE {
            let block: &[u8; SHA256_BLOCK_SIZE] = bytes[..SHA256_BLOCK_SIZE].try_into().unwrap();
            self.compress(block);
            bytes = &bytes[SHA256_BLOCK_SIZE..];
        }
        self.buffer[..bytes.len()].copy_from_slice(bytes);
        self.buffer_len = bytes.len();
    }

    pub fn finish(mut self) -> [u8; SHA1_DIGEST_SIZE] {
        let bit_length = self.length_bytes.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut digest = [0u8; SHA1_DIGEST_SIZE];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    #[inline(always)]
    fn compress(&mut self, block: &[u8; SHA256_BLOCK_SIZE]) {
        let mut words = [0u32; 16];
        for index in 0..16 {
            words[index] = u32::from_be_bytes(block[index * 4..index * 4 + 4].try_into().unwrap());
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for index in 0..80 {
            let word = if index < 16 {
                words[index]
            } else {
                let slot = index & 15;
                let value = (words[(index - 3) & 15]
                    ^ words[(index - 8) & 15]
                    ^ words[(index - 14) & 15]
                    ^ words[slot])
                    .rotate_left(1);
                words[slot] = value;
                value
            };
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[derive(Clone, Copy)]
pub struct Sha512 {
    state: [u64; 8],
    length_bytes: u128,
    buffer: [u8; SHA512_BLOCK_SIZE],
    buffer_len: usize,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    pub const fn new() -> Self {
        Self::with_initial_state([
            0x6a09_e667_f3bc_c908,
            0xbb67_ae85_84ca_a73b,
            0x3c6e_f372_fe94_f82b,
            0xa54f_f53a_5f1d_36f1,
            0x510e_527f_ade6_82d1,
            0x9b05_688c_2b3e_6c1f,
            0x1f83_d9ab_fb41_bd6b,
            0x5be0_cd19_137e_2179,
        ])
    }

    pub const fn sha384() -> Self {
        Self::with_initial_state([
            0xcbbb_9d5d_c105_9ed8,
            0x629a_292a_367c_d507,
            0x9159_015a_3070_dd17,
            0x152f_ecd8_f70e_5939,
            0x6733_2667_ffc0_0b31,
            0x8eb4_4a87_6858_1511,
            0xdb0c_2e0d_64f9_8fa7,
            0x47b5_481d_befa_4fa4,
        ])
    }

    pub const fn with_initial_state(state: [u64; 8]) -> Self {
        Self {
            state,
            length_bytes: 0,
            buffer: [0; SHA512_BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
        self.length_bytes = self.length_bytes.wrapping_add(bytes.len() as u128);
        if self.buffer_len != 0 {
            let count = (SHA512_BLOCK_SIZE - self.buffer_len).min(bytes.len());
            self.buffer[self.buffer_len..self.buffer_len + count].copy_from_slice(&bytes[..count]);
            self.buffer_len += count;
            bytes = &bytes[count..];
            if self.buffer_len == SHA512_BLOCK_SIZE {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
            if bytes.is_empty() {
                return;
            }
        }
        while bytes.len() >= SHA512_BLOCK_SIZE {
            let block: &[u8; SHA512_BLOCK_SIZE] = bytes[..SHA512_BLOCK_SIZE].try_into().unwrap();
            self.compress(block);
            bytes = &bytes[SHA512_BLOCK_SIZE..];
        }
        self.buffer[..bytes.len()].copy_from_slice(bytes);
        self.buffer_len = bytes.len();
    }

    pub fn finish(mut self) -> [u8; SHA512_DIGEST_SIZE] {
        let bit_length = self.length_bytes.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 112 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..112].fill(0);
        self.buffer[112..128].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut digest = [0u8; SHA512_DIGEST_SIZE];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 8..index * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn compress(&mut self, block: &[u8; SHA512_BLOCK_SIZE]) {
        const K: [u64; 80] = [
            0x428a_2f98_d728_ae22,
            0x7137_4491_23ef_65cd,
            0xb5c0_fbcf_ec4d_3b2f,
            0xe9b5_dba5_8189_dbbc,
            0x3956_c25b_f348_b538,
            0x59f1_11f1_b605_d019,
            0x923f_82a4_af19_4f9b,
            0xab1c_5ed5_da6d_8118,
            0xd807_aa98_a303_0242,
            0x1283_5b01_4570_6fbe,
            0x2431_85be_4ee4_b28c,
            0x550c_7dc3_d5ff_b4e2,
            0x72be_5d74_f27b_896f,
            0x80de_b1fe_3b16_96b1,
            0x9bdc_06a7_25c7_1235,
            0xc19b_f174_cf69_2694,
            0xe49b_69c1_9ef1_4ad2,
            0xefbe_4786_384f_25e3,
            0x0fc1_9dc6_8b8c_d5b5,
            0x240c_a1cc_77ac_9c65,
            0x2de9_2c6f_592b_0275,
            0x4a74_84aa_6ea6_e483,
            0x5cb0_a9dc_bd41_fbd4,
            0x76f9_88da_8311_53b5,
            0x983e_5152_ee66_dfab,
            0xa831_c66d_2db4_3210,
            0xb003_27c8_98fb_213f,
            0xbf59_7fc7_beef_0ee4,
            0xc6e0_0bf3_3da8_8fc2,
            0xd5a7_9147_930a_a725,
            0x06ca_6351_e003_826f,
            0x1429_2967_0a0e_6e70,
            0x27b7_0a85_46d2_2ffc,
            0x2e1b_2138_5c26_c926,
            0x4d2c_6dfc_5ac4_2aed,
            0x5338_0d13_9d95_b3df,
            0x650a_7354_8baf_63de,
            0x766a_0abb_3c77_b2a8,
            0x81c2_c92e_47ed_aee6,
            0x9272_2c85_1482_353b,
            0xa2bf_e8a1_4cf1_0364,
            0xa81a_664b_bc42_3001,
            0xc24b_8b70_d0f8_9791,
            0xc76c_51a3_0654_be30,
            0xd192_e819_d6ef_5218,
            0xd699_0624_5565_a910,
            0xf40e_3585_5771_202a,
            0x106a_a070_32bb_d1b8,
            0x19a4_c116_b8d2_d0c8,
            0x1e37_6c08_5141_ab53,
            0x2748_774c_df8e_eb99,
            0x34b0_bcb5_e19b_48a8,
            0x391c_0cb3_c5c9_5a63,
            0x4ed8_aa4a_e341_8acb,
            0x5b9c_ca4f_7763_e373,
            0x682e_6ff3_d6b2_b8a3,
            0x748f_82ee_5def_b2fc,
            0x78a5_636f_4317_2f60,
            0x84c8_7814_a1f0_ab72,
            0x8cc7_0208_1a64_39ec,
            0x90be_fffa_2363_1e28,
            0xa450_6ceb_de82_bde9,
            0xbef9_a3f7_b2c6_7915,
            0xc671_78f2_e372_532b,
            0xca27_3ece_ea26_619c,
            0xd186_b8c7_21c0_c207,
            0xeada_7dd6_cde0_eb1e,
            0xf57d_4f7f_ee6e_d178,
            0x06f0_67aa_7217_6fba,
            0x0a63_7dc5_a2c8_98a6,
            0x113f_9804_bef9_0dae,
            0x1b71_0b35_131c_471b,
            0x28db_77f5_2304_7d84,
            0x32ca_ab7b_40c7_2493,
            0x3c9e_be0a_15c9_bebc,
            0x431d_67c4_9c10_0d4c,
            0x4cc5_d4be_cb3e_42b6,
            0x597f_299c_fc65_7e2a,
            0x5fcb_6fab_3ad6_faec,
            0x6c44_198c_4a47_5817,
        ];
        let mut words = [0u64; 80];
        for index in 0..16 {
            words[index] = u64::from_be_bytes(block[index * 8..index * 8 + 8].try_into().unwrap());
        }
        for index in 16..80 {
            let s0 = words[index - 15].rotate_right(1)
                ^ words[index - 15].rotate_right(8)
                ^ (words[index - 15] >> 7);
            let s1 = words[index - 2].rotate_right(19)
                ^ words[index - 2].rotate_right(61)
                ^ (words[index - 2] >> 6);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        self.state = [
            self.state[0].wrapping_add(a),
            self.state[1].wrapping_add(b),
            self.state[2].wrapping_add(c),
            self.state[3].wrapping_add(d),
            self.state[4].wrapping_add(e),
            self.state[5].wrapping_add(f),
            self.state[6].wrapping_add(g),
            self.state[7].wrapping_add(h),
        ];
    }
}

pub fn sha1(bytes: &[u8]) -> [u8; SHA1_DIGEST_SIZE] {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finish()
}

pub fn sha256(bytes: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finish()
}

pub fn sha512(bytes: &[u8]) -> [u8; SHA512_DIGEST_SIZE] {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    hasher.finish()
}

pub fn sha384(bytes: &[u8]) -> [u8; 48] {
    let mut hasher = Sha512::sha384();
    hasher.update(bytes);
    let digest = hasher.finish();
    let mut truncated = [0u8; 48];
    truncated.copy_from_slice(&digest[..48]);
    truncated
}

#[cfg(test)]
mod tests {
    use super::{Sha1, Sha256, Sha512, sha1, sha256, sha384, sha512};

    #[test]
    fn sha_vectors_match_nist_examples() {
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ]
        );
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert_eq!(
            sha384(b"abc"),
            [
                0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6,
                0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a,
                0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba,
                0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
            ]
        );
        assert_eq!(
            sha512(b"abc"),
            [
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
                0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
                0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
                0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
            ]
        );
    }

    #[test]
    fn streaming_hashes_match_single_shot() {
        let body: Vec<u8> = (0..8192u32).map(|index| (index % 251) as u8).collect();

        let mut sha1_state = Sha1::new();
        let mut sha256_state = Sha256::new();
        let mut sha384_state = Sha512::sha384();
        let mut sha512_state = Sha512::new();
        for chunk in body.chunks(97) {
            sha1_state.update(chunk);
            sha256_state.update(chunk);
            sha384_state.update(chunk);
            sha512_state.update(chunk);
        }
        assert_eq!(sha1_state.finish(), sha1(&body));
        assert_eq!(sha256_state.finish(), sha256(&body));
        assert_eq!(&sha384_state.finish()[..48], &sha384(&body));
        assert_eq!(sha512_state.finish(), sha512(&body));
    }
}
