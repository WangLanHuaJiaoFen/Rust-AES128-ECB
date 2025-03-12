// S盒和逆S盒的定义
mod aes;
mod block;
mod ecb;
mod key_expansion;
mod table;

// use aes::{inv_sub_bytes, sub_bytes, shift_rows, mix_columns, inv_mix_columns, add_round_key, key_expansion};
// S盒运算和逆S盒运算
use ecb::{aes_ecb_decrypt_string, aes_ecb_encrypt_string};

fn main() {
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x30, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    println!("请输入要加密的字符串:");
    let mut plainstring = String::new();

    std::io::stdin()
        .read_line(&mut plainstring)
        .expect("读取输入失败");
    let plainstring = plainstring.trim().to_string();

    let cipherstring = aes_ecb_encrypt_string(&plainstring, &key);
    println!("加密后的密文:{}", cipherstring);

    let decryptedtext = aes_ecb_decrypt_string(&cipherstring, &key);
    println!("解密后的明文:{}", decryptedtext);
}
