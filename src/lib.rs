use num_bigint::{BigUint, RandBigInt};
use num_traits::Num;
use rand::{self, Rng};

pub struct ZKP {
    pub p: BigUint,
    pub q: BigUint,
    pub alpha: BigUint,
    pub beta: BigUint,
}

impl Default for ZKP {
    fn default() -> Self {
        Self::new()
    }
}

impl ZKP {
    pub fn new() -> Self {
        let p_hex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
        let q_hex = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";
        let alpha_hex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";

        let p = BigUint::from_str_radix(p_hex, 16).expect("Invalid hex for alpha");
        let q = BigUint::from_str_radix(q_hex, 16).expect("Invalid hex for q");
        let alpha = BigUint::from_str_radix(alpha_hex, 16).expect("Invalid hex for beta");

        // alpha^i is also a generator
        let exp = BigUint::from_str_radix("266D31266FEA1E5C41564B777E69", 16)
            .expect("could not create exp");
        let beta = ZKP::exponentiate(&alpha, &exp, &p);

        ZKP { alpha, beta, p, q }
    }

    /// output = n^exp mod p
    pub fn exponentiate(n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
        n.modpow(exponent, modulus)
    }

    /// output = s = k - c * x mod q
    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        if *k >= c * x {
            return (k - c * x).modpow(&BigUint::from(1u32), &self.q);
        }
        &self.q - (c * x - k).modpow(&BigUint::from(1u32), &self.q)
    }

    /// r1 = alpha^s * y1^c
    /// r2 = beta^s * y2^c
    pub fn verify(
        &self,
        r1: &BigUint,
        r2: &BigUint,
        y1: &BigUint,
        y2: &BigUint,
        c: &BigUint,
        s: &BigUint,
    ) -> bool {
        let sol1 = ZKP::exponentiate(&self.alpha, s, &self.p) * ZKP::exponentiate(y1, c, &self.p);
        let ver1 = *r1 == ZKP::exponentiate(&sol1, &BigUint::from(1u32), &self.p);

        let sol2 = ZKP::exponentiate(&self.beta, s, &self.p) * ZKP::exponentiate(y2, c, &self.p);
        let ver2 = *r2 == ZKP::exponentiate(&sol2, &BigUint::from(1u32), &self.p);

        ver1 && ver2
    }

    pub fn generate_random_below(bound: &BigUint) -> BigUint {
        rand::thread_rng().gen_biguint_below(bound)
    }

    pub fn generate_random_string(size: usize) -> String {
        rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(size)
            .map(char::from)
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_toy_example() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let zkp = ZKP {
            p: p.clone(),
            q,
            alpha: alpha.clone(),
            beta: beta.clone(),
        };

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);

        let c = BigUint::from(4u32);

        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);
        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        let s = zkp.solve(&k, &c, &x);
        assert_eq!(s, BigUint::from(5u32));

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result);

        // fake solution
        let x_fake = BigUint::from(7u32);
        let s_fake = zkp.solve(&k, &c, &x_fake);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s_fake);
        assert!(!result);
    }
    #[test]

    fn test_toy_example_with_random_numbers() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let zkp = ZKP {
            p: p.clone(),
            q: q.clone(),
            alpha: alpha.clone(),
            beta: beta.clone(),
        };

        let x = BigUint::from(6u32);
        let k = ZKP::generate_random_below(&q);

        let c = ZKP::generate_random_below(&q);

        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);

        let s = zkp.solve(&k, &c, &x);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result);
    }

    #[test]
    fn test_1024_bits_constants() {
        // https://www.rfc-editor.org/rfc/rfc5114.html#section-2.1
        let p_hex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
        let q_hex = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";
        let alpha_hex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";

        let p = BigUint::from_str_radix(p_hex, 16).expect("Invalid hex for alpha");
        let q = BigUint::from_str_radix(q_hex, 16).expect("Invalid hex for q");
        let alpha = BigUint::from_str_radix(alpha_hex, 16).expect("Invalid hex for beta");
        // alpha^i is also a generator
        let beta = ZKP::exponentiate(&alpha, &ZKP::generate_random_below(&q), &p);

        let zkp = ZKP {
            p: p.clone(),
            q: q.clone(),
            alpha: alpha.clone(),
            beta: beta.clone(),
        };

        let x = ZKP::generate_random_below(&q);
        let k = ZKP::generate_random_below(&q);

        let c = ZKP::generate_random_below(&q);

        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);

        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);

        let s = zkp.solve(&k, &c, &x);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result);
    }

    #[test]
    fn test_2048_bits_constants() {
        // https://www.rfc-editor.org/rfc/rfc5114.html#section-2.1
        let p_hex = "\
            AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1\
            B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15\
            EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212\
            9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207\
            C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708\
            B3BF8A317091883681286130BC8985DB1602E714415D9330\
            278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D\
            CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8\
            BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763\
            C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71\
            CF9DE5384E71B81C0AC4DFFE0C10E64F";
        let q_hex = "\
            801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB";
        let alpha_hex = "\
            AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF\
            74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA\
            AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7\
            C17669101999024AF4D027275AC1348BB8A762D0521BC98A\
            E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE\
            F180EB34118E98D119529A45D6F834566E3025E316A330EF\
            BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB\
            10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381\
            B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269\
            EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179\
            81BC087F2A7065B384B890D3191F2BFA";

        let p = BigUint::from_str_radix(p_hex, 16).expect("Invalid hex for alpha");
        let q = BigUint::from_str_radix(q_hex, 16).expect("Invalid hex for q");
        let alpha = BigUint::from_str_radix(alpha_hex, 16).expect("Invalid hex for beta");
        // alpha^i is also a generator
        let beta = ZKP::exponentiate(&alpha, &ZKP::generate_random_below(&q), &p);

        let zkp = ZKP {
            p: p.clone(),
            q: q.clone(),
            alpha: alpha.clone(),
            beta: beta.clone(),
        };

        let x = ZKP::generate_random_below(&q);
        let k = ZKP::generate_random_below(&q);

        let c = ZKP::generate_random_below(&q);

        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);

        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);

        let s = zkp.solve(&k, &c, &x);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result);
    }
}
