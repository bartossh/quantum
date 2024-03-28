use crate::globals::{AddressReader, AsVectorBytes};
use crate::globals::{Signer, Verifier};
use len_trait::len::{Empty, Len};
use serde::{Deserialize, Serialize};
use std::ops::Add;
use std::time::Instant;

/// Address holds pre and post quantum addresses.
#[derive(Serialize, Deserialize, Clone)]
pub struct Address {
    pre_quantum: String,
    post_quantum: String,
}

impl Address {
    #[inline(always)]
    pub fn from_address_reader(pre: &dyn AddressReader, post: &dyn AddressReader) -> Address {
        Address {
            pre_quantum: pre.address(),
            post_quantum: post.address(),
        }
    }

    #[inline(always)]
    pub fn get_pre_quantum(&self) -> String {
        self.pre_quantum.clone()
    }

    #[inline(always)]
    pub fn get_post_quantum(&self) -> String {
        self.post_quantum.clone()
    }
}

impl Empty for Address {
    fn is_empty(&self) -> bool {
        if self.pre_quantum.len() == 0 || self.post_quantum.len() == 0 {
            return true;
        }
        false
    }
}

impl Len for Address {
    fn len(&self) -> usize {
        self.pre_quantum.len() + self.post_quantum.len()
    }
}

impl AsVectorBytes for Address {
    fn as_vector_bytes(&self) -> Vec<u8> {
        let mut bytes = self.pre_quantum.as_bytes().to_vec();
        bytes.extend(self.post_quantum.as_bytes());

        bytes
    }
}

/// Signature holds per and post quantum signature
#[derive(Serialize, Deserialize, Clone)]
struct Signature {
    pre_quantum: Vec<u8>,
    post_quantum: Vec<u8>,
}

impl Signature {
    #[inline(always)]
    pub fn new() -> Signature {
        Signature {
            pre_quantum: Vec::new(),
            post_quantum: Vec::new(),
        }
    }

    #[inline(always)]
    pub fn update(&mut self, pre: &[u8], post: &[u8]) {
        self.pre_quantum = pre.to_vec();
        self.post_quantum = post.to_vec();
    }

    #[inline(always)]
    pub fn get_pre_quantum(&self) -> &[u8] {
        &self.pre_quantum
    }

    #[inline(always)]
    pub fn get_post_quantum(&self) -> &[u8] {
        &self.post_quantum
    }
}

/// Transaction contains all the data required for data to represent legally sealed data.
///
#[derive(Serialize, Deserialize, Clone)]
pub struct Transaction {
    subject: String,
    data: Vec<u8>,
    created_at: u128,
    issuer: Address,
    receiver: Address,
    issuer_sig: Signature,
    receiver_sig: Signature,
}

impl Transaction {
    /// Issues the transaction signing it with issuer.
    ///
    #[inline]
    pub fn issue<T: Signer + AddressReader, D: Signer + AddressReader>(
        pre_q_issuer: &T,
        post_q_issuer: &D,
        subject: String,
        data: Vec<u8>,
        receiver: Address,
    ) -> Transaction {
        let created_at = Instant::now().elapsed().as_nanos();
        let mut trx: Transaction = Transaction {
            subject,
            data: data.clone(),
            created_at,
            issuer: Address::from_address_reader(pre_q_issuer, post_q_issuer),
            receiver,
            issuer_sig: Signature::new(),
            receiver_sig: Signature::new(),
        };

        let trx_bytes = trx.as_vector_bytes();
        trx.issuer_sig.update(
            &pre_q_issuer.sign(&trx_bytes),
            &post_q_issuer.sign(&trx_bytes),
        );

        trx
    }

    /// Approves the transactions siging it by the receiver.
    ///
    #[inline(always)]
    pub fn approve(
        &mut self,
        pre_quantum_receiver: &dyn Signer,
        post_quantum_receiver: &dyn Signer,
    ) {
        let trx_bytes = self.as_vector_bytes();
        self.receiver_sig.update(
            &pre_quantum_receiver.sign(&trx_bytes),
            &post_quantum_receiver.sign(&trx_bytes),
        );
    }

    /// Validate transaction against issuer signature.
    ///
    #[inline(always)]
    pub fn validate_for_issuer(
        &self,
        pre_validator: &dyn Verifier,
        post_validator: &dyn Verifier,
    ) -> bool {
        let trx_bytes = &self.as_vector_bytes();
        if let Err(_) = pre_validator.validate_other(
            &trx_bytes,
            &self.issuer_sig.get_pre_quantum(),
            &self.issuer.get_pre_quantum(),
        ) {
            return false;
        }
        if let Err(_) = post_validator.validate_other(
            &trx_bytes,
            &self.issuer_sig.get_post_quantum(),
            &self.issuer.get_post_quantum(),
        ) {
            return false;
        }

        true
    }

    /// Validate transaction against receiver signature.
    #[inline(always)]
    pub fn validate_for_receiver(
        &self,
        pre_validator: &dyn Verifier,
        post_validator: &dyn Verifier,
    ) -> bool {
        let trx_bytes = &self.as_vector_bytes();
        if let Err(_) = pre_validator.validate_other(
            &trx_bytes,
            &self.receiver_sig.get_pre_quantum(),
            &self.receiver.get_pre_quantum(),
        ) {
            return false;
        }
        if let Err(_) = post_validator.validate_other(
            &trx_bytes,
            &self.receiver_sig.get_post_quantum(),
            &self.receiver.get_post_quantum(),
        ) {
            return false;
        }

        true
    }
}

impl Transaction {
    #[inline]
    fn estimated_size(&self) -> usize {
        let mut size = 0;
        size += self.subject.len() + self.data.len() + 16;
        size += self.issuer.len() + self.receiver.len();
        size
    }
}

impl AsVectorBytes for Transaction {
    #[inline]
    fn as_vector_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(self.estimated_size());

        buffer.extend(self.subject.as_bytes());
        buffer.extend(&self.data);
        buffer.extend(&self.created_at.to_ne_bytes());
        buffer.extend(self.issuer.as_vector_bytes());
        buffer.extend(self.receiver.as_vector_bytes());

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asymmetric_pre_quant_signer::SignerWallet as PreQuantSignerWallet;
    use crate::{asymmetric_quant_signer::SignerWallet, globals::AddressReader};
    use std::{thread, time};

    #[derive(Clone, Copy)]
    struct SignerMock {}

    impl Signer for SignerMock {
        fn sign(&self, _: &[u8]) -> Vec<u8> {
            "pucy6qnk6pmg6ttul0hbl6xzgxh6dfjceqcs9tewxr2jjrtdhotzi1a03pvqibj2eilft8mwdlwz986/8wwci6cx1zz0ly1t+ehjn7sphpoov4u71yroln9jdevok5olzwgiy6adoxynabrumaupidkfjcbwsgalejm/y9ly/r3z1y5vou6cz/rd6v+dmpch9jjcqncaj0zp/+4pisdbwmegzwadiyfi6ignhicywtvbty4pqkcpjvebgmufilfl+uny1gjvqajac941bx5tfl+dphcuxg3ztpajdx0tfmk5vqhqvzjuo3oplpn4iqfnv7itukbdudcpcqctiyy23nzdreldzlhxr33nurhm6mx4hn2ygnk3aiam1jrnhhusiweqggbkcrqgeehv4ge/j2x8o1gfkocl+2kl+ztlhs5eiiqojypux4x8ewslspbdqb7ckskmnmemgyq0gvqh75crqduwdrs+z/jl0didrwnhbtuvak41+nhn1yejvo+qepejatanqajkw+tst4ia/3rdv46oz6dvqroowiacgpwqtebpo4fcrzc3vrz/flczk92s7kkiulr1eiomy2fybzwmlefckk1i/elinchnusffspwlhzkf/gqpyuhsf6we2yvljgztjjpfkg8wbelttaqo3d1hwkew3jehvuqwrw49lvowqgtzfj0mcuypu8qeuuckkjyu+uzd1u9+nusnznuz+jqf1wubqq1galom+tlipswle9ypbgi7krmvbch93el22oidynt+zdeikaa053jvwmren2lhj85f189ziw2wbybxk0htqgwxxw/zhzqxjhjs3pwkhrxdf/35m2fwxoefixkvdqixhqko7kwsnwmv2iumsodlb2lihbjpu6ruzeao6mqvrrrn9ljw9dudgjhs4u/odpoqobyrvxixoqw0uylnj18tossvdh0dvldayk+f9kfsevofgihhpg3qae9zwu3ixtvdv+9sv0tsyoqkbamrxfwimiqwzfznzaxpd/70rdcwpijzpv9nf9km38cdpivbr8fj0nb/jiv2wsevw0s9gfwmsfhcsqfg+jpuwr2ljmq/urtvyp9ainqc8xfcosc74iwqc7fdywni5149bybandldaq6uax75kuwmmxtpjbmgbiusf89d+njyakzdz/n6dqfjun7rlbrfmlczjem24imhqmd94pzyhvw66flub/g4e+u/wka7xwwawpmxlh3xed1cyvhiyqodp7ydk4blwylczd5ufb7pqrp7idnro8srp7p+qusrowqsu9br7suubreyyzdhntja7eqmcdwvxae32/b1tbtqxy2jovqepo1eeg/sb3nl1hlrefcy0aeysvkxo4akicigw36bthjkq5rauv6136tcvma+u/ey4doeoiyduj+zhlkwnlwz97sz6xd8s3pgyecvkpnnzph77bz5tqp6iidk/b8yyf6purwakmg24l65lnorusekjwpnnajuhjdt2tqypejnkx5yxwi/gvbdrgpchp6r6fooufhoeurxljhanhb3cdyffmg6ncvz8h/e+twizlobs3wilyi/wq4tupo7tbdhjlfquiwabunbcpxkiyheejqdqbonclb8bkaof01uspzkjhnzfhvv/ghzozjjevnlivmbi2untllwcundl8lxhyg2/kdgtum2jjsqgmxmycdbc7cythanmfoci7rbqf+hrfpvazgwyxixbe3dzcpsy/917utn6f7wuiazlg/0geot8aa6urgru+309hpd0mxqo1voi/d/8aoizcmld5ioqokryxiufz6hkqs4xxjv98n/jgjvtck26bnibqmapigzmafkxauswh23wvqbnzyz3h3yrz2g6gcv12urg4olm1h5lhxvehklcwgtxznndq7iexqey9quaymgcy1zojjhtqogynj9lwjmwv1tdcaqwnw/osconakide7inqs6rd2qg4dfudkztvpe31ekaefoicyuxee7gxwybzchc/1g+jj0wjatly82k/+/kj/k5+7ympirtd2mcunjg+gpnxygxhl+m5w8rizjcb/lp0kuoyvrjsrardyabthb4emvfgn0m7tebx3dautu+viwfymgbng64vqxqkrf4icu1ckuhzahlw17xjpzcmtyafe1yoechwgb4+xps/tcktft1u30wema5uoajtrrsuuqo6x7/vdsrw2/o+xezgtooxfooq3xqo9m88qyzdnk39yo7+e8owx5vwqi2xwvezm5avq1/yic72rsj37v9z/gojowpdfaivjzgdzxr7csxnywkgptq3jlx6cb10q9an5etrw2t4zodft5ggair6yvakv62r5e41ldcxhr1v6jljgyrh6hegdigpu7baa1kxu4efxz2vwitznwxhn3fginowqy2sdtnxbxx9/z8ixtnvdsddlr2gmaenu9a93e0da8xyokfzo1g0zsdpxqbzq47egbkl49srrvat9nc7uckqycemmgsyhvgo8n9qtxhduuzmfviiesshtuxfwkbky2eko/fwbzrukd1vbbe9ajo30ygfkwrlowzyw+r9z16vuqckavaln2tbzmeff3z06f2+aflar7ildq7p0mvvy+gwkje5f2gaa0ahczyhmffp6yzmokljrnto6x6gbjmviyp21fcjphlyiskodrwcvvqdaa/tegvqqwuqqwur9aes/ahpzsjutsybc+nreg18rvc41j1alcebjiridbjj1p3g4f4nw6/ldcp4rajmj+xd1cogxpqooisnoca6yys42sjojd8jwsqshb8got9s38sa73e8xn50yxdo7gzxbiroru64z9a7qvsesx6kulls6tercoi8sjckhggxnjag5lrhkx2vmmzqaca1gppybcylem3tn0btkgln/vuzjr0fl7pwxphwjcn7jxpqcqr5wbhm8dvc0csod7ush3de89qwr4wbawvkx0jp5wryw9+e8nj9pm35twuvi1r14wwhzrsmjyezg4za2xjsn8lmy/+/j13iigpcnbtemjy376uz76bhtirqntzjvjcjhzxb2czuzc2fqr4ncypodztcndybh+xoew/wxstrlbu31bke2vbybcidfxkx/iioqlx8f+yooe5xv8qb1miwckokpywbaqcri5hmq7wwes2fhijf4ls8ex02psfkk5yct8we1r5a9mmbmqx43acpxcd5gboguyfzrvyxfmyxftf4hnsiljhxv7owawheoyiokxkmot/sg99fqc10jo9/wfktmgwmz7l9rh+ocshflmfh1yqjq1cfbsz0yz6w+xapt7za3ekcuzyvwj/f2g4o1vi5l2ymhbg/tt68lzmmjidbfbo431rndujfwnungyne2bbrf/cj9njopno6wzonbla4fcfzhwbgtilc81zroqimvbynb1szdgqbkkltuvzc1msdexngcluir5l6ggo8ncsrgfzprxhtjz6ryh1b3prgr/sf0vuk0rqz+/zduu6ory0sdhwmnfimmcczrmfkpucsnxihbd1vxoyicmmhhedmnayvpbf88p3wpiu22ob0xf2en3rslpndlg2ajid3mzegoggtyvrxtraxk8mrqwuofmgatvbvz4tiaf1vl4yhkabicfhuy4fc+ej1edszvfzpehuly7/lrd0glr+xnppghdljdurus7apozk3ubfllomlbwcbfokkdywmxrftxn4mlppc9jexaxb38ltonae/brrnw589t+h42jzrxfejzafbg7ovt95vjfkjlr5lm5diextgtvvjaglh3fe+mitqnvyakt5+hkkplo4+symms6mvgpxzq4rbrdlsu3pisozfyye/qnlj0vmtjgzd5k5mjndrspar/1pyjr7pic+fdioldlpp9egpleb7vyyas8mj8ckly4gxpjhw334tqfx+ayebkundlwpof97ahuwqzhjqjf4qca1unopey4ldx+posdhdcggnueyxhwtzvxglqfh2ltetsiht1n7c2mb6zyucenhhkshmtmdftasrw9ij0bjwazexs0rqst2czdp7au8x5i8jyziyqnkfterolil43rpw/zqou+stndrqgss77hpbousjs9findv6hhyzulrjdhkciznthxvxk506qkvffet6t24qn+ulsermisb5f344skr+sl2dslaelthmgbulsag9fqpc5q4/pizlbrje0dff+hoxptf9ae6xsqx3/25kj/yepc/5qndn6iyvruhy+ransywrhgspfwi13qmf0dcjsskdknunvaooge3j75rekz2pqjf3guokkl/igurnsh7jpnobptwl+i9b1to18dpzszuxv/3i73naihlra19svs3igshhbvmob5l5thhibg0utrkialygpfrurqn4ngnt5tqjem2uvcbw+lboiqfyxmicegemtgxg1l5szcrevjx/3iikr5esfjdmmiijz5s0llpvo8ikg3sqiicixj+z6hcwituk49/cczzytwmddgvybj5p7r/d1p0fifonv/zsj3k/sdtihuknc0vfiwvk6glqbemkn/lq82iayitcrcsn+kmi1jzip7fdwn+kokvxmiu9z0dbz9nir6eatu1pgoi6v0mqqgtdfovk3demkdmkhk6d1uh4tu7zl1g5uj93t0gjnin30dy4hnal8otijeq0ocfmrid/ggsjhjofduwkgegj/d+cdyaybanq6hdlo7mg2f6jh4ye0p3edingvvbqdnipsaeiu6r9sikvaprkgmckue8jieriyxarbwi9i4s4lbgeauugdvvcc3xg6an8oubvatciqawx4ailzcow0tevxvwtywgu33hexecovbvzqpr4bh3xynt/hkucn0yqqhoakptipblx6me97rhryq3bb437aejeamhb7xgxkz8ad54dgq3jivdphwk4tt7njvqwaiugdqvjbirsrrrwbsx68wbbk0ls6zwhhzg0ixsad20ky68z7o5fthbx1dlpbrdgmbc+1t1uy79s1bleewcyjypgqqpe+bap0hd1xwlfeiuhvru7yyscyagpnvvzoxymjjvdtt8kdjpqxxdvyofj38xqp78jjkpcp9jew23ybre4/kp6zmmleqoocs1lqfxxaj7mgsiqjnbkeeteslgi/xck91enewfg2krrjezpdr+lyduabtcxpqmp+duxywsyoksw3dzbx5u0x4uplp8t0kbv6pb+sxmphhzyypkkz9/itwqlugtyrc7tt8/wj4revhrikdtnbzgbyynyp8kinn7fm8djhxitav79atuhr1j2fp+2adw6yk2qrno6h2levvdvcps49mavrzh7ridimvieodl8lvz2rbjpvxjcaghbpn3ifxczrnsdvd/lz6amiggedklsxjwzlk9yg2cmi//xjbhl0iw5a1xla2yqzanq==".to_string().as_bytes().to_vec()
        }
    }

    impl AddressReader for SignerMock {
        fn address(&self) -> String {
            "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".to_string()
        }
    }

    #[test]
    fn as_vec_bytes() {
        let data = "pucy6qnk6pmg6ttul0hbl6xzgxh6dfjceqcs9tewxr2jjrtdhotzi1a03pvqibj2eilft8mwdlwz986/8wwci6cx1zz0ly1t+ehjn7sphpoov4u71yroln9jdevok5olzwgiy6adoxynabrumaupidkfjcbwsgalejm/y9ly/r3z1y5vou6cz/rd6v+dmpch9jjcqncaj0zp/+4pisdbwmegzwadiyfi6ignhicywtvbty4pqkcpjvebgmufilfl+uny1gjvqajac941bx5tfl+dphcuxg3ztpajdx0tfmk5vqhqvzjuo3oplpn4iqfnv7itukbdudcpcqctiyy23nzdreldzlhxr33nurhm6mx4hn2ygnk3aiam1jrnhhusiweqggbkcrqgeehv4ge/j2x8o1gfkocl+2kl+ztlhs5eiiqojypux4x8ewslspbdqb7ckskmnmemgyq0gvqh75crqduwdrs+z/jl0didrwnhbtuvak41+nhn1yejvo+qepejatanqajkw+tst4ia/3rdv46oz6dvqroowiacgpwqtebpo4fcrzc3vrz/flczk92s7kkiulr1eiomy2fybzwmlefckk1i/elinchnusffspwlhzkf/gqpyuhsf6we2yvljgztjjpfkg8wbelttaqo3d1hwkew3jehvuqwrw49lvowqgtzfj0mcuypu8qeuuckkjyu+uzd1u9+nusnznuz+jqf1wubqq1galom+tlipswle9ypbgi7krmvbch93el22oidynt+zdeikaa053jvwmren2lhj85f189ziw2wbybxk0htqgwxxw/zhzqxjhjs3pwkhrxdf/35m2fwxoefixkvdqixhqko7kwsnwmv2iumsodlb2lihbjpu6ruzeao6mqvrrrn9ljw9dudgjhs4u/odpoqobyrvxixoqw0uylnj18tossvdh0dvldayk+f9kfsevofgihhpg3qae9zwu3ixtvdv+9sv0tsyoqkbamrxfwimiqwzfznzaxpd/70rdcwpijzpv9nf9km38cdpivbr8fj0nb/jiv2wsevw0s9gfwmsfhcsqfg+jpuwr2ljmq/urtvyp9ainqc8xfcosc74iwqc7fdywni5149bybandldaq6uax75kuwmmxtpjbmgbiusf89d+njyakzdz/n6dqfjun7rlbrfmlczjem24imhqmd94pzyhvw66flub/g4e+u/wka7xwwawpmxlh3xed1cyvhiyqodp7ydk4blwylczd5ufb7pqrp7idnro8srp7p+qusrowqsu9br7suubreyyzdhntja7eqmcdwvxae32/b1tbtqxy2jovqepo1eeg/sb3nl1hlrefcy0aeysvkxo4akicigw36bthjkq5rauv6136tcvma+u/ey4doeoiyduj+zhlkwnlwz97sz6xd8s3pgyecvkpnnzph77bz5tqp6iidk/b8yyf6purwakmg24l65lnorusekjwpnnajuhjdt2tqypejnkx5yxwi/gvbdrgpchp6r6fooufhoeurxljhanhb3cdyffmg6ncvz8h/e+twizlobs3wilyi/wq4tupo7tbdhjlfquiwabunbcpxkiyheejqdqbonclb8bkaof01uspzkjhnzfhvv/ghzozjjevnlivmbi2untllwcundl8lxhyg2/kdgtum2jjsqgmxmycdbc7cythanmfoci7rbqf+hrfpvazgwyxixbe3dzcpsy/917utn6f7wuiazlg/0geot8aa6urgru+309hpd0mxqo1voi/d/8aoizcmld5ioqokryxiufz6hkqs4xxjv98n/jgjvtck26bnibqmapigzmafkxauswh23wvqbnzyz3h3yrz2g6gcv12urg4olm1h5lhxvehklcwgtxznndq7iexqey9quaymgcy1zojjhtqogynj9lwjmwv1tdcaqwnw/osconakide7inqs6rd2qg4dfudkztvpe31ekaefoicyuxee7gxwybzchc/1g+jj0wjatly82k/+/kj/k5+7ympirtd2mcunjg+gpnxygxhl+m5w8rizjcb/lp0kuoyvrjsrardyabthb4emvfgn0m7tebx3dautu+viwfymgbng64vqxqkrf4icu1ckuhzahlw17xjpzcmtyafe1yoechwgb4+xps/tcktft1u30wema5uoajtrrsuuqo6x7/vdsrw2/o+xezgtooxfooq3xqo9m88qyzdnk39yo7+e8owx5vwqi2xwvezm5avq1/yic72rsj37v9z/gojowpdfaivjzgdzxr7csxnywkgptq3jlx6cb10q9an5etrw2t4zodft5ggair6yvakv62r5e41ldcxhr1v6jljgyrh6hegdigpu7baa1kxu4efxz2vwitznwxhn3fginowqy2sdtnxbxx9/z8ixtnvdsddlr2gmaenu9a93e0da8xyokfzo1g0zsdpxqbzq47egbkl49srrvat9nc7uckqycemmgsyhvgo8n9qtxhduuzmfviiesshtuxfwkbky2eko/fwbzrukd1vbbe9ajo30ygfkwrlowzyw+r9z16vuqckavaln2tbzmeff3z06f2+aflar7ildq7p0mvvy+gwkje5f2gaa0ahczyhmffp6yzmokljrnto6x6gbjmviyp21fcjphlyiskodrwcvvqdaa/tegvqqwuqqwur9aes/ahpzsjutsybc+nreg18rvc41j1alcebjiridbjj1p3g4f4nw6/ldcp4rajmj+xd1cogxpqooisnoca6yys42sjojd8jwsqshb8got9s38sa73e8xn50yxdo7gzxbiroru64z9a7qvsesx6kulls6tercoi8sjckhggxnjag5lrhkx2vmmzqaca1gppybcylem3tn0btkgln/vuzjr0fl7pwxphwjcn7jxpqcqr5wbhm8dvc0csod7ush3de89qwr4wbawvkx0jp5wryw9+e8nj9pm35twuvi1r14wwhzrsmjyezg4za2xjsn8lmy/+/j13iigpcnbtemjy376uz76bhtirqntzjvjcjhzxb2czuzc2fqr4ncypodztcndybh+xoew/wxstrlbu31bke2vbybcidfxkx/iioqlx8f+yooe5xv8qb1miwckokpywbaqcri5hmq7wwes2fhijf4ls8ex02psfkk5yct8we1r5a9mmbmqx43acpxcd5gboguyfzrvyxfmyxftf4hnsiljhxv7owawheoyiokxkmot/sg99fqc10jo9/wfktmgwmz7l9rh+ocshflmfh1yqjq1cfbsz0yz6w+xapt7za3ekcuzyvwj/f2g4o1vi5l2ymhbg/tt68lzmmjidbfbo431rndujfwnungyne2bbrf/cj9njopno6wzonbla4fcfzhwbgtilc81zroqimvbynb1szdgqbkkltuvzc1msdexngcluir5l6ggo8ncsrgfzprxhtjz6ryh1b3prgr/sf0vuk0rqz+/zduu6ory0sdhwmnfimmcczrmfkpucsnxihbd1vxoyicmmhhedmnayvpbf88p3wpiu22ob0xf2en3rslpndlg2ajid3mzegoggtyvrxtraxk8mrqwuofmgatvbvz4tiaf1vl4yhkabicfhuy4fc+ej1edszvfzpehuly7/lrd0glr+xnppghdljdurus7apozk3ubfllomlbwcbfokkdywmxrftxn4mlppc9jexaxb38ltonae/brrnw589t+h42jzrxfejzafbg7ovt95vjfkjlr5lm5diextgtvvjaglh3fe+mitqnvyakt5+hkkplo4+symms6mvgpxzq4rbrdlsu3pisozfyye/qnlj0vmtjgzd5k5mjndrspar/1pyjr7pic+fdioldlpp9egpleb7vyyas8mj8ckly4gxpjhw334tqfx+ayebkundlwpof97ahuwqzhjqjf4qca1unopey4ldx+posdhdcggnueyxhwtzvxglqfh2ltetsiht1n7c2mb6zyucenhhkshmtmdftasrw9ij0bjwazexs0rqst2czdp7au8x5i8jyziyqnkfterolil43rpw/zqou+stndrqgss77hpbousjs9findv6hhyzulrjdhkciznthxvxk506qkvffet6t24qn+ulsermisb5f344skr+sl2dslaelthmgbulsag9fqpc5q4/pizlbrje0dff+hoxptf9ae6xsqx3/25kj/yepc/5qndn6iyvruhy+ransywrhgspfwi13qmf0dcjsskdknunvaooge3j75rekz2pqjf3guokkl/igurnsh7jpnobptwl+i9b1to18dpzszuxv/3i73naihlra19svs3igshhbvmob5l5thhibg0utrkialygpfrurqn4ngnt5tqjem2uvcbw+lboiqfyxmicegemtgxg1l5szcrevjx/3iikr5esfjdmmiijz5s0llpvo8ikg3sqiicixj+z6hcwituk49/cczzytwmddgvybj5p7r/d1p0fifonv/zsj3k/sdtihuknc0vfiwvk6glqbemkn/lq82iayitcrcsn+kmi1jzip7fdwn+kokvxmiu9z0dbz9nir6eatu1pgoi6v0mqqgtdfovk3demkdmkhk6d1uh4tu7zl1g5uj93t0gjnin30dy4hnal8otijeq0ocfmrid/ggsjhjofduwkgegj/d+cdyaybanq6hdlo7mg2f6jh4ye0p3edingvvbqdnipsaeiu6r9sikvaprkgmckue8jieriyxarbwi9i4s4lbgeauugdvvcc3xg6an8oubvatciqawx4ailzcow0tevxvwtywgu33hexecovbvzqpr4bh3xynt/hkucn0yqqhoakptipblx6me97rhryq3bb437aejeamhb7xgxkz8ad54dgq3jivdphwk4tt7njvqwaiugdqvjbirsrrrwbsx68wbbk0ls6zwhhzg0ixsad20ky68z7o5fthbx1dlpbrdgmbc+1t1uy79s1bleewcyjypgqqpe+bap0hd1xwlfeiuhvru7yyscyagpnvvzoxymjjvdtt8kdjpqxxdvyofj38xqp78jjkpcp9jew23ybre4/kp6zmmleqoocs1lqfxxaj7mgsiqjnbkeeteslgi/xck91enewfg2krrjezpdr+lyduabtcxpqmp+duxywsyoksw3dzbx5u0x4uplp8t0kbv6pb+sxmphhzyypkkz9/itwqlugtyrc7tt8/wj4revhrikdtnbzgbyynyp8kinn7fm8djhxitav79atuhr1j2fp+2adw6yk2qrno6h2levvdvcps49mavrzh7ridimvieodl8lvz2rbjpvxjcaghbpn3ifxczrnsdvd/lz6amiggedklsxjwzlk9yg2cmi//xjbhl0iw5a1xla2yqzanq==".to_string().as_bytes().to_vec();
        let s = SignerMock {};
        let trx = Transaction::issue(
            &s,
            &s,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&s, &s),
        );
        let rounds: usize = 5;
        for _ in 0..rounds {
            let v = &trx.as_vector_bytes()[..];
            assert_eq!(v.len(), trx.estimated_size());
        }
    }

    #[test]
    fn issue() {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let rounds: usize = 2;
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        for _ in 0..rounds {
            let trx = Transaction::issue(
                &issuer,
                &q_issuer,
                "next transaction".to_string(),
                data.clone(),
                Address::from_address_reader(&receiver, &q_receiver),
            );
            assert_eq!(trx.as_vector_bytes().len(), trx.estimated_size());
        }
    }

    #[test]
    fn approve() {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let rounds: usize = 2;
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );
        for _ in 0..rounds {
            trx.approve(&receiver, &q_receiver);
            assert_eq!(trx.as_vector_bytes().len(), trx.estimated_size());
        }
    }

    #[test]
    fn validate_for_issuer() {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let rounds: usize = 2;
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );
        for _ in 0..rounds {
            let result = trx.validate_for_issuer(&receiver, &q_receiver);
            assert_eq!(result, true);
        }
    }

    #[test]
    fn validate_for_receiver() {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let rounds: usize = 2;
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );
        trx.approve(&receiver, &q_receiver);

        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&issuer, &q_issuer);
            assert_eq!(result, true);
        }
        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&receiver, &q_receiver);
            assert_eq!(result, true);
        }
    }

    #[test]
    fn validate_for_wrong_issuer() {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let rounds: usize = 2;
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );

        trx.issuer = Address::from_address_reader(&receiver, &q_receiver); // Inject wrong issuer address.

        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&issuer, &q_issuer);
            assert_eq!(result, false);
        }
        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&receiver, &q_receiver);
            assert_eq!(result, false);
        }
    }

    #[test]
    fn validate_for_wrong_receiver() {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let rounds: usize = 2;
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );
        trx.approve(&issuer, &q_issuer); // Approve by the wrong wallet.

        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&issuer, &q_issuer);
            assert_eq!(result, false);
        }
        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&receiver, &q_receiver);
            assert_eq!(result, false);
        }
    }

    #[test]
    fn validate_for_altered_data() {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let rounds: usize = 2;
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );

        let mut data_wrong: Vec<u8> = Vec::with_capacity(cap);
        for i in 0..cap {
            if i % 100 == 0 {
                data_wrong.push(255);
            } else {
                data_wrong.push(128);
            }
        }

        trx.data = data_wrong.clone(); // Alter data.

        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&issuer, &q_issuer);
            assert_eq!(result, false);
        }
        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&receiver, &q_receiver);
            assert_eq!(result, false);
        }
    }

    #[test]
    fn validate_for_altered_zero_data() {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let rounds: usize = 2;
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );

        trx.data = Vec::new().clone(); // Alter data.

        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&issuer, &q_issuer);
            assert_eq!(result, false);
        }
        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&receiver, &q_receiver);
            assert_eq!(result, false);
        }
    }

    #[test]
    fn validate_for_altered_subject() {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let rounds: usize = 2;
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );

        trx.subject = "altered".to_string();

        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&issuer, &q_issuer);
            assert_eq!(result, false);
        }
        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&receiver, &q_receiver);
            assert_eq!(result, false);
        }
    }

    #[test]
    fn validate_for_altered_time() {
        let q_issuer: SignerWallet = SignerWallet::new();
        let issuer: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let q_receiver: SignerWallet = SignerWallet::new();
        let receiver: PreQuantSignerWallet = PreQuantSignerWallet::new();
        let rounds: usize = 2;
        let cap = 100000;
        let mut data: Vec<u8> = Vec::with_capacity(cap);
        for _ in 0..cap {
            data.push(128);
        }
        let mut trx = Transaction::issue(
            &issuer,
            &q_issuer,
            "next transaction".to_string(),
            data,
            Address::from_address_reader(&receiver, &q_receiver),
        );

        let hundred_millis = time::Duration::from_millis(100);
        thread::sleep(hundred_millis);
        trx.created_at = Instant::now().elapsed().as_nanos();

        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&issuer, &q_issuer);
            assert_eq!(result, false);
        }
        for _ in 0..rounds {
            let result = trx.validate_for_receiver(&receiver, &q_receiver);
            assert_eq!(result, false);
        }
    }
}
