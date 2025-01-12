package chacha20

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func Test_chaCha20RoundBlock(t *testing.T) {
	var chaCha20RoundBlockTestVectors = []struct {
		name      string
		key       [32]byte
		nonce     [12]byte
		counter   uint64
		chaCha20RoundBlock [64]byte
	}{
		{
			name:      "RFC8439 Appendix A.1 (Key Stream Test Vector) #1",
			key:       [32]byte(mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000000")),
			nonce:     [12]byte(mustDecodeHex("000000000000000000000000")),
			counter:   0x00000000,
			chaCha20RoundBlock: [64]byte(mustDecodeHex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")),
		},
		{
			name:      "RFC8439 Appendix A.1 (Key Stream Test Vector) #2",
			key:       [32]byte(mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000000")),
			nonce:     [12]byte(mustDecodeHex("000000000000000000000000")),
			counter:   0x00000001,
			chaCha20RoundBlock: [64]byte(mustDecodeHex("9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f")),
		},
		{
			name:      "RFC8439 Appendix A.1 (Key Stream Test Vector) #3",
			key:       [32]byte(mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000001")),
			nonce:     [12]byte(mustDecodeHex("000000000000000000000000")),
			counter:   0x00000001,
			chaCha20RoundBlock: [64]byte(mustDecodeHex("3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0")),
		},
		{
			name:      "RFC8439 Appendix A.1 (Key Stream Test Vector) #4",
			key:       [32]byte(mustDecodeHex("00ff000000000000000000000000000000000000000000000000000000000000")),
			nonce:     [12]byte(mustDecodeHex("000000000000000000000000")),
			counter:   0x00000002,
			chaCha20RoundBlock: [64]byte(mustDecodeHex("72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096")),
		},
		{
			name:      "RFC8439 Appendix A.1 (Key Stream Test Vector) #5",
			key:       [32]byte(mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000000")),
			nonce:     [12]byte(mustDecodeHex("000000000000000000000002")),
			counter:   0x00000000,
			chaCha20RoundBlock: [64]byte(mustDecodeHex("c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d")),
		},
	}
	for _, v := range chaCha20RoundBlockTestVectors {
		t.Run(v.name, func(t *testing.T) {
			x, _ := NewCipher(v.key[:], v.nonce[:], v.counter)
			if got := x.chaCha20RoundBlock(); !reflect.DeepEqual(got, v.chaCha20RoundBlock) {
				t.Errorf("Cipher.chaCha20RoundBlock()\ngot:  %s\nwant: %s", hex.EncodeToString(got[:64]), hex.EncodeToString(v.chaCha20RoundBlock[:64]))
			}
		})
	}
}

func Test_state_XORKeyStream(t *testing.T) {
	encryptionTestVectors := []struct {
		name       string
		key        [32]byte
		nonce      [12]byte
		counter    uint64
		plaintext  []byte
		ciphertext []byte
	}{
		{
			name:       "RFC8439 Appendix A.2 (Encryption Test Vector) #1",
			key:        [32]byte(mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000000")),
			nonce:      [12]byte(mustDecodeHex("000000000000000000000000")),
			counter:    0x00000000,
			plaintext:  mustDecodeHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			ciphertext: mustDecodeHex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"),
		},
		{
			name:       "RFC8439 Appendix A.2 (Encryption Test Vector) #2",
			key:        [32]byte(mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000001")),
			nonce:      [12]byte(mustDecodeHex("000000000000000000000002")),
			counter:    0x00000001,
			plaintext:  []byte("Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to"),
			ciphertext: mustDecodeHex("a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221"),
		},
		{
			name:       "RFC8439 Appendix A.2 (Encryption Test Vector) #3",
			key:        [32]byte(mustDecodeHex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")),
			nonce:      [12]byte(mustDecodeHex("000000000000000000000002")),
			counter:    0x0000002a,
			plaintext:  mustDecodeHex("2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e"),
			ciphertext: mustDecodeHex("62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"),
		},
	}
	for _, v := range encryptionTestVectors {
		t.Run(v.name, func(t *testing.T) {
			x, _ := NewCipher(v.key[:], v.nonce[:], v.counter)
			got := make([]byte, len(v.plaintext))
			x.XORKeyStream(got, v.plaintext)
			if !reflect.DeepEqual(got, v.ciphertext) {
				t.Errorf("Cipher.XORKeyStream()\ngot:  %s\nwant: %s", hex.EncodeToString(got), hex.EncodeToString(v.ciphertext))
			}
		})
	}
}
