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

func Test_keyStream(t *testing.T) {
	var keyStreamTestVectors = []struct {
		name      string
		key       [32]byte
		nonce     [12]byte
		counter   uint32
		keyStream func() [64]byte
	}{
		{
			name:    "RFC8439 Appendix A.1 (Key Stream Test Vector) #1",
			key:     [32]byte(mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000000")),
			nonce:   [12]byte(mustDecodeHex("000000000000000000000000")),
			counter: 0x00000000,
			keyStream: func() [64]byte {
				b, err := hex.DecodeString("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")
				if err != nil {
					panic(err)
				}
				return [64]byte(b[:64])
			},
		},
		{
			name:    "RFC8439 Appendix A.1 (Key Stream Test Vector) #2",
			key:     [32]byte(mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000000")),
			nonce:   [12]byte(mustDecodeHex("000000000000000000000000")),
			counter: 0x00000001,
			keyStream: func() [64]byte {
				b, err := hex.DecodeString("9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f")
				if err != nil {
					panic(err)
				}
				return [64]byte(b[:64])
			},
		},
		{
			name:    "RFC8439 Appendix A.1 (Key Stream Test Vector) #3",
			key:     [32]byte(mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000001")),
			nonce:   [12]byte(mustDecodeHex("000000000000000000000000")),
			counter: 0x00000001,
			keyStream: func() [64]byte {
				b, err := hex.DecodeString("3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0")
				if err != nil {
					panic(err)
				}
				return [64]byte(b[:64])
			},
		},
		{
			name:    "RFC8439 Appendix A.1 (Key Stream Test Vector) #4",
			key:     [32]byte(mustDecodeHex("00ff000000000000000000000000000000000000000000000000000000000000")),
			nonce:   [12]byte(mustDecodeHex("000000000000000000000000")),
			counter: 0x00000002,
			keyStream: func() [64]byte {
				b, err := hex.DecodeString("72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096")
				if err != nil {
					panic(err)
				}
				return [64]byte(b[:64])
			},
		},
		{
			name:    "RFC8439 Appendix A.1 (Key Stream Test Vector) #5",
			key:     [32]byte(mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000000")),
			nonce:   [12]byte(mustDecodeHex("000000000000000000000002")),
			counter: 0x00000000,
			keyStream: func() [64]byte {
				b, err := hex.DecodeString("c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d")
				if err != nil {
					panic(err)
				}
				return [64]byte(b[:64])
			},
		},
	}
	for _, v := range keyStreamTestVectors {
		t.Run(v.name, func(t *testing.T) {
			x := NewCipher(v.key, v.counter, v.nonce)
			want := v.keyStream()
			got := x.(*state).keyStream()
			if !reflect.DeepEqual(got, want) {
				t.Errorf("state.keyStream()\ngot:  %s\nwant: %s", hex.EncodeToString(got[:64]), hex.EncodeToString(want[:64]))
			}
		})
	}
}

//func Test_state_XORKeyStream(t *testing.T) {
//	type args struct {
//		dst []byte
//		src []byte
//	}
//	tests := []struct {
//		name string
//		x    state
//		args args
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			tt.x.XORKeyStream(tt.args.dst, tt.args.src)
//		})
//	}
//}
