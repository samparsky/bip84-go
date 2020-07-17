package main

import (
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"encoding/hex"
)

type Purpose = uint32

const (
	PurposeBIP84 Purpose = 0x80000054 // 84' BIP84
	CoinTypeBTC uint32 = 0x80000000
	Apostrophe uint32 = 0x80000000 // 0'
)

var (
	// Bip84PublicWalletVersion is the version flag for BIP84 serialized private keys
	Bip84PublicWalletVersion, _ = hex.DecodeString("04b24746") 
	// Bip84PrivateWalletVersion is the version flag for BIP84 serialized private keys
	Bip84PrivateWalletVersion, _ = hex.DecodeString("04b2430c")
)

func generateMnemonic() string {
	// mnemonic 
	// 128 bits for 12 words
	// 256 bits for 24 words
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		log.Fatalf("%v", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	return mnemonic
}

func main() {

	// generate mnemonic 
	mnemonic := generateMnemonic()
	fmt.Println("---- Generated Mnemonic -------")
	fmt.Println(mnemonic)
	fmt.Println()

	// convert mnemonic to seed
	// to be used as entropy to generate private key
	seed := bip39.NewSeed(mnemonic, "")
	// create a master Key from mnemonic seed
	masterPrivateKey, err := bip32.NewMasterKey(seed)
	masterPrivateKey.Version = Bip84PrivateWalletVersion
	masterPublicKey := masterPrivateKey.PublicKey()
	masterPublicKey.Version = Bip84PublicWalletVersion

	fmt.Println("---- Generated Master Key -------")
	fmt.Println("Extended Private Key - ", masterPrivateKey.B58Serialize())
	fmt.Println("Extended Public Key - ", masterPublicKey.B58Serialize())
	fmt.Println()

	// Generate a BIP84 path key derivation	
	purposeChildKey, err := masterPrivateKey.NewChildKey(PurposeBIP84)
	coinTypeChildKey, err := purposeChildKey.NewChildKey(CoinTypeBTC)
	// generate first child account of m/84'/0'/0'
	childAccount, err := coinTypeChildKey.NewChildKey(0 + Apostrophe)
	childAccount.Version = Bip84PrivateWalletVersion
	childAccountPublicKey := childAccount.PublicKey()
	childAccountPublicKey.Version = Bip84PublicWalletVersion

	fmt.Println("---- Generated Child Account Key -------")
	fmt.Println("Private Key", childAccount.B58Serialize())
	fmt.Println("Public Key", childAccountPublicKey.B58Serialize())
	fmt.Println()

	// Generate Bech32 Address from Child Account Key
	prvKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), childAccount.Key)
	btcwif, err := btcutil.NewWIF(prvKey, &chaincfg.MainNetParams, true)
	serializedPubKey := btcwif.SerializePubKey()
	witnessProg := btcutil.Hash160(serializedPubKey)
	addressWitnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Printf("%v", err)
	}
	segwitBech32 := addressWitnessPubKeyHash.EncodeAddress()
	fmt.Println("---- Generated Child Account Bech32 Address -------")
	fmt.Println(segwitBech32)
	fmt.Println()

}