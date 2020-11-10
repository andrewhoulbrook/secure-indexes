package cryptoUtils

/* Package of functions performing symmetric file encryption (AES), generating   *
 * crytographically secure arrays of random bytes and HMAC SHA-256 cryptographic *
 * hash functions, all of which enable the building of secure indexes.           *
 * Source ref: crypto.stanford.edu/~eujin/papers/secureindex/secureindex.pdf     */

import (
	"crypto/aes" // Standard packages
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"

	"secureindex/bloomFilter" // Bloom Filter package
)

/* Error handling */
func errorCheck(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, msg+"\n")
		os.Exit(1)
	}
}

/* Declare custom structure for components of secure indexes */
type SecureIndex struct {
	Trapdoors [][]byte
	Codewords [][]byte
	Index     *bloomFilter.BloomFilter
}

/* Symmetric file encryption using AES */
func Encrypt(filepath string, keypath string) {

	// Read user's document
	plaintext, err := ioutil.ReadFile(filepath)
	errorCheck("ERROR: unable to read file for encryption.", err)

	// Generate 32 byte random key
	key, err := GenerateRandomBytes(32)
	errorCheck("ERROR: unable to generate random bytes.", err)

	// Generate new AES cipher using key
	c, err := aes.NewCipher(key)
	errorCheck("ERROR: unable create new AES cipher.", err)

	// Use Galois-Counter Mode (GCM) cipher block
	gcm, err := cipher.NewGCM(c)
	errorCheck("ERROR: unable to generate AES-GCM block cipher.", err)

	// Creates a new byte array the size of the nonce
	nonce, err := GenerateRandomBytes(gcm.NonceSize())
	errorCheck("ERROR: unable to generate nounce vales.", err)

	// Populate nonce with cryptographically secure random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println("ERROR: unable to populate nounce value.", err)
	}

	// Write cipertext to file
	err = ioutil.WriteFile(filepath+".encrypted.data", gcm.Seal(nonce, nonce, plaintext, nil), 0777)
	errorCheck("ERROR: unable to write encrypted file.", err)

	// Write key to file
	err = ioutil.WriteFile(keypath+".encrypted.private", key, 0700)
	errorCheck("ERROR: unable to write private key.", err)
}

/* Function to generate cyptographically secure array of random bytes */
func GenerateRandomBytes(n int) ([]byte, error) {
	byteArray := make([]byte, n)
	_, err := rand.Read(byteArray)

	if err != nil {
		return nil, err
	}

	return byteArray, nil
}

/* Create k 128-bit randomly generated keys */
func GenerateHashKeys(fp float64) [][]byte {

	// Determine optimal number of k hashes for a bloom fitler
	// k = -log2(p), where p is the probability of false positives
	kHashes := math.Round(math.Abs(-(math.Log2(fp))))

	// Create k 128-bit randomly generated keys
	keys := make([][]byte, 0, 0)
	for k := 0; k <= int(kHashes); k++ {
		key, err := GenerateRandomBytes(16)
		errorCheck("ERROR: unable to generate random bytes.", err)
		keys = append(keys, key)
	}

	return keys
}

/* Create and return HMAC for a given trapdoor or codeword */
func createHMAC(m string, k []byte) []byte {

	h := hmac.New(sha256.New, k)
	h.Write([]byte(m))

	return h.Sum(nil)
}

/* Create trapdoors for a given keyword and k hash keys */
func BuildTrapdoors(keyword string, keys [][]byte) [][]byte {

	trapdoors := make([][]byte, 0, 0)
	for _, key := range keys {
		trapdoor := createHMAC(keyword, key)
		trapdoors = append(trapdoors, trapdoor)
	}

	return trapdoors
}

/* Create trapdoors for a given keyword and k hash keys */
func BuildCodewords(filename string, trapdoors [][]byte) [][]byte {

	codewords := make([][]byte, 0, 0)
	for _, t := range trapdoors {
		codeword := createHMAC(filename, t)
		codewords = append(codewords, codeword)
	}

	return codewords
}

/* Create trapdoors and codewords for a given keyword, k hash keys and filename */
func (si *SecureIndex) Build(filename string, keyword string, keys [][]byte) {

	si.Trapdoors = BuildTrapdoors(keyword, keys)
	si.Codewords = BuildCodewords(filename, si.Trapdoors)
}

/* Perform blinding of index for an IND-CKA secure index */
func (si *SecureIndex) Blind(numKeywords int, docSize int, numKeys int) {

	// Calculate blinding factor
	b_f := (docSize - numKeywords) * numKeys

	blinding := make([][]byte, 0, 0)

	// Generate slice array of random bytes
	randomBytes, err := GenerateRandomBytes(b_f)
	errorCheck("ERROR: unable to generate random bytes.", err)

	// Put random entries into the Bloom Filter
	blinding = append(blinding, randomBytes)
	si.Index.Add(blinding)
}
