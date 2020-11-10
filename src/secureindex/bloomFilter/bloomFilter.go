package bloomFilter

/* Implementation of a basic Bloom Filter structure enabling the building of Secure Indexes *
 * Source ref: crypto.stanford.edu/~eujin/papers/secureindex/secureindex.pdf                */

import (
	"encoding/binary" // Standard packages
	"math"
)

/* Declare custom type for a bit array used to construct Bloom Filter */
type BloomFilter struct {
	BitArray []bool
}

/* Build a Bloom Filter data structure, estimate the filter's optimal parameters *
 * m = (n * k) / ln(2), where n is the number of unique words in document        *
 * s = represents a recommended scaling factor allowing for document updates     */
func (filter *BloomFilter) Create(hashes int, keywords int, scaling float64) {

	// Determine optimal size parameter for the Bloom Filter
	m := (float64(keywords) * scaling * float64(hashes)) / math.Log(2)

	// Create the filter's bit array and pointer, zero initialised
	filter.BitArray = make([]bool, int(math.Round(m)))
}

/* Map a set of codewords to corresponding positions in Bloom Filter */
func findPositions(codewords [][]byte, filterSize int) []uint64 {

	indexPositions := make([]uint64, 0, 0)

	for codeword := range codewords {
		x, _ := binary.Uvarint(codewords[codeword])
		indexPositions = append(indexPositions, x%uint64(filterSize))
	}

	return indexPositions
}

/* Add a set of k codewords to a Bloom Filter */
func (filter *BloomFilter) Add(codewords [][]byte) {

	indexPositions := findPositions(codewords, len(filter.BitArray))

	for _, i := range indexPositions {
		filter.BitArray[i] = true
	}
}

/* Check if a set of k codewords is held in the Bloom Filter */
func (filter *BloomFilter) Search(codewords [][]byte) bool {

	exists := true // return boolean match

	indexPositions := findPositions(codewords, len(filter.BitArray))

	// Map set of codewords to corresponding positions in Bloom Filter
	for _, i := range indexPositions {
		if filter.BitArray[i] == false {
			exists = false
		}
	}
	return exists
}
