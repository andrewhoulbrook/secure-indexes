package main

/* Implementation of Secure Indexes in Go. This script extracts keywords and builds a secure index for a file.            *
 * Given a document file (txt, pdf et...), extract text and keywords and builds a secure index file for the document      *
 * Optionally encrypts the document using AES (GCM cipher mode), or user can simply encrypt their own document seperately *
 * Encrypted document and index can then be uploaded to a server or repository.                                           *
 * Source ref: crypto.stanford.edu/~eujin/papers/secureindex/secureindex.pdf                                              */

import (
	"encoding/csv" // Import std. packages
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"secureindex/bloomFilter" // Import custom packages
	"secureindex/cryptoUtils"
	"secureindex/textExtract"
)

const (
	S_F = 1.5  // Scaling factor to allow for document updates
	F_P = 0.01 // Probability of false positives found in Bloom Filter
)

/* Error handling */
func errorCheck(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, msg+"\n")
		os.Exit(1)
	}
}

/* Write data to a CSV file */
func writeToCSV(filepath string, data []string) error {

	// Create new file for writing out secure index
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create file stream
	w := csv.NewWriter(file)
	defer w.Flush()

	// Write data to file
	wErr := w.Write(data)
	if wErr != nil {
		return err
	}

	return nil
}

/* Write k hash keys to file */
func writeKeyFile(filepath string, hashKeys [][]byte) error {

	// Encode k hash keys from bytes to strings.
	var outputKeys []string
	for x, _ := range hashKeys {
		keyStr := hex.EncodeToString(hashKeys[x])
		outputKeys = append(outputKeys, keyStr)
	}

	err := writeToCSV(filepath+".sindex.private", outputKeys)
	if err != nil {
		return err
	}

	return nil
}

/* Read a series of k pre-saved hashkeys from a keyfile */
func readKeyfile(filepath string) ([][]byte, error) {

	// Store k private keys in array slice
	keys := make([][]byte, 0, 0)

	// Read k hash keys from CSV file
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}

	r := csv.NewReader(file)

	for {
		record, rErr := r.Read()
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			return nil, rErr
		}

		for r, _ := range record {
			key, hErr := hex.DecodeString(record[r])
			if hErr != nil {
				return nil, hErr
			}
			keys = append(keys, key)
		}
	}

	return keys, nil
}

/* Write the secure index to a CSV file */
func writeSecureIndexFile(filepath string, indexArray []bool) error {

	// Format bool array (secure index) for writing to file
	var outputArray []string
	for _, v := range indexArray {
		if v {
			outputArray = append(outputArray, "1")
		} else {
			outputArray = append(outputArray, "0")
		}
	}
	// Write secure index to CSV file
	err := writeToCSV(filepath+".sindex", outputArray)

	return err
}

/* Takes a directory path containing files to be indexed and encrypted.					 					   *
 * User chooses to encrypt files using this script and/or build a secure index for files 					   *
 * Outputs symmetric encryption keys (for file encryption) and k cryptographic hash keys (for secure indexing) */
func main() {

	// Get directory path as user input
	var dirpath string
	fmt.Printf("Enter path to directory for indexing: ")
	fmt.Scanf("%s\n", &dirpath)

	// Check if user wishes to encrypt files after indexing (or user will encrypt themselves)
	var fileEncrypt string
	fmt.Printf("Encrypt files after index build? [y/N]: ")
	fmt.Scanf("%s\n", &fileEncrypt)

	// Load in user-specified keyfile, else generate k random hash keys
	var keyFilepath string
	fmt.Printf("Enter path for private index keys [leave blank to generate new keys]: ")
	fmt.Scanf("%s\n", &keyFilepath)

	hashKeys := make([][]byte, 0, 0)

	// Read hash keys from file otherwise generate new set of k hash keys
	if len(keyFilepath) == 0 {
		hashKeys = cryptoUtils.GenerateHashKeys(F_P)

		// Write new hash keys to file
		fmt.Printf("Enter path to save new private index keys: ")
		fmt.Scanf("%s\n", &keyFilepath)
		_, fn := path.Split(dirpath)
		err := writeKeyFile(keyFilepath+"/"+fn, hashKeys)
		errorCheck("ERROR: unable to write hash keys to file.", err)
	} else {
		// Read hash keys from file
		var err error
		hashKeys, err = readKeyfile(keyFilepath)
		errorCheck("ERROR: unable to read hash keys from file.", err)
	}

	// Walk through the directory structure and search any secure indexes found
	files := make([]string, 0, 0)
	sErr := filepath.Walk(dirpath, func(path string, f os.FileInfo, err error) error {
		files = append(files, path)
		return nil
	})
	errorCheck("ERROR: unable to traverse directory.", sErr)

	// List all files in directory
	//files, err := ioutil.ReadDir(dirpath)
	//errorCheck("ERROR: unable to find directory.", err)

	fmt.Printf("\n Building index for files in %s\n", dirpath)
	fmt.Printf(" ----------------------------------\n\n")

	filetypes := []string{".txt", ".csv", ".rtf", ".pdf"} //".odt", ".docx"}

	// Loop over and index each file in directory
	for _, file := range files {

		indexFlag := false

		for _, ft := range filetypes {
			if strings.Contains(file, ft) {
				indexFlag = true
				break
			}
		}

		if indexFlag {
			fmt.Printf("  indexing %s\n", file)

			// Extract raw text for file, extract keywords from text
			text := textExtract.Text{file, "", make([]string, 0, 0)}
			text.ExtractText()
			text.ExtractKeywords()

			// Create a Bloom Filter structure
			filter := bloomFilter.BloomFilter{make([]bool, 0, 0)}
			filter.Create(len(text.Keywords), len(hashKeys), S_F)

			// Create a Secure Index structure
			sIndex := cryptoUtils.SecureIndex{make([][]byte, 0, 0), make([][]byte, 0, 0), &filter}

			var sep string

			// Split filepath and obain file name
			if strings.Contains(file, "\\") {
				sep = "\\"
			} else {
				sep = "/"
			}
			splitName := strings.Split(file, sep)
			fname := splitName[len(splitName)-1]

			// Create trapdoors and codewords for each keyword, add to the Secure Index
			for _, keyword := range text.Keywords {
				sIndex.Build(fname, keyword, hashKeys)
				sIndex.Index.Add(sIndex.Codewords)
			}

			// Perform index blinding
			sIndex.Blind(len(text.Keywords), len(text.RawText), len(hashKeys))

			// Write secure index to file
			err := writeSecureIndexFile(file, sIndex.Index.BitArray)
			errorCheck("ERROR: unable to write secure index to file.", err)

			// Encrypt document file (if user chose to)
			if fileEncrypt == "Y" || fileEncrypt == "y" {
                keyFiledir, _ := path.Split(keyFilepath)
				cryptoUtils.Encrypt(file, keyFiledir+fname)
			}
		}
	}

	fmt.Printf("\n Secure index builds complete.\n\n")
}
