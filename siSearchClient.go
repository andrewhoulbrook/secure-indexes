package main

/* Implementation of Secure Indexes in Go. This script runs the keyword search function on the client-side                      *
 * This script used to build a trapdoor for a given keyword which can be securely sent to complete a keyword search server-side *
 * Source ref: crypto.stanford.edu/~eujin/papers/secureindex/secureindex.pdf                                                    */

import (
	"encoding/csv"
	"encoding/hex"	
    "encoding/json"
    "fmt"
	"io"
	"os"
    "bufio"
    "strings"
    "crypto/tls"
    "secureindex/cryptoUtils" // Cryptographic functions package
)

/* Error handling */
func errorCheck(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, msg+"\n")
		os.Exit(1)
	}
}

/* Function to read k private keys from key file *
 * Return k private keys as 2d slice of bytes    */
func readKeys(keyFile string) [][]byte {
	// Store k private keys in array slice
	hashKeys := make([][]byte, 0, 0)

	// Read k hash keys from CSV file
	file, _ := os.Open(keyFile)
	r := csv.NewReader(file)
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		 errorCheck("ERROR: unable to read from keyfile.", err)

        // Read keys from file and decode from hex
		for r, _ := range record {
			key, err := hex.DecodeString(record[r])
		    errorCheck("ERROR: unable to read from keyfile.", err)
			hashKeys = append(hashKeys, key)
		}
	}
    return hashKeys
}

/* Takes a single keyword and file containing k cryptographic hash keys *
 * to build a trapdoor for seaching a secure index. Outputs a trapdoor  */
func main() {

    arguments := os.Args
    if len(arguments) == 1 {
        fmt.Println("ERROR: provide host:port for client to connect to.")
        return
    }

    // Set secure configuration settings for establishing TLS connections with server
    config := &tls.Config{
        InsecureSkipVerify: true,
        MinVersion: tls.VersionTLS12,
        CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
        },
    }

    // Open client connection to tcp server
    server := arguments[1]
    connection, err := tls.Dial("tcp", server, config)
    errorCheck("ERROR: unable to establish connection.", err)
    //defer connection.Close()

    // Instantiate new JSON encoder and String Reader objects
    jsonEncoder := json.NewEncoder(connection)
    stringReader := bufio.NewReader(connection)

    fmt.Println("Search secure indexes on file server. Key 'x' to close connection.")
    fmt.Printf(">")

    for {
        // Get a keyword as user input
    	var keyword string
    	fmt.Printf("Enter a single keyword to search: ")
	    fmt.Scanf("%s\n", &keyword)
        keyword = strings.ToLower(strings.TrimSpace(keyword))

        // Handle closing of tcp connection if user enters the trigger
        if keyword == "x" {
            // Send empty trapdoor trigger closing connection on server-side
            err := jsonEncoder.Encode(nil)
            //err := jsonEncoder.Encode(make([][]byte, 0, 0))
            errorCheck("ERROR: unable to create trapdoors to send to server.", err)
            
            // Close client connection to tcp server
            connection.Close()
            return
        }

        // Get filepath containing k hash keys as user input
	    var keyFilepath string
	    fmt.Printf(">Enter local filepath for private search keys: ")
	    fmt.Scanf("%s\n", &keyFilepath)

        // Read k private keys from user's keyfile
        hashKeys := readKeys(keyFilepath)

	    // Create search trapdoor based on user's keyword
	    trapdoors := cryptoUtils.BuildTrapdoors(keyword, hashKeys)

        // Send trapdoor to the tcp server for searching against secure indexes
        err := jsonEncoder.Encode(trapdoors)
        errorCheck("ERROR: unable to create trapdoors to send to server.", err)

        // Get search matches by reading repsonse from tcp server
        response, _ := stringReader.ReadString('>')
        fmt.Printf(response)
    }
}
