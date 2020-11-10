package main

/* Implementation of Secure Indexes in Go. This script runs the keyword search function on the server-side             *
 * This script used to search a series of secure indexes using a given trapdoor (generated client-side) for a keyword  *
 * Source ref: crypto.stanford.edu/~eujin/papers/secureindex/secureindex.pdf                                           */

import (
	"encoding/csv"
	"encoding/json"
    "fmt"
    "net"
	"io"
	"os"
	"strings"
    "crypto/tls"
    "path/filepath"
	"secureindex/bloomFilter"   // Bloom Filter package
	"secureindex/cryptoUtils"   // Cryptographic functions package
)

/* Error handling */
func errorCheck(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, msg+"\n")
		os.Exit(1)
	}
}

/* Read a secure index file */
func ReadSecureIndexFile(filepath string) ([]bool, error) {

	// Creat bool slice for the secure index
	si := make([]bool, 0, 0)

	// Read the secure index from file stored in binary (CSV) format
	file, _ := os.Open(filepath)
	r := csv.NewReader(file)

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Format binary index data into bool array
		for r, _ := range record {
			if record[r] != "0" {
				si = append(si, true)
			} else {
				si = append(si, false)
			}
		}
	}

    // Return the secure index in the form of a bool slice
    return si, nil
}

/* Function to handle the processing of keyword trapdoors received from tcp client *
 * */
func handleConnection(conn net.Conn) {
    defer conn.Close()
    
    for {
        // Read trapdoors sent from TCP client as serialised JSON object
	    trapdoors := make([][]byte, 0, 0)
        err := json.NewDecoder(conn).Decode(&trapdoors)
        errorCheck("ERROR: unable to read data sent from TCP client.", err)
     
        // Trigger closing the connection if empty trapdoor received
        if trapdoors == nil {
            return
        }

        // Hard coded root test directory for storing secure index-document pairs
        dirpath := "test/"

	    // Walk through the directory structure and search any secure indexes
	    files := make([]string, 0, 0)
	    sErr := filepath.Walk(dirpath, func(path string, f os.FileInfo, err error) error {
		    files = append(files, path)
		    return nil
    	})
	    errorCheck("ERROR: unable to traverse directory.", sErr)

        //Store matches (document filenames) from keyword search
	    results := make([]string, 0, 0)
        io.WriteString(conn, "\n Checked the following indexes:\n -------------------------------\n")

	    for _, file := range files {
            // Secure index files identified using the ".sindex" file extension
		    if strings.HasSuffix(file, ".sindex") {
			    io.WriteString(conn, fmt.Sprintf(" -%s\n", file))

			    // Create a Bloom Filter structure
			    si, err := ReadSecureIndexFile(file)
			    errorCheck("ERROR: unable to read secure index file.", err)
			    filter := bloomFilter.BloomFilter{si}

			    // Split filepath and obtain file name
			    var sep string
			    if strings.Contains(file, "\\") {
				    sep = "\\"
			    } else {
				    sep = "/"
			    }
			    splitName := strings.Split(file, sep)
			    fname := splitName[len(splitName)-1]

			    // Create codewords from file name and trapdoors
			    codewords := cryptoUtils.BuildCodewords(strings.Replace(fname, ".sindex", "", -1), trapdoors)

		        // Find matching codewords in the secure index, save file name in results if match found
			    match := filter.Search(codewords)
			    if match {
				    results = append(results, fmt.Sprintf(" -%s\n", strings.Replace(fname, ".sindex", "", -1)))
                } 
		    }
	    }

        io.WriteString(conn, "\n Keyword matches found:\n ----------------------\n")

	    // Send search results to TCP client
	    if len(results) > 0 {
		    for _, res := range results {
                io.WriteString(conn, res)
            }
	    } else {
            io.WriteString(conn, " -No matches found.\n")
        }
        
        io.WriteString(conn, "\n>")
    }
}

/* Main */
func main() {

    // Get user-specified port number
    arguments := os.Args
    if len(arguments) == 1 {
        fmt.Println("ERROR: provide port number for server to listen on.")
        return
    }

    // Load X509 certificate keypair for establishing TLS connections
    cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        fmt.Println("ERROR", err)
        return
    }

    // Set secure configuration settings for TLS server
    config := &tls.Config{
        Certificates: []tls.Certificate{cer},
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

    // Create listener on specified port
    port := ":" + arguments[1]
    listener, err := tls.Listen("tcp", port, config)
    errorCheck("ERROR: unable to listen on given port.\n", err)
    defer listener.Close()

    fmt.Printf("Listening on port%s...\n", port)

    for {
        // Accept incoming connections from TCP clients
        connection, err := listener.Accept()
        errorCheck("ERROR: unable to establish TLS connection with client.", err)

        fmt.Printf("TLS connection established with: %s\n", connection.RemoteAddr())

        // Concurrently handle incoming TCP connections
        go handleConnection(connection)
    }
}
