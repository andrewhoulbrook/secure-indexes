# Secure Indexes

A rough attempt to implement the secure index technique outlined in Eu-Jin Goh's Secure Indexes paper. 

## What is a Secure Index?

*"A secure index is a data structure that allows a querier with a “trapdoor” for a word x to test in O(1) time only if the index contains x; The index reveals no information about its contents without valid trapdoors, and trapdoors can only be  generated with a secret key. Secure indexes allow a querier to check if a document contains a keyword without having to decrypt the entire document, a property that is especially useful for large documents and large document collections."*

<p align="center">
    <img src="/doc/doc-index-pairs.png" alt="secure index">
</p>

A secure index, as formulated in the paper, is also shown to offer protection again against adaptive chosen keyword attack (IND-CKA). The index is built using pseudo-random functions and a Bloom Filter as a per-document index. Encrypted documents can be stored in document index pairs.  

## Secure Index Building

Key requirements are Bloom Filters, a pseudo-random function (applied twice) and a pseudo-random generator. The index can be built using the following stages after key words have been extracted from a given document ```D_id```:

* Key generation: a pseudo-random function is used to generate a master key, ```K = (k1, ... , kr)```

For each unique key word ```W```:

* Create trapdoor: using the master key, create trapdoor for key word ```W```; ```X = f(k_1, w_1), ... , f(k_i, w_i)```
* Create codeword: using an identifier for the document, create codeword for trapdoor; ```Y = f(D_id, X_1), ... , (D_id, X_i))```
* Insert codeword into Bloom Filter which acts as the secure index for document ```D_id```
* Perform index blinding with random tokens

<p align="center">
    <img src="/doc/index-build.png" alt="secure index building">
</p>

Trapdoor can not be simply inserted into the index as this leaves the index vulnerable to correlation attacks. Codewords representing a key word are different for each document in the set. Together with **blinding** this helps **secure indexes** become IND-CKA secure.

## Secure Index Searching

To search a secure index a trapdoor must first be created for a given key word using the master key. The trapdoor can then be passed to, for example a server holding document index pairs, to complete the search. The server will need to compute a codeword, using each document's identifier and the given trapdoor, and check for a positive match for the presence of the codeword in the Bloom Filter index. For any matches found, the server returns the document's identifier indicating the presence of a given key word in that document.   

<p align="center">
    <img src="/doc/index-search.png" alt="secure index searching">
</p>

## Bloom Filters

Eu-Jin Goh's secure indexes utilise an underlying data structure known as a [Bloom Filter](https://en.wikipedia.org/wiki/Bloom_filter). A Bloom Filter is a probabilistic data structure built around hash functions and represented as a bit array. It can be used to test whether an element is a member of a set. The ability to query a Bloom Filter in *O(1)* time is an attractive feature. Employed as a index, this means a Bloom Filter can guarantee no false negative key word matches but false positives key words remain possible.  

False positives are inherent in using Bloom Filters but minimised by selecting optimal filter parameters: ```m = (n * k) / ln(2)```, where ```m``` is the filter's size, ```n``` is the number of unique words in document and ```k``` the number of hash functions.  

However, further false positives are added to the filter as a result of index blinding.  

Note: there are various Go implementations of Bloom Filters using non-cryptographic hash functions such as Murmur and FNV hashing, e.g. [```package bloom```](https://godoc.org/github.com/willf/bloom).

## Implementing Secure Indexes with HMAC-SHA-256

The paper uses HMAC as the pseudo-random function used to generate trapdoors and codewords. I've implemented the algorithm using HMAC-SHA-256 and Go's built-in ```crypto/hmac``` and ```crypto/sha256``` packages as well as ```crypto/rand``` to generate cryptographically random keys.

A ```secureIndex``` ```struct``` data structure is defined containing two-dimensional byte slices, holding trapdoors and codewords as they are generated, and a ```bloomFilter``` object.  

```
type SecureIndex struct {
	Trapdoors [][]byte
	Codewords [][]byte
	Index *bloomFilter.BloomFilter
}
```

A ```bloomFilter``` is implemented as a ```struct``` containing an one-dimensional boolean slice. 

```
type BloomFilter struct {
	BitArray []bool
}
```

A secure index is implemented in the code by first declaring and initialising an empty (zero'd) ```bloomFilter``` and calling ```Create()``` with parameters to optimise the filter's size. A ```secureIndex``` can be created using the ```bloomFilter``` object and once trapdoors and codewords have been generated from a given set of document keywords.

```
// Create a Bloom Filter structure
filter := bloomFilter.BloomFilter{make([]bool, 0)}
filter.Create(len(text.Keywords), len(hashKeys), Scaling_Factor)
	
// Create a Secure Index structure
sIndex := cryptoUtils.SecureIndex{trapdoors, codewords, &filter}
```

## Using the Code

The following non-standard packages are required:

* "github.com/lu4p/cat" - used to perform text extraction from txt, csv, pdf and other document formats
* "gopkg.in/jdkato/prose.v2" - used to perform light NLP tasks and assist with keyword extraction

These packages can be installed using ```go-get``` as follows:

```
go get -v github.com/lup4p/cat
go get -v gopkg.in/jdkato/prose/v2
```

Place the following files into your ```go/src``` directory:

* ```textExtract.go``` - functions to handle text extraction, keyword extract and building keyword lists
* ```bloomFilter.go``` - functions implementing Bloom Filters. Building and searching Bloom Filters
* ```cryptoUtils.go``` - functions to build cryptographic hashes (HMAC-SHA-2126), using ```crypto/rand```, and optionally encrypt a user's file after indexing using AES (GCM mode), if the user is not separately encrypting the file themselves.   

The above are imported as packages into the ```siBuild.go```, ```siSearchClient.go``` and ```siSearchServer.go``` programs which can then be compiled. 

# Running the Code

Run ```siBuildIndex``` on a collection of documents. The index build will recurse through all sub-directories within a given root directory looking for documents (.pdf, .rtf, .csv, .txt) to index and optionally encrypt. The user can also encrypt their documents independently of ```siIndexBuild```. A ```.sindex``` file will be created for each document indexed. 

If ```siBuildIndex``` is also used to encrypt documents after indexing, it lazily dumps the keys into the same folder as the user's index keys.  

Secure indexes can be built on the client side. Encrypted document/secure index pairs can then be uploaded to the server. 

In the example below i've run the index building on the server for testing and convenience:

<p align="center">
    <img src="/doc/index-build-example.png" alt="secure index building example">
</p>

Run ```siSearchServer``` to listen for TLS connections from ```siSearchClient```. The search client will take a user keyword (single keyword) and create a trapdoor to pass to the server. The server will return a rudimentary response, a list of filenames where keyword match was found in file's Secure Index.          

The following example is search for the keyword "alice" in a test folder of documents. 

<p align="center">
    <img src="/doc/search-example-alice.png" alt="alice search example">
</p>

The server returns four results, including (thankfully) Alice in Wonderland. Bearing in mind the drawback of inherent false positives, the keyword matches in this instance appear to stand up: 

<p align="center">
    <img src="/doc/grep-alice-test.png" alt="alice search check">
</p>

**Note:** the ```alice_in_wonderland.txt``` is only the first chapter (I miss-labelled it), whereas ```alice_in_wonderland.pdf``` is the full text. Hence the grep results.  

## Examples

A few other quick examples using some relatively unique keywords and no obvious false positives:

<p align="center">
    <img src="/doc/search-example-kurtz.png" alt="kurtz search example">
</p>

<p align="center">
    <img src="/doc/grep-alice-moriarty.png" alt="moriarty search check">
</p>

## Built with

* [Go](https://golang.org/)
* [Go, CAT Package](https://github.com/lu4p/cat)
* [Go, Prose.v2 Package](https://gopkg.in/jdkato/prose.v2)

**Why Go?** Why not. I'm new to Go. A chance to experiment and learn some of the fundamentals! 

## Key References 

* [Eu-Jin Goh, Secure Indexes (2004)](http://crypto.stanford.edu/~eujin/papers/secureindex/secureindex.pdf)
* [Brent J. Waters et. al., Encrypted Searchable Audit Logs (2004)](http://crypto.stanford.edu/~bwaters/publications/papers/audit_log.pdf)

## Authors

Initial work contributed by Andrew Houlbrook - [andrewhoulbrook](https://github.com/andrewhoulbrook)