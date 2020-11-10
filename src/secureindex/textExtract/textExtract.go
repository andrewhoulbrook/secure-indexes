package textExtract

/* Light NLP functions to perform text and keyword extractions enabling the building of Secure Indexes *
 * Source ref: crypto.stanford.edu/~eujin/papers/secureindex/secureindex.pdf                           */

import (
	"fmt" // Standard packages
	"os"
	"regexp"
	"strings"

	"github.com/lu4p/cat"      // Cat package for raw text extraction
	"gopkg.in/jdkato/prose.v2" // Prose package for NLP and keyword extraction
)

// Regexp string of English language stopwords (source: NLTK)
const STOP_WORDS = "\\b(ourselves|hers|between|yourself|but|again|there|about|once|during|out|very|having|with|they|own|an|be|some|for|do|its|yours|such|into|of|most|itself|other|off|is|s|am|or|who|as|from|him|each|the|themselves|until|below|are|we|these|your|his|through|don|nor|me|were|her|more|himself|this|down|should|our|their|while|above|both|up|to|ours|had|she|all|no|when|at|any|before|them|same|and|been|have|in|will|on|does|yourselves|then|that|because|what|over|why|so|can|did|not|now|under|he|you|herself|has|just|where|too|only|myself|which|those|i|after|few|whom|t|being|if|theirs|my|against|a|by|doing|it|how|further|was|here|than)\\b\\s"

/* Error handling */
func errorCheck(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, msg+"\n")
		os.Exit(1)
	}
}

/* Define basic structure for text 'object' associated with a file */
type Text struct {
	Filepath string
	RawText  string
	Keywords []string
}

/* Extract text from various popular document formats */
func (t *Text) ExtractText() {

	// Extract text using CAT package (txt, csv, pdf, rtf, odt, docx etc...)
	content, err := cat.Cat(t.Filepath)
	if err != nil {
		fmt.Println("INFO: unable to read ", t.Filepath, " (skipping file)")
	}

	if len(content) == 0 {
		fmt.Println("INFO: unable to find text content in ", t.Filepath, " (skipping file)")
	} else {
		t.RawText = strings.ToLower(content)
	}
}

/* Function to extract keywords from a document using light NLP */
func (t *Text) ExtractKeywords() {

	// Remove stopwords
	cleanText := removeStopwords(t)

	// Create a Prose document object ready for tokenising
	doc, err := prose.NewDocument(cleanText)
	errorCheck("ERROR: unable to initialise a Prose document object.", err)

	// Create slice to hold extracted keywords
	tokens := make([]string, 0, 0)

	// Tokenise the Prose document object
	for _, tok := range doc.Tokens() {

		// Extract nouns from POS tags to use as keywords, convert to lowercase
		if strings.Contains(tok.Tag, "NN") {
			tokens = append(tokens, strings.ToLower(tok.Text))
		}
	}

	// Dedupe list of keywords
	t.Keywords = removeDuplicates(tokens)
}

/* Remove English language stopwords */
func removeStopwords(t *Text) string {

	// Build regex for matching stopwords
	reg, err := regexp.Compile(STOP_WORDS)
	errorCheck("ERROR: unable to remove stopwords.", err)

	// Remove stopwords from the text, return cleaned text
	return reg.ReplaceAllString(t.RawText, "")
}

/* Deduplicate keyword extracts from extracted text */
func removeDuplicates(keywords []string) []string {

	// Use map to record duplicates
	encountered := make(map[string]bool)
	result := make([]string, 0, 0)

	for v := range keywords {
		if encountered[keywords[v]] == true {
			// Do not add duplicate.
		} else {
			// Record element as an encountered element.
			encountered[keywords[v]] = true
			// Append to result slice
			result = append(result, keywords[v])
		}
	}
	// Return the deduped slice array
	return result
}
