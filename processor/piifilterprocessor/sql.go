package piifilterprocessor

import (
	"container/list"
	"strings"
	"unicode"

	"github.com/antlr/antlr4/runtime/Go/antlr"
	"go.uber.org/zap"
)

type sqlFilter struct {
	pfp          *piifilterprocessor
	logger       *zap.Logger
	filteredText string
	categories   *list.List
}

const SqlFilterDlpTag = "sql_filter"

func NewSqlFilter(pfp *piifilterprocessor, logger *zap.Logger) *sqlFilter {
	return &sqlFilter{
		pfp:        pfp,
		logger:     logger,
		categories: list.New(),
	}
}

func (f *sqlFilter) Filter(input string, key string, filterData *FilterData) (bool, bool) {
	is := NewCaseChangingStream(antlr.NewInputStream(input), true)
	lexer := NewMySqlLexer(is)

	redactedLiteral := false
	var str strings.Builder
	for token := lexer.NextToken(); token.GetTokenType() != antlr.TokenEOF; {
		if token.GetTokenType() == MySqlLexerSTRING_LITERAL {
			text := token.GetText()
			openQuote := ""
			closeQuote := ""
			lenText := len(text)
			if len(text) > 0 && (text[0] == '"' || text[0] == '\'') {
				openQuote = string(text[0])
				text = text[1:]
				lenText--
			}
			if lenText > 0 && (text[lenText-1] == '"' || text[lenText-1] == '\'') {
				closeQuote = string(text[lenText-1])
				text = text[:lenText-1]
			}
			_, redacted := f.pfp.redactString(text)
			token.SetText(openQuote + redacted + closeQuote)
			redactedLiteral = true
		}
		str.WriteString(token.GetText())
		token = lexer.NextToken()
	}
	f.filteredText = str.String()

	if redactedLiteral {
		f.pfp.addDlpElementToList(filterData.DlpElements, key, "", SqlFilterDlpTag)
		f.categories.PushBack("")
	}

	return false, f.categories.Len() > 0
}

func (f *sqlFilter) FilteredText() string {
	return f.filteredText
}

type CaseChangingStream struct {
	antlr.CharStream
	upper bool
}

// NewCaseChangingStream returns a new CaseChangingStream that forces
// all tokens read from the underlying stream to be either upper case
// or lower case based on the upper argument.
func NewCaseChangingStream(in antlr.CharStream, upper bool) *CaseChangingStream {
	return &CaseChangingStream{
		in, upper,
	}
}

// LA gets the value of the symbol at offset from the current position
// from the underlying CharStream and converts it to either upper case
// or lower case.
func (is *CaseChangingStream) LA(offset int) int {
	in := is.CharStream.LA(offset)
	if in < 0 {
		// Such as antlr.TokenEOF which is -1
		return in
	}
	if is.upper {
		return int(unicode.ToUpper(rune(in)))
	}
	return int(unicode.ToLower(rune(in)))
}
