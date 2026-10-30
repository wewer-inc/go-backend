package store

import (
	"strings"
	"unicode/utf8"
)

// LikeEscape has to follow the LIKE or ILIKE of any pattern built by LikeContains or
// LikePrefix:
//
//	db.Where("email ILIKE ? "+store.LikeEscape, store.LikeContains(term))
//
// The clause states what Postgres assumes anyway, that a backslash is the escape
// character. The unit tests run on sqlite, which has none unless told, so without the
// clause one pattern would match differently in the two databases.
const LikeEscape = `ESCAPE '\'`

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// LikeContains wraps s in wildcards for a substring match, after neutralising the LIKE
// metacharacters inside it. User input containing % or _ then matches those literal
// characters, and a backslash at the end of s cannot consume the closing wildcard. Case is
// left alone, so lower s first when comparing against LOWER(col).
func LikeContains(s string) string {
	return "%" + likeEscaper.Replace(s) + "%"
}

// LikePrefix is LikeContains for a match anchored at the start of the column.
func LikePrefix(s string) string {
	return likeEscaper.Replace(s) + "%"
}

// ValidSearchText reports whether Postgres would accept s as a text parameter, which takes
// valid UTF-8 and no NUL byte. Anything else fails the statement, turning bad client input
// into a 500 when it should be a 400. Query strings bypass the NUL filter applied to
// request bodies, so search terms need this check of their own.
func ValidSearchText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
