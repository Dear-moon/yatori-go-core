package mooc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const siteURL = "https://www.icourse163.org/"

type MOOCUser struct {
	ID       string
	Nickname string
}

var identityAssignment = regexp.MustCompile(`(?:^|[;\r\n])\s*(?:window\.)?webUser\s*=\s*`)
var identityField = regexp.MustCompile(`^\s*(?:"(id|nickName|loginId)"|'(id|nickName|loginId)'|(id|nickName|loginId))\s*:\s*([\s\S]*)$`)

func (c *MOOCClient) unauthenticated(operation string) error {
	c.user = nil
	c.lastVerifiedAt = time.Time{}
	kind := ErrAuthenticationFailed
	if c.verifiedOnce {
		kind = ErrSessionExpired
	}
	return &RequestError{Operation: operation, Kind: kind}
}

func (c *MOOCClient) CurrentUser(ctx context.Context) (*MOOCUser, error) {
	var user *MOOCUser
	err := c.run(ctx, func(ctx context.Context) error { var err error; user, err = c.currentUser(ctx); return err })
	return user, err
}
func (c *MOOCClient) currentUser(ctx context.Context) (*MOOCUser, error) {
	c.user = nil
	c.lastVerifiedAt = time.Time{}
	body, err := c.request(ctx, "profile", http.MethodGet, siteURL, nil, false)
	if err != nil {
		return nil, err
	}
	user, found, err := parseIdentity(body)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, c.unauthenticated("profile")
	}
	c.user = user
	c.lastVerifiedAt = time.Now()
	c.verifiedOnce = true
	copy := *user
	return &copy, nil
}

// Parse only the embedded data literal; remote JavaScript must never execute.
func parseIdentity(body []byte) (*MOOCUser, bool, error) {
	invalid := func() (*MOOCUser, bool, error) {
		return nil, false, &RequestError{Operation: "profile schema", Kind: ErrUnexpectedResponse}
	}
	z := html.NewTokenizer(strings.NewReader(string(body)))
	inScript, siteMarker := false, false
	loginMarker := strings.Contains(string(body), "/member/login.htm")
	var user *MOOCUser
	assignments := 0
	for {
		switch z.Next() {
		case html.ErrorToken:
			if z.Err() != io.EOF {
				return invalid()
			}
			if user != nil {
				return user, true, nil
			}
			if siteMarker && loginMarker {
				return nil, false, nil
			}
			return invalid()
		case html.StartTagToken:
			token := z.Token()
			inScript = token.Data == "script"
			if inScript {
				for _, a := range token.Attr {
					if a.Key == "src" {
						inScript = false
					}
				}
			}
		case html.EndTagToken:
			if z.Token().Data == "script" {
				inScript = false
			}
		case html.TextToken:
			if !inScript {
				continue
			}
			text := string(z.Text())
			if strings.Contains(text, "window.urlPrefix") {
				siteMarker = true
			}
			matches := identityAssignment.FindAllStringIndex(text, -1)
			for _, at := range matches {
				assignments++
				if assignments > 1 {
					return invalid()
				}
				literal := strings.TrimSpace(text[at[1]:])
				if strings.HasPrefix(literal, "null;") || strings.HasPrefix(literal, "null\n") {
					continue
				}
				fields, err := identityFields(literal)
				if err != nil {
					return invalid()
				}
				if strings.TrimSpace(fields["id"]) == "" || strings.TrimSpace(fields["loginId"]) == "" {
					return invalid()
				}
				nickname, exists := fields["nickName"]
				if !exists {
					return invalid()
				}
				user = &MOOCUser{ID: fields["id"], Nickname: nickname}
			}
		}
	}
}

// Split top-level properties while preserving quoted commas and nested values.
func identityFields(literal string) (map[string]string, error) {
	bad := errors.New("invalid identity literal")
	if len(literal) == 0 || literal[0] != '{' {
		return nil, bad
	}
	depth, start := 1, 1
	var quote byte
	escaped := false
	fields := map[string]string{}
	consume := func(part string) error {
		m := identityField.FindStringSubmatch(part)
		if m == nil {
			return nil
		}
		key := m[1] + m[2] + m[3]
		if _, exists := fields[key]; exists {
			return bad
		}
		value, err := jsString(strings.TrimSpace(m[4]))
		if err != nil {
			return bad
		}
		fields[key] = value
		return nil
	}
	for i := 1; i < len(literal); i++ {
		ch := literal[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				if ch != '}' || consume(literal[start:i]) != nil {
					return nil, bad
				}
				rest := strings.TrimSpace(literal[i+1:])
				if rest != "" && !strings.HasPrefix(rest, ";") {
					return nil, bad
				}
				return fields, nil
			}
		case ',':
			if depth == 1 {
				if err := consume(literal[start:i]); err != nil {
					return nil, err
				}
				start = i + 1
			}
		}
	}
	return nil, bad
}
func jsString(value string) (string, error) {
	bad := errors.New("invalid identity string")
	if len(value) < 2 {
		return "", bad
	}
	if value[0] == '"' {
		var out string
		err := json.Unmarshal([]byte(value), &out)
		return out, err
	}
	if value[0] != '\'' || value[len(value)-1] != '\'' {
		return "", bad
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 1; i < len(value)-1; i++ {
		ch := value[i]
		if ch == '\'' {
			return "", bad
		}
		if ch == '"' {
			b.WriteString("\\\"")
			continue
		}
		if ch == '\\' {
			i++
			if i >= len(value)-1 {
				return "", bad
			}
			if value[i] == '\'' {
				b.WriteByte('\'')
				continue
			}
			b.WriteByte('\\')
			b.WriteByte(value[i])
			continue
		}
		b.WriteByte(ch)
	}
	b.WriteByte('"')
	var out string
	err := json.Unmarshal([]byte(b.String()), &out)
	return out, err
}
