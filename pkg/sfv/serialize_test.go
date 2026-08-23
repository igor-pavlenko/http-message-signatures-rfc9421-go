package sfv

import (
	"strings"
	"testing"
)

func TestSerializeItem(t *testing.T) {
	tests := []struct {
		name    string
		item    Item
		want    string
		wantErr bool
	}{
		{
			name: "boolean true",
			item: Item{Value: true, Parameters: nil},
			want: "?1",
		},
		{
			name: "boolean false",
			item: Item{Value: false, Parameters: nil},
			want: "?0",
		},
		{
			name: "integer",
			item: Item{Value: int64(42), Parameters: nil},
			want: "42",
		},
		{
			name: "negative integer",
			item: Item{Value: int64(-123), Parameters: nil},
			want: "-123",
		},
		{
			name: "token (valid identifier)",
			item: Item{Value: Token{Value: "application/json"}, Parameters: nil},
			want: "application/json",
		},
		{
			name: "token with special chars",
			item: Item{Value: Token{Value: "text/html:level-1"}, Parameters: nil},
			want: "text/html:level-1",
		},
		{
			name: "quoted string (with space)",
			item: Item{Value: "hello world", Parameters: nil},
			want: `"hello world"`,
		},
		{
			name: "quoted string (with escape)",
			item: Item{Value: `hello "world"`, Parameters: nil},
			want: `"hello \"world\""`,
		},
		{
			name: "byte sequence",
			item: Item{Value: []byte("hello"), Parameters: nil},
			want: ":aGVsbG8=:",
		},
		{
			name: "item with boolean parameter",
			item: Item{
				Value: Token{Value: "test"},
				Parameters: []Parameter{
					{Key: "flag", Value: true},
				},
			},
			want: "test;flag",
		},
		{
			name: "item with string parameter",
			item: Item{
				Value: Token{Value: "test"},
				Parameters: []Parameter{
					{Key: "name", Value: Token{Value: "value"}},
				},
			},
			want: "test;name=value",
		},
		{
			name: "item with multiple parameters",
			item: Item{
				Value: 123,
				Parameters: []Parameter{
					{Key: "a", Value: true},
					{Key: "b", Value: Token{Value: "text"}},
					{Key: "c", Value: int64(456)},
				},
			},
			want: "123;a;b=text;c=456",
		},
		{
			name: "item with multiple parameters",
			item: Item{
				Value: 123,
				Parameters: []Parameter{
					{Key: "a", Value: false},
					{Key: "b", Value: Token{Value: "text"}},
					{Key: "c", Value: int64(456)},
				},
			},
			want: "123;a=?0;b=text;c=456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SerializeItem(tt.item)
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeItem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SerializeItem() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeInnerList(t *testing.T) {
	tests := []struct {
		name    string
		list    InnerList
		want    string
		wantErr bool
	}{
		{
			name: "empty inner list",
			list: InnerList{Items: []Item{}, Parameters: nil},
			want: "()",
		},
		{
			name: "single item",
			list: InnerList{
				Items: []Item{
					{Value: int64(1), Parameters: nil},
				},
				Parameters: nil,
			},
			want: "(1)",
		},
		{
			name: "multiple items",
			list: InnerList{
				Items: []Item{
					{Value: int64(1), Parameters: nil},
					{Value: int64(2), Parameters: nil},
					{Value: int64(3), Parameters: nil},
				},
				Parameters: nil,
			},
			want: "(1 2 3)",
		},
		{
			name: "items with mixed types",
			list: InnerList{
				Items: []Item{
					{Value: Token{Value: "token"}, Parameters: nil},
					{Value: int64(42), Parameters: nil},
					{Value: true, Parameters: nil},
				},
				Parameters: nil,
			},
			want: "(token 42 ?1)",
		},
		{
			name: "inner list with parameters",
			list: InnerList{
				Items: []Item{
					{Value: int64(1), Parameters: nil},
					{Value: int64(2), Parameters: nil},
				},
				Parameters: []Parameter{
					{Key: "level", Value: int64(5)},
					{Key: "safe", Value: true},
				},
			},
			want: "(1 2);level=5;safe",
		},
		{
			name: "items with item parameters",
			list: InnerList{
				Items: []Item{
					{Value: Token{Value: "a"}, Parameters: []Parameter{{Key: "x", Value: int64(1)}}},
					{Value: Token{Value: "b"}, Parameters: []Parameter{{Key: "y", Value: int64(2)}}},
					{Value: Token{Value: "c"}, Parameters: []Parameter{{Key: "z", Value: false}}},
				},
				Parameters: nil,
			},
			want: "(a;x=1 b;y=2 c;z=?0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SerializeInnerList(tt.list)
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeInnerList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SerializeInnerList() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeDictionary(t *testing.T) {
	tests := []struct {
		name    string
		dict    *Dictionary
		want    string
		wantErr bool
	}{
		{
			name: "empty dictionary",
			dict: &Dictionary{Keys: []string{}, Values: map[string]any{}},
			want: "",
		},
		{
			name: "single item member",
			dict: &Dictionary{
				Keys:   []string{"a"},
				Values: map[string]any{"a": Item{Value: int64(1), Parameters: nil}},
			},
			want: "a=1",
		},
		{
			name: "multiple item members",
			dict: &Dictionary{
				Keys: []string{"a", "b", "c", "d"},
				Values: map[string]any{
					"a": Item{Value: int64(1), Parameters: nil},
					"b": Item{Value: int64(-2), Parameters: nil},
					"c": Item{Value: true, Parameters: nil},
					"d": Item{Value: false, Parameters: nil},
				},
			},
			want: "a=1, b=-2, c, d=?0",
		},
		{
			name: "multiple item members with skipped key",
			dict: &Dictionary{
				Keys: []string{"a", "b", "d"},
				Values: map[string]any{
					"a": Item{Value: int64(2), Parameters: nil},
					"b": Item{Value: Token{Value: "b-string"}, Parameters: nil},
					"c": Item{Value: true, Parameters: nil},
					"d": Item{Value: false, Parameters: nil},
				},
			},
			want: "a=2, b=b-string, d=?0",
		},
		{
			name: "bare key (boolean true)",
			dict: &Dictionary{
				Keys: []string{"flag", "other"},
				Values: map[string]any{
					"flag":  Item{Value: true, Parameters: nil},
					"other": Item{Value: Token{Value: "value"}, Parameters: nil},
				},
			},
			want: "flag, other=value",
		},
		{
			name: "boolean true with parameters (not bare)",
			dict: &Dictionary{
				Keys: []string{"flag"},
				Values: map[string]any{
					"flag": Item{Value: true, Parameters: []Parameter{{Key: "x", Value: int64(1)}}},
				},
			},
			want: "flag=?1;x=1",
		},
		{
			name: "inner list member",
			dict: &Dictionary{
				Keys: []string{"list"},
				Values: map[string]any{
					"list": InnerList{
						Items: []Item{
							{Value: int64(1), Parameters: nil},
							{Value: int64(2), Parameters: nil},
						},
						Parameters: nil,
					},
				},
			},
			want: "list=(1 2)",
		},
		{
			name: "mixed members",
			dict: &Dictionary{
				Keys: []string{"a", "b", "c"},
				Values: map[string]any{
					"a": Item{Value: Token{Value: "token"}, Parameters: nil},
					"b": InnerList{
						Items:      []Item{{Value: int64(1), Parameters: nil}},
						Parameters: nil,
					},
					"c": Item{Value: true, Parameters: nil},
				},
			},
			want: "a=token, b=(1), c",
		},
		{
			name: "members with parameters",
			dict: &Dictionary{
				Keys: []string{"a", "b"},
				Values: map[string]any{
					"a": Item{Value: int64(1), Parameters: []Parameter{{Key: "x", Value: int64(10)}}},
					"b": InnerList{
						Items:      []Item{{Value: int64(2), Parameters: nil}},
						Parameters: []Parameter{{Key: "y", Value: int64(20)}},
					},
				},
			},
			want: "a=1;x=10, b=(2);y=20",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SerializeDictionary(tt.dict)
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeDictionary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SerializeDictionary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsValidToken(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "simple token",
			input: "token",
			want:  true,
		},
		{
			name:  "token with hyphen",
			input: "my-token",
			want:  true,
		},
		{
			name:  "token with underscore",
			input: "my_token",
			want:  true,
		},
		{
			name:  "token with digits",
			input: "token123",
			want:  true,
		},
		{
			name:  "token with colon",
			input: "text/html:level-1",
			want:  true,
		},
		{
			name:  "token with slash",
			input: "application/json",
			want:  true,
		},
		{
			name:  "token with asterisk start",
			input: "*token",
			want:  true,
		},
		{
			name:  "token with asterisk inside",
			input: "to*ken",
			want:  true,
		},
		{
			name:  "token with percent",
			input: "to%ken",
			want:  true,
		},
		{
			name:  "token with dot",
			input: "token.v1",
			want:  true,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
		{
			name:  "starts with digit",
			input: "123token",
			want:  false,
		},
		{
			name:  "contains space",
			input: "hello world",
			want:  false,
		},
		{
			name:  "contains comma",
			input: "hello,world",
			want:  false,
		},
		{
			name:  "contains equals",
			input: "key=value",
			want:  false,
		},
		{
			name:  "contains semicolon",
			input: "a;b",
			want:  false,
		},
		{
			name:  "contains quote",
			input: `hello"world`,
			want:  false,
		},
		{
			name:  "contains parenthesis",
			input: "hello(world)",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidToken(tt.input)
			if got != tt.want {
				t.Errorf("isValidToken(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSerializeString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple string",
			input: "hello",
			want:  `"hello"`,
		},
		{
			name:  "string with space",
			input: "hello world",
			want:  `"hello world"`,
		},
		{
			name:  "string with quote",
			input: `hello "world"`,
			want:  `"hello \"world\""`,
		},
		{
			name:  "string with backslash",
			input: `hello\world`,
			want:  `"hello\\world"`,
		},
		{
			name:  "string with both escapes",
			input: `say "hello\world"`,
			want:  `"say \"hello\\world\""`,
		},
		{
			name:  "empty string",
			input: "",
			want:  `""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SerializeString(tt.input)
			if got != tt.want {
				t.Errorf("SerializeString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSerializeBareItem(t *testing.T) {
	tests := []struct {
		name    string
		value   any
		want    string
		wantErr bool
	}{
		{
			name:  "boolean true",
			value: true,
			want:  "?1",
		},
		{
			name:  "boolean false",
			value: false,
			want:  "?0",
		},
		{
			name:  "integer int64",
			value: int64(42),
			want:  "42",
		},
		{
			name:  "integer int",
			value: 42,
			want:  "42",
		},
		{
			name:  "negative integer",
			value: int64(-999),
			want:  "-999",
		},
		{
			name:  "token string",
			value: Token{Value: "token"},
			want:  "token",
		},
		{
			name:  "quoted string",
			value: "hello world",
			want:  `"hello world"`,
		},
		{
			name:  "byte sequence",
			value: []byte{0x01, 0x02, 0x03},
			want:  ":AQID:",
		},
		{
			name:  "empty byte sequence",
			value: []byte{},
			want:  "::",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sb strings.Builder
			err := writeBareItem(&sb, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("writeBareItem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got := sb.String()
			if got != tt.want {
				t.Errorf("writeBareItem() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeParameters(t *testing.T) {
	tests := []struct {
		name    string
		params  []Parameter
		want    string
		wantErr bool
	}{
		{
			name:   "empty parameters",
			params: []Parameter{},
			want:   "",
		},
		{
			name: "single boolean true parameter",
			params: []Parameter{
				{Key: "flag", Value: true},
			},
			want: ";flag",
		},
		{
			name: "single boolean false parameter",
			params: []Parameter{
				{Key: "flag", Value: false},
			},
			want: ";flag=?0",
		},
		{
			name: "single string parameter",
			params: []Parameter{
				{Key: "name", Value: Token{Value: "value"}},
			},
			want: ";name=value",
		},
		{
			name: "single integer parameter",
			params: []Parameter{
				{Key: "count", Value: int64(42)},
			},
			want: ";count=42",
		},
		{
			name: "multiple mixed parameters",
			params: []Parameter{
				{Key: "a", Value: true},
				{Key: "b", Value: Token{Value: "text"}},
				{Key: "c", Value: int64(123)},
				{Key: "d", Value: false},
			},
			want: ";a;b=text;c=123;d=?0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sb strings.Builder
			err := writeParameters(&sb, tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("writeParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got := sb.String()
			if got != tt.want {
				t.Errorf("writeParameters() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRoundTrip tests parsing and serializing back
func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "simple dictionary",
			input: "a=1, b=2, c=3",
		},
		{
			name:  "dictionary with bare key",
			input: "flag, other=value",
		},
		{
			name:  "dictionary with inner list",
			input: "list=(1 2 3), item=token",
		},
		{
			name:  "complex dictionary",
			input: "a=1;x=10, b=(1 2);y=20, c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse
			parser := NewParser(tt.input, NoLimits())
			dict, err := parser.ParseDictionary()
			if err != nil {
				t.Fatalf("ParseDictionary() error = %v", err)
			}

			// Serialize
			got, err := SerializeDictionary(dict)
			if err != nil {
				t.Fatalf("SerializeDictionary() error = %v", err)
			}

			// Compare
			if got != tt.input {
				t.Errorf("Round trip failed:\n  input:  %q\n  output: %q", tt.input, got)
			}
		})
	}
}

func TestSerializeList(t *testing.T) {
	tests := []struct {
		name    string
		list    List
		want    string
		wantErr bool
	}{
		{
			name: "empty list",
			list: List{Members: nil},
			want: "",
		},
		{
			name: "single item",
			list: List{
				Members: []any{
					Item{Value: Token{Value: "foo"}, Parameters: nil},
				},
			},
			want: "foo",
		},
		{
			name: "multiple items",
			list: List{
				Members: []any{
					Item{Value: Token{Value: "a"}, Parameters: nil},
					Item{Value: Token{Value: "b"}, Parameters: nil},
					Item{Value: Token{Value: "c"}, Parameters: nil},
				},
			},
			want: "a, b, c",
		},
		{
			name: "items with parameters",
			list: List{
				Members: []any{
					Item{Value: Token{Value: "a"}, Parameters: []Parameter{{Key: "p", Value: int64(1)}}},
					Item{Value: Token{Value: "b"}, Parameters: []Parameter{{Key: "q", Value: int64(2)}}},
				},
			},
			want: "a;p=1, b;q=2",
		},
		{
			name: "inner list member",
			list: List{
				Members: []any{
					InnerList{
						Items:      []Item{{Value: Token{Value: "a"}, Parameters: nil}, {Value: Token{Value: "b"}, Parameters: nil}},
						Parameters: nil,
					},
				},
			},
			want: "(a b)",
		},
		{
			name: "multiple inner lists",
			list: List{
				Members: []any{
					InnerList{
						Items:      []Item{{Value: Token{Value: "a"}, Parameters: nil}, {Value: Token{Value: "b"}, Parameters: nil}},
						Parameters: nil,
					},
					InnerList{
						Items:      []Item{{Value: Token{Value: "c"}, Parameters: nil}, {Value: Token{Value: "d"}, Parameters: nil}},
						Parameters: nil,
					},
				},
			},
			want: "(a b), (c d)",
		},
		{
			name: "mixed items and inner lists",
			list: List{
				Members: []any{
					Item{Value: Token{Value: "foo"}, Parameters: nil},
					InnerList{
						Items:      []Item{{Value: Token{Value: "a"}, Parameters: nil}, {Value: Token{Value: "b"}, Parameters: nil}},
						Parameters: nil,
					},
					Item{Value: Token{Value: "bar"}, Parameters: nil},
				},
			},
			want: "foo, (a b), bar",
		},
		{
			name: "integer items",
			list: List{
				Members: []any{
					Item{Value: int64(1), Parameters: nil},
					Item{Value: int64(2), Parameters: nil},
					Item{Value: int64(3), Parameters: nil},
				},
			},
			want: "1, 2, 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SerializeList(&tt.list)
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SerializeList() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestListRoundTrip(t *testing.T) {
	tests := []string{
		"a, b, c",
		"1, 2, 3",
		"(a b), (c d)",
		"foo;p=1, bar;q=2",
		"(a b);x=1, (c d);y=2",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			// Parse
			p := NewParser(input, DefaultLimits())
			list, err := p.ParseList()
			if err != nil {
				t.Fatalf("ParseList() error = %v", err)
			}

			// Serialize
			got, err := SerializeList(list)
			if err != nil {
				t.Fatalf("SerializeList() error = %v", err)
			}

			// Compare
			if got != input {
				t.Errorf("Round trip failed:\n  input:  %q\n  output: %q", input, got)
			}
		})
	}
}
