package sfv

import (
	"testing"
)

func TestParser_ParseList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int // number of members
		wantErr bool
	}{
		{
			name:  "empty list",
			input: "",
			want:  0,
		},
		{
			name:  "single token",
			input: "foo",
			want:  1,
		},
		{
			name:  "single integer",
			input: "42",
			want:  1,
		},
		{
			name:  "multiple tokens",
			input: "a, b, c",
			want:  3,
		},
		{
			name:  "multiple integers",
			input: "1, 2, 3",
			want:  3,
		},
		{
			name:  "mixed items",
			input: "foo, 42, \"bar\"",
			want:  3,
		},
		{
			name:  "items with parameters",
			input: "a;p=1, b;q=2",
			want:  2,
		},
		{
			name:  "inner list",
			input: "(a b c)",
			want:  1,
		},
		{
			name:  "multiple inner lists",
			input: "(a b), (c d)",
			want:  2,
		},
		{
			name:  "mixed items and inner lists",
			input: "foo, (a b), bar",
			want:  3,
		},
		{
			name:  "inner list with parameters",
			input: "(a b);p=1, (c d);q=2",
			want:  2,
		},
		{
			name:    "trailing comma",
			input:   "a, b,",
			wantErr: true,
		},
		{
			name:  "no space after comma",
			input: "a,b,c",
			want:  3,
		},
		{
			name:  "boolean values",
			input: "?1, ?0, ?1",
			want:  3,
		},
		{
			name:  "byte sequence",
			input: ":YWJj:, :ZGVm:",
			want:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.input, DefaultLimits())
			list, err := p.ParseList()

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseList() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseList() error = %v", err)
			}

			if len(list.Members) != tt.want {
				t.Errorf("ParseList() got %d members, want %d", len(list.Members), tt.want)
			}
		})
	}
}

func TestParseList_MemberTypes(t *testing.T) {
	t.Run("item member", func(t *testing.T) {
		p := NewParser("foo;p=1", DefaultLimits())
		list, err := p.ParseList()
		if err != nil {
			t.Fatalf("ParseList() error = %v", err)
		}

		if len(list.Members) != 1 {
			t.Fatalf("got %d members, want 1", len(list.Members))
		}

		item, ok := list.Members[0].(Item)
		if !ok {
			t.Fatalf("member is %T, want Item", list.Members[0])
		}

		tok, ok := item.Value.(Token)
		if !ok {
			t.Errorf("item value = %T, want Token", item.Value)
		} else if tok.Value != "foo" {
			t.Errorf("item value = %v, want foo", tok.Value)
		}

		if len(item.Parameters) != 1 || item.Parameters[0].Key != "p" {
			t.Errorf("unexpected parameters: %v", item.Parameters)
		}
	})

	t.Run("inner list member", func(t *testing.T) {
		p := NewParser("(a b);p=1", DefaultLimits())
		list, err := p.ParseList()
		if err != nil {
			t.Fatalf("ParseList() error = %v", err)
		}

		if len(list.Members) != 1 {
			t.Fatalf("got %d members, want 1", len(list.Members))
		}

		innerList, ok := list.Members[0].(InnerList)
		if !ok {
			t.Fatalf("member is %T, want InnerList", list.Members[0])
		}

		if len(innerList.Items) != 2 {
			t.Errorf("inner list has %d items, want 2", len(innerList.Items))
		}

		if len(innerList.Parameters) != 1 || innerList.Parameters[0].Key != "p" {
			t.Errorf("unexpected parameters: %v", innerList.Parameters)
		}
	})
}

func FuzzParseList(f *testing.F) {
	seeds := []string{
		"",
		"a",
		"a, b, c",
		"1, 2, 3",
		"(a b), (c d)",
		"foo;p=1, bar;q=2",
		":YWJj:, :ZGVm:",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		p := NewParser(input, DefaultLimits())
		// Just ensure it doesn't panic
		_, _ = p.ParseList()
	})
}
