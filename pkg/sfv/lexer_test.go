package sfv

import (
	"testing"
)

func TestParser_peek(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		offset int
		want   byte
	}{
		{
			name:   "peek at start",
			data:   "hello",
			offset: 0,
			want:   'h',
		},
		{
			name:   "peek at middle",
			data:   "hello",
			offset: 2,
			want:   'l',
		},
		{
			name:   "peek at end",
			data:   "hello",
			offset: 4,
			want:   'o',
		},
		{
			name:   "peek past end returns 0 (EOF)",
			data:   "hello",
			offset: 5,
			want:   0,
		},
		{
			name:   "peek empty string",
			data:   "",
			offset: 0,
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{
				data:   tt.data,
				offset: tt.offset,
			}
			if got := p.peek(); got != tt.want {
				t.Errorf("peek() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParser_consume(t *testing.T) {
	tests := []struct {
		name         string
		data         string
		offset       int
		expected     byte
		wantConsumed bool
		wantOffset   int
	}{
		{
			name:         "consume matching byte",
			data:         "hello",
			offset:       0,
			expected:     'h',
			wantConsumed: true,
			wantOffset:   1,
		},
		{
			name:         "consume non-matching byte",
			data:         "hello",
			offset:       0,
			expected:     'x',
			wantConsumed: false,
			wantOffset:   0,
		},
		{
			name:         "consume at end",
			data:         "hello",
			offset:       5,
			expected:     'x',
			wantConsumed: false,
			wantOffset:   5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{
				data:   tt.data,
				offset: tt.offset,
			}
			if got := p.consume(tt.expected); got != tt.wantConsumed {
				t.Errorf("consume() = %v, want %v", got, tt.wantConsumed)
			}
			if p.offset != tt.wantOffset {
				t.Errorf("offset = %v, want %v", p.offset, tt.wantOffset)
			}
		})
	}
}

func TestParser_skipOWS(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		offset     int
		wantOffset int
	}{
		{
			name:       "skip spaces",
			data:       "   hello",
			offset:     0,
			wantOffset: 3,
		},
		{
			name:       "skip tabs",
			data:       "\t\t\thello",
			offset:     0,
			wantOffset: 3,
		},
		{
			name:       "skip mixed OWS",
			data:       " \t \t hello",
			offset:     0,
			wantOffset: 5,
		},
		{
			name:       "no OWS to skip",
			data:       "hello",
			offset:     0,
			wantOffset: 0,
		},
		{
			name:       "skip OWS at offset",
			data:       "hello   world",
			offset:     5,
			wantOffset: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{
				data:   tt.data,
				offset: tt.offset,
			}
			p.skipOWS()
			if p.offset != tt.wantOffset {
				t.Errorf("offset = %v, want %v", p.offset, tt.wantOffset)
			}
		})
	}
}

func TestParser_skipSP(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		offset     int
		wantOffset int
	}{
		{
			name:       "skip spaces only",
			data:       "   hello",
			offset:     0,
			wantOffset: 3,
		},
		{
			name:       "tabs not skipped (SP only, not OWS)",
			data:       "\t\t\thello",
			offset:     0,
			wantOffset: 0,
		},
		{
			name:       "skip spaces but stop at tab",
			data:       "  \thello",
			offset:     0,
			wantOffset: 2,
		},
		{
			name:       "no SP to skip",
			data:       "hello",
			offset:     0,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{
				data:   tt.data,
				offset: tt.offset,
			}
			p.skipSP()
			if p.offset != tt.wantOffset {
				t.Errorf("offset = %v, want %v", p.offset, tt.wantOffset)
			}
		})
	}
}

func TestParser_isEOF(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		offset int
		want   bool
	}{
		{
			name:   "not at EOF",
			data:   "hello",
			offset: 0,
			want:   false,
		},
		{
			name:   "at EOF",
			data:   "hello",
			offset: 5,
			want:   true,
		},
		{
			name:   "past EOF",
			data:   "hello",
			offset: 10,
			want:   true,
		},
		{
			name:   "empty string is EOF",
			data:   "",
			offset: 0,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{
				data:   tt.data,
				offset: tt.offset,
			}
			if got := p.isEOF(); got != tt.want {
				t.Errorf("isEOF() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseError_Error(t *testing.T) {
	err := &ParseError{
		Offset:  42,
		Message: "expected closing quote",
		Context: `...("@method" "@path);alg...`,
	}

	// The %q format specifier escapes quotes in the context
	want := `parse error at offset 42: expected closing quote (near: "...(\"@method\" \"@path);alg...")`
	got := err.Error()

	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
