package services

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrValidation",
			err:      ErrValidation,
			expected: true,
		},
		{
			name:     "ErrInvalidInput",
			err:      ErrInvalidInput,
			expected: true,
		},
		{
			name:     "wrapped ErrValidation",
			err:      fmt.Errorf("wrapped: %w", ErrValidation),
			expected: true,
		},
		{
			name:     "wrapped ErrInvalidInput",
			err:      fmt.Errorf("wrapped: %w", ErrInvalidInput),
			expected: true,
		},
		{
			name:     "ErrNotFound",
			err:      ErrNotFound,
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("generic error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidationError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
