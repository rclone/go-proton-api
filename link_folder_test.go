package proton

import "testing"

func TestIsDeleteChildrenResponseCodeAllowed(t *testing.T) {
	tests := []struct {
		name string
		code Code
		want bool
	}{
		{name: "success", code: SuccessCode, want: true},
		{name: "not_found", code: 2501, want: true},
		{name: "conflict", code: AFileOrFolderNameExist, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDeleteChildrenResponseCodeAllowed(tt.code)
			if got != tt.want {
				t.Fatalf("unexpected result: got=%v want=%v", got, tt.want)
			}
		})
	}
}
