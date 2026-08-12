package persist

import "testing"

func TestSanitizeBackupNamePreventsPathTraversal(t *testing.T) {
	for input, want := range map[string]string{
		"../../outside":      "_.._outside",
		"plant A / sensor 1": "plant_A___sensor_1",
		"normal-backup_01":   "normal-backup_01",
		"..":                 "",
	} {
		if got := sanitizeBackupName(input); got != want {
			t.Fatalf("sanitizeBackupName(%q)=%q want %q", input, got, want)
		}
	}
}
